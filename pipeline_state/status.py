"""Version 1 accession status sidecars, independent of pipeline execution.

Missing files raise FileNotFoundError; invalid records raise StatusValidationError.
Writes are atomic, but concurrent writers are not locked. Callers must serialize
access (revision checks are advisory, not a multi-process compare-and-swap).
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile


STAGE_IDS = (
    "antivirus", "ingest", "fits", "reports", "summary", "fixity",
    "bag_construct", "bag_validate", "tar_serialize",
)
STATES = {"not_started", "running", "completed", "failed", "interrupted", "unknown"}
FRESHNESS_STATES = {"current", "stale", "unverified"}
LAYOUTS = {"unbagged", "bagged", "ambiguous", "unknown"}


class StatusValidationError(ValueError):
    """Malformed JSON, invalid schema, or mismatched accession identity."""


class UnsupportedSchemaError(StatusValidationError):
    """A status record requires a newer schema reader/writer."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _status_path(output_folder, accession_number):
    # Apply Windows component rules even when read on another operating system.
    if (not isinstance(accession_number, str) or not accession_number
            or ".." in accession_number
            or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', accession_number)
            or accession_number != accession_number.strip()
            or accession_number.endswith(".")
            or accession_number.split(".")[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}):
        raise StatusValidationError("Accession number must be a single safe path component")
    root = Path(output_folder).resolve()
    path = root / f"{accession_number}_status.json"
    if path.resolve().parent != root or (root / accession_number).resolve().parent != root:
        raise StatusValidationError("Accession path resolves outside the output directory")
    return path


def _timestamp(value, name, nullable=False):
    if nullable and value is None:
        return
    try:
        if not isinstance(value, str):
            raise ValueError()
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
    except ValueError as exc:
        raise StatusValidationError(f"{name} must be an ISO-8601 timestamp with timezone") from exc


def _choice(value, choices, name):
    if not isinstance(value, str) or value not in choices:
        raise StatusValidationError(f"Invalid {name}: {value!r}")


def _integer(value, minimum, name):
    if type(value) is not int or value < minimum:
        raise StatusValidationError(f"{name} must be an integer >= {minimum}")


def _validate(status, accession_number):
    if not isinstance(status, dict):
        raise StatusValidationError("Status must be an object")
    version = status.get("schema_version")
    _integer(version, 1, "schema_version")
    if version > 1:
        raise UnsupportedSchemaError(f"Newer unsupported status schema: {version}")
    required = {"revision", "accession_number", "accession_path", "created_at",
                "updated_at", "layout", "steps"}
    if not required <= status.keys():
        raise StatusValidationError("Missing required status fields")
    if status["accession_number"] != accession_number or status["accession_path"] != accession_number:
        raise StatusValidationError("Embedded accession identity does not match requested accession")
    _integer(status["revision"], 1, "revision")
    _timestamp(status["created_at"], "created_at")
    _timestamp(status["updated_at"], "updated_at")
    _choice(status["layout"], LAYOUTS, "layout")
    steps = status["steps"]
    if not isinstance(steps, dict) or not set(STAGE_IDS) <= steps.keys():
        raise StatusValidationError("All nine internal stages are required")
    fields = {"state", "outcome", "attempt", "started_at", "finished_at", "freshness",
              "settings", "inputs", "outputs", "evidence", "result"}
    for stage in STAGE_IDS:
        step = steps[stage]
        if not isinstance(step, dict) or not fields <= step.keys():
            raise StatusValidationError(f"Missing required fields for {stage}")
        _choice(step["state"], STATES, f"{stage}.state")
        outcome = step["outcome"]
        if outcome is not None and (not isinstance(outcome, str) or
                                   not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", outcome)):
            raise StatusValidationError(f"{stage}.outcome must be null or a safe string token")
        _integer(step["attempt"], 0, f"{stage}.attempt")
        for name in ("started_at", "finished_at"):
            _timestamp(step[name], f"{stage}.{name}", nullable=True)
        fresh = step["freshness"]
        if not isinstance(fresh, dict) or not {"state", "checked_at", "method", "reasons"} <= fresh.keys():
            raise StatusValidationError(f"Invalid {stage}.freshness")
        _choice(fresh["state"], FRESHNESS_STATES, f"{stage}.freshness.state")
        _timestamp(fresh["checked_at"], f"{stage}.freshness.checked_at", nullable=True)
        if not isinstance(fresh["method"], str) or not fresh["method"].strip():
            raise StatusValidationError("Freshness method must be a nonempty string")
        if not isinstance(fresh["reasons"], list) or not all(isinstance(r, str) for r in fresh["reasons"]):
            raise StatusValidationError("Freshness reasons must be a list of strings")
        for name in ("settings", "inputs", "outputs", "evidence", "result"):
            if not isinstance(step[name], dict):
                raise StatusValidationError(f"{stage}.{name} must be an object")


def _write(path, status):
    # Serialize first so serialization errors never touch the destination.
    try:
        serialized = json.dumps(status, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except (ValueError, TypeError) as exc:
        raise StatusValidationError(f"Status is not valid JSON: {exc}") from exc
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=f".{path.name}.",
                                         suffix=".tmp", delete=False) as stream:
            temporary = stream.name
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def create_status(output_folder, accession_number, *, layout="unbagged"):
    """Create a record with explicit layout; refuse to replace any existing file.

    Default remains unbagged for new managed accessions. A first managed run of
    existing artifacts can supply unknown without inferring legacy layout.
    """
    path = _status_path(output_folder, accession_number)
    if path.exists():
        raise FileExistsError(path)
    timestamp = _now()
    status = dict(schema_version=1, revision=1, accession_number=accession_number,
                  accession_path=accession_number, created_at=timestamp,
                  updated_at=timestamp, layout=layout, steps={})
    for stage in STAGE_IDS:
        status["steps"][stage] = dict(
            state="not_started", outcome=None, attempt=0, started_at=None,
            finished_at=None, freshness=dict(state="unverified", checked_at=None,
                                            method="none", reasons=[]),
            settings={}, inputs={}, outputs={}, evidence={}, result={})
    _validate(status, accession_number)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write(path, status)
    return status


def load_status(output_folder, accession_number):
    """Load without creating or repairing anything; preserve unknown fields."""
    path = _status_path(output_folder, accession_number)
    try:
        with path.open(encoding="utf-8") as stream:
            status = json.load(stream)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StatusValidationError(f"Malformed status JSON in {path}: {exc}") from exc
    _validate(status, accession_number)
    return status


def save_status(output_folder, accession_number, status):
    """Save an existing record and return its new revision without mutating input.

    Refuse stale revisions and invalid existing files. Unknown fields loaded by
    callers survive because the entire supplied record is written.
    """
    path = _status_path(output_folder, accession_number)
    _validate(status, accession_number)
    previous = load_status(output_folder, accession_number)
    if status["revision"] != previous["revision"]:
        raise StatusValidationError("Revision does not match the stored status; reload before saving")
    candidate = deepcopy(status)
    candidate["revision"] += 1
    candidate["updated_at"] = _now()
    _write(path, candidate)
    return candidate
