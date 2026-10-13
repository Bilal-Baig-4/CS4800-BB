"""Record operation boundaries through the status API; no resume decisions."""
from copy import deepcopy
import csv
from datetime import datetime, timezone
from pathlib import Path
from lxml import etree as ET

from . import status as pipeline_status
from .freshness import capture_stage, apply_execution_evidence


class StatusRecordingError(RuntimeError):
    """Execution history could not be reliably persisted."""


def now():
    return datetime.now(timezone.utc).isoformat()


class RunRecorder:
    """One serialized managed run. Never consult stage states to skip work."""
    def __init__(self, output, accession):
        self.output = Path(output).resolve()
        self.accession = accession
        try:
            self.status = pipeline_status.load_status(self.output, accession)
        except FileNotFoundError:
            # Existing artifacts do not establish layout or legacy execution history.
            self.status = pipeline_status.create_status(self.output, accession, layout="unknown")

    def paths(self, **paths):
        """Record only actual artifacts, relative to the output root."""
        outputs = {}
        for name, path in paths.items():
            if path is None or not isinstance(path, (str, Path)):
                continue
            path = Path(path)
            if path.exists():
                outputs[name] = path.resolve().relative_to(self.output).as_posix()
        return outputs

    def run(self, stage, operation, normalize, *, settings=None, failure_outcome="error",
            progress=None, layout=None):
        candidate = deepcopy(self.status)
        step = candidate["steps"][stage]
        step.update(state="running", outcome=None, attempt=step["attempt"] + 1,
                    started_at=now(), finished_at=None, settings=settings or {},
                    inputs={}, outputs={}, evidence={}, result={})
        step.pop("message", None)
        # Only this attempted stage is reset; downstream records stay unchanged.
        step["freshness"].update(state="unverified", checked_at=None, method="none", reasons=[])
        try:
            self.status = pipeline_status.save_status(self.output, self.accession, candidate)
        except Exception as exc:
            raise StatusRecordingError(f"Cannot record {stage} running; operation was not started: {exc}") from exc
        captured_inputs, input_errors = capture_stage(stage, self.status, self.output, self.accession, input_side=True)
        try:
            value = operation()
        except Exception as operation_error:
            candidate = deepcopy(self.status)
            candidate["steps"][stage].update(
                state="failed", outcome=failure_outcome(operation_error) if callable(failure_outcome) else failure_outcome, finished_at=now(),
                message=str(operation_error)[:2000], result=deepcopy(progress or {}))
            if stage == "reports" and (progress or {}).get("csv_generated"):
                candidate["steps"][stage]["outcome"] = "partial"
                candidate["steps"][stage]["outputs"] = self.paths(csv=self.output / f"{self.accession}_files.csv")
            if stage == "bag_construct":
                candidate["layout"] = "unknown"  # Rejected/partial construction is not a verified layout.
            try:
                self.status = pipeline_status.save_status(self.output, self.accession, candidate)
            except Exception as save_error:
                raise StatusRecordingError(
                    f"{stage} failed: {operation_error}. Failure status could not be saved: {save_error}; "
                    "the stored attempt may remain running.") from operation_error
            raise
        # A normalization/final-write failure must leave the durable running boundary.
        try:
            result = normalize(value)
            candidate = deepcopy(self.status)
            disposition = dict(state="completed", finished_at=now())
            disposition.update(result)
            candidate["steps"][stage].update(disposition)
            if layout and candidate["steps"][stage]["state"] == "completed":
                candidate["layout"] = layout
            if candidate["steps"][stage]["state"] == "completed":
                apply_execution_evidence(stage, candidate, self.output, self.accession, captured_inputs, input_errors)
            self.status = pipeline_status.save_status(self.output, self.accession, candidate)
        except Exception as exc:
            raise StatusRecordingError(
                f"{stage} returned, but its final status could not be recorded: {exc}. "
                "Artifacts are retained; the stored attempt may remain running.") from exc
        return value


def file_count(xml):
    try:
        tree = ET.parse(str(xml), ET.XMLParser(resolve_entities=False, no_network=True))
        return len(tree.findall(".//{http://dataaccessioner.org/schema/dda-1-1}file"))
    except (OSError, ET.XMLSyntaxError):
        return None


def fixity_result(recorder, returned):
    csv_path, log_path = returned if isinstance(returned, tuple) and len(returned) == 2 else (None, None)
    counts = {"ok_count": None, "mismatch_count": None, "missing_count": None, "error_count": None}
    outcome = "processed"
    try:
        with Path(csv_path).open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if "status" not in (reader.fieldnames or []):
                raise ValueError("Missing status column")
            statuses = [row["status"] for row in reader]
        if any(status not in {"OK", "MISMATCH", "MISSING", "ERROR"} for status in statuses):
            raise ValueError("Unknown fixity finding")
        counts = dict(zip(counts, (statuses.count(s) for s in ("OK", "MISMATCH", "MISSING", "ERROR"))))
        outcome = "empty" if not statuses else "passed" if all(s == "OK" for s in statuses) else "findings"
    except (OSError, TypeError, ValueError, csv.Error):
        pass  # Do not turn unavailable counts into zero or invent a pass.
    return dict(outcome=outcome, result=counts, outputs=recorder.paths(csv=csv_path, log=log_path))
