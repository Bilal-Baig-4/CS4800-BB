"""Read-only nine-stage planning using managed history and lightweight existence checks."""
from pathlib import Path
import re

from . import status as pipeline_status
from .view import STEP_STAGES, STAGE_NAMES

SAFE_RERUN = {"antivirus", "fits", "reports", "summary", "fixity", "bag_validate", "tar_serialize"}
ACCEPTABLE = {
    "antivirus": {"clean", "empty"}, "ingest": {"generated", "empty"},
    "fits": {"identified", "unidentified", "processed", "empty"},
    "reports": {"generated"}, "summary": {"generated", "empty"},
    "fixity": {"passed"}, "bag_construct": {"constructed"},
    "bag_validate": {"valid"}, "tar_serialize": {"serialized"},
}


def bag_layout(payload):
    payload = Path(payload)
    if not payload.is_dir():
        return "missing"
    indicators = [p for p in payload.iterdir() if p.name.casefold() in
                  {"data", "bagit.txt", "bag-info.txt", "aptrust-info.txt", "fetch.txt"}
                  or re.fullmatch(r"(?:tag)?manifest-.*\.txt", p.name.casefold())]
    if not indicators:
        return "unbagged"
    if ((payload / "data").is_dir() and (payload / "bagit.txt").is_file()
            and (payload / "bag-info.txt").is_file()
            and any(p.is_file() for p in payload.glob("manifest-*.txt"))):
        return "bagged"
    return "ambiguous"


def artifact_availability(output, accession, status=None):
    """No hashing, timestamps, XML parsing, or writes. Reject escaping recorded paths."""
    root = Path(output).resolve()
    pipeline_status._status_path(root, accession)  # Shared accession-component safety rules.
    payload = root / accession
    layout = bag_layout(payload)
    recorded = {}
    requirements = {
        "antivirus": {"csv": "file", "log": "file"},
        "ingest": {"payload": "dir", "xml": "file"}, "fits": {"xml": "file"},
        "reports": {"csv": "file", "html": "file"}, "summary": {"text": "file"},
        "fixity": {"csv": "file", "log": "file"}, "bag_construct": {"bag": "dir"},
        "bag_validate": {}, "tar_serialize": {"tar": "file"},
    }
    for stage, required in requirements.items():
        outputs = status["steps"][stage]["outputs"] if status else {}
        valid = True
        for name, kind in required.items():
            value = outputs.get(name)
            if not isinstance(value, str) or not value or Path(value).is_absolute() or "\\" in value or ":" in value:
                valid = False
                break
            path = root / value
            if not path.resolve().is_relative_to(root) or not (path.is_dir() if kind == "dir" else path.is_file()):
                valid = False
                break
            expected = {("ingest", "payload"): payload, ("ingest", "xml"): root / f"{accession}.xml",
                        ("fits", "xml"): root / f"{accession}.xml", ("bag_construct", "bag"): payload}.get((stage, name))
            if expected is not None and path.resolve() != expected.resolve():
                valid = False
                break
        recorded[stage] = valid
    return dict(payload=payload.is_dir(), xml=(root / f"{accession}.xml").is_file(),
                csv=(root / f"{accession}_files.csv").is_file(), layout=layout,
                bag=layout == "bagged", bag_profile="aptrust" if (payload / "aptrust-info.txt").is_file() else "generic",
                recorded=recorded)


def build_resume_plan(status, selected_steps, sub_options, output, accession, artifacts=None):
    """Return nine ordered stage decisions without mutating history or selections.

    Review pauses the whole requested plan. Resolve by changing requested work,
    explicit safe rerun, or external review; running records never auto-rerun.
    """
    if status is not None:
        pipeline_status._validate(status, accession)
    available = artifact_availability(output, accession, status) if artifacts is None else artifacts
    requested = {
        "antivirus": selected_steps.get("ingest", False) and sub_options.get("antivirus", False),
        "ingest": selected_steps.get("ingest", False), "fits": selected_steps.get("fits", False),
        "reports": selected_steps.get("reports", False), "summary": selected_steps.get("reports", False),
        "fixity": selected_steps.get("fixity", False), "bag_construct": selected_steps.get("bagging", False),
        "bag_validate": selected_steps.get("bagging", False) and sub_options.get("validate", False),
        "tar_serialize": selected_steps.get("bagging", False) and sub_options.get("tar", False)
                         and sub_options.get("profile") == "aptrust",
    }
    rerun = sub_options.get("rerun_completed", False)
    decisions = {}
    for stage in pipeline_status.STAGE_IDS:
        action, reason = "skip", "not_requested"
        record = status["steps"][stage] if status else None
        if requested[stage]:
            action, reason = "run", "no_managed_status" if record is None else record["state"]
            if record is not None:
                state, outcome = record["state"], record["outcome"]
                if state in ("running", "unknown"):
                    action, reason = "review", "previous_attempt_may_be_interrupted" if state == "running" else "unknown_history"
                elif stage in ("ingest", "bag_construct") and state in ("failed", "interrupted"):
                    action, reason = "review", "unsafe_automatic_retry"
                elif state == "completed":
                    if rerun and stage in SAFE_RERUN:
                        action, reason = "run", "explicit_safe_rerun"
                    elif record["freshness"]["state"] == "stale":
                        action, reason = ("run" if stage in SAFE_RERUN and outcome in ACCEPTABLE[stage] else "review"), "recorded_stale"
                    elif outcome not in ACCEPTABLE[stage]:
                        action, reason = "review", "outcome_not_satisfied"
                    elif available["recorded"][stage] and (stage not in ("bag_construct", "bag_validate") or available["bag"]):
                        action, reason = "reuse", "completed_unverified" if record["freshness"]["state"] == "unverified" else "completed_outputs_present"
                    elif stage in ("ingest", "bag_construct"):
                        action, reason = "review", "completed_outputs_missing_or_ambiguous"
                    else:
                        action, reason = "run", "completed_outputs_missing"
            if stage == "antivirus" and action == "reuse":
                result = record["result"]
                if result.get("error_count") != 0 or result.get("detection_count") != 0 or result.get("scanned_count") is None:
                    action, reason = "review", "scan_result_not_usable"
            if stage == "bag_construct" and available["bag"] and action == "run":
                # Preserve selective validation/TAR against an unmanaged existing bag.
                action, reason = ("skip", "existing_bag_no_construction") if requested["bag_validate"] or requested["tar_serialize"] else ("block", "existing_bag_cannot_be_rebuilt")
            if stage == "bag_construct" and available["layout"] == "ambiguous":
                action, reason = "block", "ambiguous_bag_layout"
            if stage in ("bag_construct", "bag_validate", "tar_serialize") and available["bag"] and available["bag_profile"] != sub_options.get("profile"):
                action, reason = "review", "existing_bag_profile_mismatch"
        decisions[stage] = dict(stage=stage, action=action, reason=reason)
        if record is not None and record["freshness"]["state"] == "stale":
            decisions[stage]["freshness_reasons"] = list(record["freshness"]["reasons"])

    def dependency(stage, producer, available_now):
        current = decisions[stage]
        if current["action"] not in ("run", "reuse"):
            return
        upstream = decisions[producer]
        if upstream["action"] in ("review", "block"):
            current.update(action="block", reason=f"{producer}_requires_review")
        elif upstream["action"] == "run":
            current.update(action="run", reason=f"same_run_{producer}_output")
        elif current["action"] == "run" and not available_now:
            current.update(action="block", reason=f"missing_{producer}_prerequisite")

    for stage in ("fits", "reports", "fixity"):
        dependency(stage, "ingest", available["xml"] and (available["payload"] if stage != "reports" else True))
    dependency("reports", "fits", available["xml"] or decisions["ingest"]["action"] == "run")
    dependency("summary", "reports", available["csv"])
    for stage in ("fits", "fixity"):
        if decisions[stage]["action"] == "run" and decisions["ingest"]["action"] != "run" and available["layout"] != "unbagged":
            decisions[stage].update(action="block", reason="unbagged_payload_required")
    if decisions["ingest"]["action"] == "run" and status and (available["xml"] or available["bag"]):
        decisions["ingest"].update(action="review", reason="existing_preservation_baseline")
    if decisions["ingest"]["action"] == "run" and decisions["antivirus"]["action"] == "reuse":
        decisions["antivirus"].update(action="review", reason="scan_cannot_be_reused_for_new_ingest")
    dependency("bag_construct", "ingest", available["payload"])
    for stage in ("bag_validate", "tar_serialize"):
        dependency(stage, "bag_construct", available["bag"])
    if requested["tar_serialize"] and requested["bag_validate"]:
        if decisions["bag_validate"]["action"] in ("review", "block"):
            decisions["tar_serialize"].update(action="block", reason="successful_validation_required")
    if status and requested["bag_construct"] and status["steps"]["fixity"]["outcome"] == "findings":
        if decisions["fixity"]["action"] != "run":
            decisions["bag_construct"].update(action="block", reason="managed_fixity_findings_require_passing_rerun")
        else:
            decisions["bag_construct"]["requires_passing_fixity"] = True
    # Propagate late safety decisions to dependent actions in the preview.
    for stage, producer in (("fits", "ingest"), ("reports", "ingest"), ("fixity", "ingest"),
                            ("reports", "fits"), ("summary", "reports"), ("bag_construct", "ingest"),
                            ("bag_validate", "bag_construct"), ("tar_serialize", "bag_construct")):
        if decisions[stage]["action"] in ("run", "reuse") and decisions[producer]["action"] in ("review", "block"):
            decisions[stage].update(action="block", reason=f"{producer}_requires_review")
    if requested["tar_serialize"] and requested["bag_validate"] and decisions["bag_validate"]["action"] in ("review", "block"):
        decisions["tar_serialize"].update(action="block", reason="successful_validation_required")
    return list(decisions.values())


def format_execution_plan(plan):
    by_stage = {decision["stage"]: decision for decision in plan}
    headings = ("Ingest", "Format Identification", "Reports", "Fixity", "Bagging")
    lines = ["Execution Plan", ""]
    for heading, stages in zip(headings, STEP_STAGES.values()):
        entries = [by_stage[stage] for stage in stages]
        if all(entry["reason"] == "not_requested" for entry in entries):
            lines.append(f"{heading} — Not Selected")
        else:
            lines.append(f"{heading}:")
            for entry in entries:
                detail = entry['reason'].replace('_', ' ')
                if entry.get("freshness_reasons"):
                    detail += ": " + ", ".join(reason.replace("_", " ") for reason in entry["freshness_reasons"])
                lines.append(f"  {STAGE_NAMES[entry['stage']]} — {entry['action'].title()} ({detail})")
    lines.append("\nFreshness uses recorded change-detection evidence; it is not integrity verification.")
    return "\n".join(lines)
