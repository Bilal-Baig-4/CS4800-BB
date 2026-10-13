"""Pure presentation of recorded history; no disk inspection or status mutation."""

STEP_STAGES = {
    "ingest": ("antivirus", "ingest"),
    "format_identification": ("fits",),
    "reports": ("reports", "summary"),
    "fixity": ("fixity",),
    "bagging": ("bag_construct", "bag_validate", "tar_serialize"),
}
STAGE_NAMES = {
    "antivirus": "Virus Scan", "ingest": "Accession Ingest",
    "fits": "Format Identification", "reports": "Metadata Reports",
    "summary": "Collection Summary", "fixity": "Fixity Verification",
    "bag_construct": "Bag Construction", "bag_validate": "Bag Validation",
    "tar_serialize": "TAR Serialization",
}
STATE_LABELS = {
    "not_started": "Not Started", "running": "Running / Possibly Interrupted",
    "completed": "Completed", "failed": "Failed", "interrupted": "Incomplete Previous Attempt",
    "unknown": "Unknown",
}
OUTCOME_LABELS = {
    "clean": "Clean", "detections": "Detections", "partial": "Partial Results",
    "unavailable": "Unavailable", "empty": "Empty", "generated": "Generated",
    "processed": "Detailed Results Unavailable", "identified": "Identified",
    "unidentified": "Unidentified", "passed": "Passed", "findings": "Findings",
    "constructed": "Constructed", "rejected": "Rejected", "valid": "Valid",
    "invalid": "Invalid", "indeterminate": "Indeterminate", "serialized": "Serialized",
    "error": "Error",
}


def stage_text(step):
    label = STATE_LABELS.get(step["state"], "Unknown")
    outcome = step.get("outcome")
    if outcome:
        label += " — " + OUTCOME_LABELS.get(outcome, outcome.replace("_", " "))
    return label


def _summarize_group(records):
    states = [record["state"] for record in records]
    if "running" in states:
        return "Running / Possibly Interrupted"
    if "failed" in states:
        return "Needs Attention" if "completed" in states else "Failed"
    if "interrupted" in states:
        return "Incomplete Previous Attempt"
    if all(state == "completed" for state in states):
        return "Completed"
    if "completed" in states:
        return "Partially Complete"
    if "unknown" in states:
        return "Unknown"
    return "Not Started"


def summarize_user_steps(status):
    """Summarize five groups, with detail for all nine stage records.

    Input is a validated schema-v1 record. Optional operations are not assumed
    requested because a current GUI checkbox happens to be selected.
    """
    steps = status["steps"]
    summaries = {}
    for user_step, stages in STEP_STAGES.items():
        records = [steps[stage] for stage in stages]
        summaries[user_step] = dict(
            label=_summarize_group(records),
            detail="\n".join(f"{STAGE_NAMES[stage]}: {stage_text(steps[stage])}" for stage in stages))

    av, ingest = steps["antivirus"], steps["ingest"]
    if ingest["state"] == "completed" and av["state"] not in ("running", "interrupted"):
        label = "Completed"
        if av["state"] == "not_started":
            label += " — Virus Scan Not Run"
        elif av["state"] in ("failed", "unknown"):
            label += " — Virus Scan Needs Attention"
        elif av.get("outcome") in ("detections", "partial", "unavailable"):
            label += " — Virus Scan " + OUTCOME_LABELS[av["outcome"]]
        summaries["ingest"]["label"] = label
    elif av["state"] == "completed" and ingest["state"] == "not_started":
        summaries["ingest"]["label"] = "Partially Complete"

    for user_step, stage in (("format_identification", "fits"), ("fixity", "fixity")):
        summaries[user_step]["label"] = stage_text(steps[stage])
    if (steps["reports"]["state"] == "completed" and steps["reports"].get("outcome") == "partial"
            and summaries["reports"]["label"] == "Completed"):
        summaries["reports"]["label"] = "Needs Attention — Partial Reports"

    construction, validation, tar = (steps[stage] for stage in STEP_STAGES["bagging"])
    bag = summaries["bagging"]
    states = [record["state"] for record in (construction, validation, tar)]
    if "running" in states or "interrupted" in states or "failed" in states:
        pass  # Keep the conservative execution-state summary above.
    elif validation["state"] == "completed" and validation.get("outcome") == "invalid":
        bag["label"] = "Needs Attention — Bag Invalid"
    elif "unknown" in states:
        bag["label"] = "Partially Complete — Unknown History" if "completed" in states else "Unknown"
    elif validation["state"] == "completed" and validation.get("outcome") not in ("valid", "invalid"):
        bag["label"] = "Needs Attention — Validation Result Unclear"
    elif construction["state"] == "completed" or validation["state"] == "completed" or tar["state"] == "completed":
        bag["label"] = ("Completed" if all(state == "completed" for state in states) else
                        "TAR Serialized" if tar["state"] == "completed" else
                        "Bag Validated" if validation["state"] == "completed" else "Construction Completed")
        # These keys are honored only if explicitly present in recorded settings.
        # Current recorder does not yet persist optional-action request intent.
        settings = construction.get("settings", {})
        unfinished = []
        if settings.get("validate") is True and validation["state"] == "not_started":
            unfinished.append("Validation Pending")
        if (settings.get("serialize_tar") is True and settings.get("profile") == "aptrust"
                and tar["state"] == "not_started"):
            unfinished.append("TAR Pending")
        if unfinished:
            bag["label"] = "Partially Complete — " + "; ".join(unfinished)
    for user_step, stages in STEP_STAGES.items():
        stale = [stage for stage in stages if steps[stage]["freshness"]["state"] == "stale"]
        if stale:
            summaries[user_step]["label"] += " — Stale"
            summaries[user_step]["detail"] += "\nFreshness: " + "; ".join(
                f"{STAGE_NAMES[stage]}: {', '.join(steps[stage]['freshness']['reasons'])}" for stage in stale)
    return summaries


def format_stage_details(status):
    """Readable execution details; unverified freshness is not a failure."""
    lines = [f"Accession: {status['accession_number']}", f"Revision: {status['revision']}",
             f"Recorded layout: {status['layout']}", ""]
    for stages in STEP_STAGES.values():
        for stage in stages:
            record = status["steps"][stage]
            lines.append(f"{STAGE_NAMES[stage]}: {stage_text(record)}")
            lines.append(f"  Attempt: {record['attempt']}; freshness: {record['freshness']['state']}")
            if record["freshness"].get("reasons"):
                lines.append("  Freshness reasons: " + ", ".join(record["freshness"]["reasons"]))
            if record.get("started_at"):
                lines.append(f"  Started: {record['started_at']}")
            if record.get("finished_at"):
                lines.append(f"  Finished: {record['finished_at']}")
            if record.get("message"):
                lines.append(f"  Message: {record['message']}")
            for name, path in record.get("outputs", {}).items():
                lines.append(f"  Output {name}: {path}")
            lines.append("")
    return "\n".join(lines)
