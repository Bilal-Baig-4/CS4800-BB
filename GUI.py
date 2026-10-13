import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import threading
import logging
import traceback
import re
from datetime import datetime
from lxml import etree as ET
from pipeline_state.recording import RunRecorder, file_count, fixity_result
from pipeline_state import status as pipeline_status
from pipeline_state.view import summarize_user_steps, format_stage_details
from pipeline_state.resume import build_resume_plan, bag_layout
from pipeline_state.freshness import load_reconciled_status

from pipeline import (
    ingest_accession,
    enrich_accession_with_fits,
    run_xslt_processor,
    run_fixity,
    generate_summary_report,
    run_antivirus_scan,
    construct_bag,
    validate_bag,
    serialize_bag_to_tar,
    BAGIT_AVAILABLE,
    AV_AVAILABLE,
    DEFENDER_PATH,
    APTRUST_ACCESS_VALUES,
    APTRUST_STORAGE_OPTIONS,
)


# ==========================
# INPUT LOCKING
# ==========================

def set_inputs_locked(locked: bool):
    """
    Disable every user-editable widget while the pipeline runs so settings
    cannot be changed mid-run. Re-enables them when done.
    """
    global inputs_locked
    inputs_locked = locked
    for widget in lockable_inputs:
        try:
            if isinstance(widget, ttk.Combobox):
                widget.config(state="disabled" if locked else "readonly")
            else:
                widget.config(state="disabled" if locked else "normal")
        except tk.TclError:
            pass
    update_ingest_controls()
    toggle_bag_fields()
    update_history_actions()

# ==========================
# PIPELINE
# ==========================

def selected_run_options():
    """Snapshot selections/settings before locking and starting the worker."""
    return {
        "steps": dict(ingest=run_ingest.get(), fits=run_format_identification.get(),
                      reports=run_reports.get(), fixity=run_fixity_selected.get(),
                      bagging=run_bagging.get()),
        "input": input_dir_var.get(), "output": output_dir_var.get(),
        "accession": accession_var.get().strip(), "move": move_var.get(),
        "antivirus": av_var.get(), "profile": bag_profile_var.get(),
        "validate": validate_bag_var.get(), "tar": serialize_tar_var.get(),
        "rerun_completed": rerun_completed_var.get(),
        "metadata": dict(contact_name=contact_name_var.get().strip(),
                         contact_email=contact_email_var.get().strip(),
                         source_organization=source_org_var.get().strip(),
                         title=bag_title_var.get().strip(), access=bag_access_var.get(),
                         storage_option=bag_storage_var.get(),
                         description=bag_desc_var.get().strip()),
    }


def require_unbagged(payload, operation):
    if not payload.is_dir():
        raise ValueError(f"{operation} requires an existing accession payload directory: {payload}")
    if bag_layout(payload) != "unbagged":
        raise ValueError(f"{operation} requires an unbagged payload. Existing or ambiguous "
                         "BagIt layouts are unsupported; no recovery or rebuild is attempted.")


def require_accession_xml(xml, accession, payload=None, operation="Reports"):
    """Check XML identity and baseline paths without hashing or reconciling outputs."""
    if not xml.is_file():
        raise ValueError(f"{operation} requires existing accession XML: {xml}")
    try:
        tree = ET.parse(str(xml), ET.XMLParser(resolve_entities=False, no_network=True))
    except (OSError, ET.XMLSyntaxError) as exc:
        raise ValueError(f"{operation} cannot read accession XML: {exc}") from exc
    ns = "http://dataaccessioner.org/schema/dda-1-1"
    accession_nodes = tree.findall(f"{{{ns}}}accession")
    if (tree.getroot().tag != f"{{{ns}}}collection" or len(accession_nodes) != 1
            or accession_nodes[0].get("number") != accession):
        raise ValueError(f"{operation} requires Data Accessioner XML for accession {accession}.")
    if payload is not None:
        seen = set()
        for record in tree.findall(f".//{{{ns}}}file"):
            name = record.get("name", "")
            if (not name or "\\" in name or ":" in name
                    or any(part in ("", ".", "..") for part in name.split("/"))
                    or name.casefold() in seen):
                raise ValueError(f"{operation}: invalid or duplicate baseline file path: {name!r}")
            seen.add(name.casefold())
            file_path = payload / name
            if not file_path.resolve().is_relative_to(payload.resolve()):
                raise ValueError(f"{operation}: baseline path escapes the accession: {name}")
            if operation == "Format Identification":
                if not file_path.is_file():
                    raise ValueError(f"Format Identification requires payload file: {file_path}")
                if record.find("{info:lc/xmlns/premis-v2}object/"
                               "{info:lc/xmlns/premis-v2}objectCharacteristics") is None:
                    raise ValueError(f"Format Identification requires baseline PREMIS metadata: {name}")
            if operation == "Fixity" and not re.fullmatch(r"[0-9a-fA-F]{32}", record.get("MD5", "")):
                raise ValueError(f"Fixity requires an MD5 baseline for: {name}")


def validate_selected_run(options, allow_no_steps=False):
    """Validate available prerequisites; same-run producers satisfy later needs."""
    steps = options["steps"]
    if not any(steps.values()) and not allow_no_steps:
        raise ValueError("Select at least one processing step.")
    if not options["output"].strip() or not options["accession"]:
        raise ValueError("Output Directory and Accession Number are required.")
    accession = options["accession"]
    if (accession in (".", "..") or ".." in accession
            or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', accession)
            or accession.endswith(".")
            or accession.split(".")[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}):
        raise ValueError("Accession Number must be a single safe path component.")
    output = Path(options["output"]).resolve()
    payload = output / accession
    xml = output / f"{accession}.xml"
    if payload.resolve().parent != output or xml.resolve().parent != output:
        raise ValueError("Accession paths must stay inside Output Directory.")
    if output.exists() and not output.is_dir():
        raise ValueError("Output Directory must be a directory.")
    if steps["ingest"]:
        if not options["input"].strip() or not Path(options["input"]).is_dir():
            raise ValueError("Ingest requires an existing Input Directory.")
        source = Path(options["input"]).resolve()
        if payload.resolve().is_relative_to(source) or source.is_relative_to(payload.resolve()):
            raise ValueError("Input Directory and accession payload must not contain one another.")
        if payload.exists():
            require_unbagged(payload, "Ingest")
    for key, label in (("fits", "Format Identification"), ("reports", "Reports"),
                       ("fixity", "Fixity")):
        if steps[key] and not steps["ingest"]:
            if key != "reports":
                require_unbagged(payload, label)
            require_accession_xml(xml, accession, payload if key != "reports" else None, label)
    if steps["reports"]:
        for stylesheet in ("files.csv.xslt", "files.html.xslt"):
            if not (Path(__file__).parent / stylesheet).is_file():
                raise ValueError(f"Reports requires stylesheet: {stylesheet}")
    if steps["bagging"]:
        if not BAGIT_AVAILABLE:
            raise ValueError("Bagging requires bagit-python. Install it before running this step.")
        layout = bag_layout(payload)
        if layout == "ambiguous":
            raise ValueError("Existing or ambiguous BagIt layout. Construction will not rebuild it.")
        existing_bag = layout == "bagged" and not steps["ingest"]
        if options["profile"] not in ("aptrust", "generic"):
            raise ValueError("Select a supported BagIt profile.")
        if existing_bag:
            if not (options["validate"] or (options["tar"] and options["profile"] == "aptrust")):
                raise ValueError("An existing bag cannot be reconstructed. Select validation or permitted TAR serialization.")
            actual_profile = "aptrust" if (payload / "aptrust-info.txt").is_file() else "generic"
            if actual_profile != options["profile"]:
                raise ValueError("Selected profile does not match the existing bag; select its current profile.")
        else:
            if not steps["ingest"]:
                require_unbagged(payload, "Bag construction")
            metadata = options["metadata"]
            if any(any(c in value for c in "\r\n\0") for value in metadata.values()):
                raise ValueError("BagIt metadata must be single-line text without NUL characters.")
            if options["profile"] == "aptrust":
                if not metadata["title"] or not metadata["source_organization"]:
                    raise ValueError("APTrust construction requires Title and Source-Organization.")
                if metadata["access"] not in APTRUST_ACCESS_VALUES or metadata["storage_option"] not in APTRUST_STORAGE_OPTIONS:
                    raise ValueError("Select valid APTrust Access and Storage-Option values.")
            # Use an existing baseline when supplied, never silently discard a bad one.
            if xml.exists() and not steps["ingest"]:
                require_accession_xml(xml, accession)


def restore_run_controls():
    progress_bar.stop()
    run_button.config(state="normal")
    set_inputs_locked(False)


def history_identity(output, accession):
    # Compare the captured fields without filesystem resolution during cleanup.
    return (output, accession.strip())


def update_history_actions():
    refresh_status_button.config(state="disabled" if inputs_locked else "normal")
    status_details_button.config(state="normal" if loaded_history is not None and not inputs_locked else "disabled")


def clear_loaded_history(*_):
    global loaded_history, details_window
    loaded_history = None
    if details_window is not None:
        if details_window.winfo_exists():
            details_window.destroy()
        details_window = None
    for variable in step_history_vars.values():
        variable.set("Not Loaded")
    history_message_var.set("Status not loaded")
    update_history_actions()


def select_remaining_steps(status):
    """Suggest mandatory work from loaded status without inferring Bagging intent."""
    groups = (
        (run_ingest, ("ingest",)),
        (run_format_identification, ("fits",)),
        (run_reports, ("reports", "summary")),
        (run_fixity_selected, ("fixity",)),
    )
    for variable, stages in groups:
        variable.set(not all(status["steps"][stage]["state"] == "completed" and
                             status["steps"][stage]["freshness"]["state"] == "current"
                             for stage in stages))
    # Stage history alone does not establish which optional bag operations were requested.
    run_bagging.set(False)


def stale_completed_warning(status):
    """Group completed work affected by changes into the five user-facing steps."""
    groups = (
        ("Step 1 — Ingest", ("antivirus", "ingest")),
        ("Step 2 — Format Identification", ("fits",)),
        ("Step 3 — Reports", ("reports", "summary")),
        ("Step 4 — Fixity", ("fixity",)),
        ("Step 5 — Bagging", ("bag_construct", "bag_validate", "tar_serialize")),
    )
    affected = [heading for heading, stages in groups
                if any(status["steps"][stage]["state"] == "completed" and
                       status["steps"][stage]["freshness"]["state"] == "stale"
                       for stage in stages)]
    if not affected:
        return None
    return ("Files or processing outputs have changed since this accession was last processed.\n\n"
            "The following completed steps may no longer be current:\n\n" +
            "\n".join(f"• {heading}" for heading in affected) +
            "\n\nThe mandatory processing steps that need attention have been selected.\n"
            "Bagging remains optional; select it if needed.\n\n"
            "Review the selections before continuing.")


def load_accession_status(show_errors=True, expected_identity=None):
    """Load durable history; suggest remaining work on a successful manual refresh."""
    global loaded_history
    output, accession = output_dir_var.get(), accession_var.get().strip()
    if expected_identity is not None and history_identity(output, accession) != expected_identity:
        return  # A queued refresh must not display results for a different accession.
    clear_loaded_history()
    try:
        if not output.strip() or not accession:
            raise ValueError("Output Directory and Accession Number are required to load status.")
        status = load_reconciled_status(output, accession)
        summaries = summarize_user_steps(status)
    except FileNotFoundError:
        history_message_var.set("No managed status file found for this accession.")
        return
    except (ValueError, OSError) as exc:
        history_message_var.set("Status could not be loaded; file left unchanged.")
        if show_errors:
            messagebox.showerror("Status Load Error", str(exc))
        return
    loaded_history = status
    if show_errors and expected_identity is None and not inputs_locked:
        select_remaining_steps(status)
    for name, variable in step_history_vars.items():
        variable.set(summaries[name]["label"])
    history_message_var.set(f"Recorded history: {accession}")
    update_history_actions()
    root.update_idletasks()
    width, height = map(int, root.geometry().split("+")[0].split("x"))
    root.geometry(f"{max(width, root.winfo_reqwidth() + 20)}x{max(height, root.winfo_reqheight() + 16)}")
    if show_errors and expected_identity is None and not inputs_locked:
        warning = stale_completed_warning(status)
        if warning:
            messagebox.showwarning("Changes Detected", warning)


def show_status_details():
    global details_window
    if loaded_history is None or inputs_locked:
        return
    if details_window is not None and details_window.winfo_exists():
        details_window.lift()
        return
    details_window = tk.Toplevel(root)
    details_window.title(f"Recorded Status — {loaded_history['accession_number']}")
    details_window.transient(root)
    text = tk.Text(details_window, width=75, height=24, wrap="word")
    scroll = ttk.Scrollbar(details_window, command=text.yview)
    text.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    text.pack(side="left", fill="both", expand=True)
    text.insert("1.0", format_stage_details(loaded_history))
    text.configure(state="disabled")


def prepare_execution_plan(options):
    if not any(options["steps"].values()):
        raise ValueError("Select at least one processing step.")
    if not options["output"].strip() or not options["accession"]:
        raise ValueError("Output Directory and Accession Number are required.")
    try:
        status = load_reconciled_status(options["output"], options["accession"])
    except FileNotFoundError:
        status = None
    options["_managed_status_exists"] = status is not None
    plan = build_resume_plan(status, options["steps"], options, options["output"], options["accession"])
    return plan


def format_run_confirmation(plan, options):
    """Describe planned work for users without changing any decisions."""
    groups = (
        ("Step 1 — Ingest", ("antivirus", "ingest")),
        ("Step 2 — Format Identification", ("fits",)),
        ("Step 3 — Reports", ("reports", "summary")),
        ("Step 4 — Fixity", ("fixity",)),
        ("Step 5 — Bagging", ("bag_construct", "bag_validate", "tar_serialize")),
    )
    by_stage = {item["stage"]: item for item in plan}
    labels = {
        "antivirus": "Microsoft Defender scan",
        "ingest": "Move files into accession" if options.get("move") else "Copy files into accession",
        "fits": "Format identification", "reports": "Metadata reports",
        "summary": "Collection summary", "fixity": "Fixity verification",
        "bag_construct": "Create BagIt package", "bag_validate": "Validate BagIt package",
        "tar_serialize": "Create TAR archive",
    }
    prerequisites = {
        "ingest": "accession files and inventory", "fits": "format identification output",
        "reports": "metadata reports", "bag_construct": "BagIt package",
        "bag_validate": "BagIt validation",
    }
    warnings = {
        "previous_attempt_may_be_interrupted": "A previous attempt may still be running or was interrupted; review it before continuing.",
        "unknown_history": "The previous processing result is unknown; review it before continuing.",
        "unsafe_automatic_retry": "A previous attempt did not finish safely; review the existing files before retrying.",
        "outcome_not_satisfied": "The previous result needs attention before continuing.",
        "completed_outputs_missing_or_ambiguous": "Previously completed outputs are missing or unclear; review them before continuing.",
        "scan_result_not_usable": "The previous scan could not be used; review the scan results.",
        "existing_bag_cannot_be_rebuilt": "An existing BagIt package cannot be rebuilt automatically.",
        "ambiguous_bag_layout": "The existing package structure is unclear; review it before continuing.",
        "existing_bag_profile_mismatch": "The existing package does not match the selected packaging profile.",
        "unbagged_payload_required": "This work requires accession files that have not been bagged.",
        "existing_preservation_baseline": "An accession inventory already exists; review it before ingesting again.",
        "scan_cannot_be_reused_for_new_ingest": "A new ingest needs a new virus scan.",
        "successful_validation_required": "The BagIt package must pass validation before creating a TAR archive.",
        "managed_fixity_findings_require_passing_rerun": "Fixity found missing or changed files; rerun Fixity and obtain a passing result before bagging.",
        "completed_outputs_missing": "Previously completed outputs are missing and will be recreated.",
        "explicit_safe_rerun": "Previously completed work will run again as requested.",
        "failed": "The previous attempt failed; this work will be retried.",
        "interrupted": "The previous attempt was interrupted; this work will be retried.",
    }
    lines = ["The following steps will run:", ""]
    attention = []
    for heading, stages in groups:
        entries = [by_stage[s] for s in stages if s in by_stage]
        running = [item for item in entries if item["action"] == "run"]
        if running:
            lines.append(heading)
            if len(stages) > 1:
                lines.extend(f"  • {labels[item['stage']]}" for item in running)
        for item in entries:
            if item["reason"] == "not_requested":
                continue
            reason = item["reason"]
            warning = warnings.get(reason)
            if reason == "recorded_stale" or "freshness_reasons" in item:
                stale = ("Outputs have changed; affected work will run again." if item["action"] == "run"
                         else "Outputs have changed; review them before continuing.")
                attention.append(f"{heading}: {labels[item['stage']]} — {stale}")
            if reason.endswith("_requires_review"):
                producer = reason.removesuffix("_requires_review")
                warning = f"Review {prerequisites.get(producer, 'earlier work')} before continuing."
            elif reason.startswith("missing_") and reason.endswith("_prerequisite"):
                producer = reason[len("missing_"):-len("_prerequisite")]
                warning = f"Required {prerequisites.get(producer, 'earlier outputs')} could not be found."
            if warning is None and item["action"] in ("review", "block") and reason != "recorded_stale":
                warning = "This work needs review before processing can start."
            if warning:
                attention.append(f"{heading}: {labels[item['stage']]} — {warning}")
            if item.get("requires_passing_fixity"):
                attention.append(f"{heading}: Fixity must pass before creating the BagIt package.")
    if not any(item["action"] == "run" for item in plan):
        lines = ["No steps need to run."]
    if any(item["action"] == "reuse" for item in plan):
        lines.extend(["", "Previously completed steps will be reused automatically."])
    if any(all(by_stage[s]["reason"] == "not_requested" for s in stages) for _, stages in groups):
        lines.extend(["", "Other steps will not run."])
    if attention:
        lines.extend(["", "Please note:", *dict.fromkeys(attention)])
    return "\n".join(lines)


def confirm_run(message):
    """Modal confirmation with explicit Run and Cancel buttons."""
    dialog = tk.Toplevel(root)
    dialog.title("Confirm Run")
    dialog.transient(root)
    confirmed = False

    def finish(run=False):
        nonlocal confirmed
        confirmed = run
        dialog.destroy()

    frame = ttk.Frame(dialog, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=message, wraplength=580, justify="left").pack(anchor="w")
    buttons = ttk.Frame(frame)
    buttons.pack(anchor="e", pady=(16, 0))
    ttk.Button(buttons, text="Run", command=lambda: finish(True)).pack(side="left", padx=(0, 8))
    cancel = ttk.Button(buttons, text="Cancel", command=finish)
    cancel.pack(side="left")
    dialog.protocol("WM_DELETE_WINDOW", finish)
    dialog.bind("<Escape>", lambda event: finish())
    dialog.grab_set()
    cancel.focus_set()
    root.wait_window(dialog)
    return confirmed


def validate_execution_plan(options, plan):
    if not options.get("_managed_status_exists", False):
        # Keep established selective prerequisites/diagnostics for first managed runs.
        validate_selected_run(options)
    if any(item["action"] in ("review", "block") for item in plan):
        raise ValueError(format_run_confirmation(plan, options) +
                         "\n\nProcessing will not start. Review the warnings and Status Details before continuing.")
    actions = {item["stage"]: item["action"] for item in plan}
    effective = dict(options)
    effective["steps"] = dict(ingest=actions["ingest"] == "run", fits=actions["fits"] == "run",
                             reports=actions["reports"] == "run", fixity=actions["fixity"] == "run",
                             bagging=any(actions[s] == "run" for s in ("bag_construct", "bag_validate", "tar_serialize")))
    validate_selected_run(effective, allow_no_steps=True)
    if actions["antivirus"] == "run" and (not options["input"].strip() or not Path(options["input"]).is_dir()):
        raise ValueError("Antivirus requires an existing Input Directory, or disable the scan option.")


def run_pipeline(options=None, plan=None):
    # start_pipeline snapshots on the Tk thread; direct callers can snapshot here.
    options = selected_run_options() if options is None else options
    steps = options["steps"]
    out_dir = Path(options["output"])
    accession = options["accession"]
    payload = out_dir / accession
    xml = out_dir / f"{accession}.xml"
    log_path = None
    infected_files = {}
    bag_valid = None
    tar_path = None
    try:
        fresh_plan = prepare_execution_plan(options)
        if plan is not None and fresh_plan != plan:
            raise ValueError("Execution plan changed after preview. Refresh status and start again.")
        plan = fresh_plan
        validate_execution_plan(options, plan)
        actions = {item["stage"]: item["action"] for item in plan}
        should_run = lambda stage: actions[stage] == "run"
        out_dir.mkdir(parents=True, exist_ok=True)
        recorder = RunRecorder(out_dir, accession)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = out_dir / f"pipeline_log_{accession}_{timestamp}.log"
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(filename=log_path, level=logging.INFO,
                            format="%(asctime)s - %(levelname)s - %(message)s", filemode="w",
                            encoding="utf-8")
        logging.info("Selected processing started: %s", ", ".join(k for k, v in steps.items() if v))
        if should_run("antivirus") or should_run("ingest"):
            clean_files = None
            if should_run("antivirus"):
                import pipeline as pipeline_module
                if not pipeline_module.AV_AVAILABLE:
                    recorder.run("antivirus", lambda: None, lambda _: dict(
                        state="failed", outcome="unavailable", message="Microsoft Defender unavailable.",
                        result=dict(scanned_count=0, detection_count=None, error_count=None)),
                        settings={"requested": True})
                    logging.warning("Microsoft Defender unavailable; scan skipped.")
                    messagebox.showwarning("Windows Defender Unavailable",
                                           "Microsoft Defender is unavailable. Processing will continue without an antivirus scan.")
                else:
                    status_var.set("Scanning files with Microsoft Defender...")
                    scan_observation = {}

                    def scan_result(value):
                        _, detections, unavailable = value
                        details = dict(scan_observation)
                        artifacts = details.pop("outputs", {})
                        state = details.pop("state", "failed" if unavailable else "completed")
                        outcome = details.pop("outcome", "unavailable" if unavailable else "detections" if detections else "processed")
                        details.setdefault("scanned_count", None)
                        details.setdefault("error_count", None)
                        details.setdefault("detection_count", len(detections))
                        result = dict(state=state, outcome=outcome, result=details,
                                      outputs=recorder.paths(**artifacts))
                        if state == "failed":
                            result["message"] = "Microsoft Defender verification unavailable."
                        return result

                    clean_files, infected_files, skipped = recorder.run(
                        "antivirus", lambda: run_antivirus_scan(options["input"], out_dir, accession,
                                                                result_callback=scan_observation.update),
                        scan_result, settings={"requested": True})
                    if skipped:
                        clean_files = None
                        messagebox.showwarning("Antivirus Scan Skipped",
                                               "Microsoft Defender could not complete the scan. Processing will continue without antivirus verification.")
                    elif infected_files:
                        findings = "\n".join(f"  {p.name}: {threat}" for p, threat in infected_files.items())
                        if not messagebox.askyesno("Threats Detected", f"Microsoft Defender flagged {len(infected_files)} file(s):\n\n{findings}\n\nContinue without these files?"):
                            status_var.set("Processing cancelled by user.")
                            logging.warning("Processing cancelled after Defender detections.")
                            return
                    else:
                        clean_files = None
            if should_run("ingest"):
                status_var.set("Running Ingest...")
                xml = Path(recorder.run("ingest", lambda: ingest_accession(
                options["input"], out_dir, accession, move_files=options["move"],
                clean_files_only=clean_files if infected_files else None,
                progress_callback=lambda current, total, name: root.after(
                    0, status_var.set, f"Ingest: {current}/{total}: {name}")),
                lambda path: dict(outcome="empty" if file_count(path) == 0 else "generated",
                                  result={"file_count": file_count(path)},
                                  outputs=recorder.paths(payload=payload, xml=path)),
                settings={"move_files": options["move"]}, layout="unbagged"))
        if should_run("fits"):
            require_unbagged(payload, "Format Identification")
            require_accession_xml(xml, accession, payload, "Format Identification")
            status_var.set("Running Format Identification...")
            recorder.run("fits", lambda: enrich_accession_with_fits(payload, xml,
                progress_callback=lambda current, total, name: root.after(
                    0, status_var.set, f"Format Identification: {current}/{total}: {name}")),
                lambda _: dict(outcome="processed", outputs=recorder.paths(xml=xml),
                               result={"message": "API returned normally; per-attempt FITS findings are not exposed."}))
        if should_run("reports") or should_run("summary"):
            if should_run("reports"):
                require_accession_xml(xml, accession)
            status_var.set("Generating Reports...")
            csv = out_dir / f"{accession}_files.csv"
            html = out_dir / f"{accession}_files.html"
            report_progress = dict(csv_generated=False, html_generated=False)

            def generate_reports():
                run_xslt_processor(xml, Path(__file__).parent / "files.csv.xslt", csv)
                report_progress["csv_generated"] = True
                run_xslt_processor(xml, Path(__file__).parent / "files.html.xslt", html)
                report_progress["html_generated"] = True

            if should_run("reports"):
                recorder.run("reports", generate_reports,
                         lambda _: dict(outcome="generated", result=dict(report_progress),
                                        outputs=recorder.paths(csv=csv, html=html)), progress=report_progress)
            if should_run("summary"):
                recorder.run("summary", lambda: generate_summary_report(csv, out_dir, accession),
                         lambda _: dict(outcome="generated", outputs=recorder.paths(text=out_dir / f"{accession}.txt")))
        if should_run("fixity"):
            require_unbagged(payload, "Fixity")
            require_accession_xml(xml, accession, payload, "Fixity")
            status_var.set("Running Fixity...")
            recorder.run("fixity", lambda: run_fixity(xml, out_dir, accession),
                         lambda result: fixity_result(recorder, result))
        if any(should_run(s) for s in ("bag_construct", "bag_validate", "tar_serialize")):
            if recorder.status["steps"]["fixity"]["outcome"] == "findings":
                raise ValueError("Managed fixity findings block Bagging. Explicitly rerun Fixity and obtain a passing result.")
            if any(item.get("requires_passing_fixity") for item in plan) and recorder.status["steps"]["fixity"]["outcome"] != "passed":
                raise ValueError("A passing Fixity rerun is required before Bagging.")
            bag_path = payload
            if should_run("bag_construct"):
                status_var.set("Constructing Bag...")
                # Retain the existing Windows handler-release behavior before moving payload.
                for handler in logging.root.handlers[:]:
                    handler.flush()
                    handler.close()
                    logging.root.removeHandler(handler)
                try:
                    bag_path = recorder.run("bag_construct", lambda: construct_bag(payload, accession, profile=options["profile"],
                                             xml_manifest=xml if xml.exists() else None,
                                             **options["metadata"]),
                        lambda path: dict(outcome="constructed", outputs=recorder.paths(
                            bag=path, declaration=Path(path) / "bagit.txt", manifest=Path(path) / "manifest-md5.txt")),
                        settings=dict(profile=options["profile"], **{key: options["metadata"][key] for key in
                                      ("source_organization", "access", "storage_option")}),
                        failure_outcome=lambda exc: "rejected" if isinstance(exc, ValueError) else "error", layout="bagged")
                finally:
                    handler = logging.FileHandler(log_path, "a", encoding="utf-8")
                    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
                    logging.root.addHandler(handler)
            if should_run("bag_validate"):
                status_var.set("Validating Bag...")
                validation_observation = {}

                def validation_result(value):
                    valid, error = value
                    result = dict(validation_observation)
                    state = result.pop("state", "completed")
                    outcome = result.pop("outcome", "valid" if valid else "invalid")
                    message = result.pop("message", error)
                    result.setdefault("valid", valid)
                    return dict(state=state, outcome=outcome, result=result, message=message[:2000])

                bag_valid, error = recorder.run("bag_validate", lambda: validate_bag(
                    bag_path, result_callback=validation_observation.update), validation_result,
                    failure_outcome="indeterminate")
                if not bag_valid:
                    raise ValueError(f"Bag validation failed; TAR serialization blocked: {error}")
            if should_run("tar_serialize"):
                status_var.set("Serializing TAR...")
                tar_path = recorder.run("tar_serialize", lambda: serialize_bag_to_tar(bag_path),
                                        lambda path: dict(outcome="serialized", outputs=recorder.paths(tar=path)))
        status_var.set("Selected processing steps completed.")
        logging.info("Selected processing steps completed.")
        summary = ["Selected processing steps completed."]
        if infected_files:
            summary.append(f"{len(infected_files)} Defender-flagged file(s) excluded from ingest.")
        if bag_valid is True:
            summary.append("BagIt bag validated.")
        if tar_path:
            summary.append(f"TAR archive: {tar_path}")
        summary.append(f"Log file:\n{log_path}")
        messagebox.showinfo("Processing Complete", "\n".join(summary))
    except Exception as exc:
        logging.error("Selected processing failed.\n" + traceback.format_exc())
        status_var.set("Processing failed; see error details.")
        messagebox.showerror("Processing Error", f"{exc}" + (f"\n\nLog file:\n{log_path}" if log_path else ""))
    finally:
        restore_run_controls()
        # Reload the durable file on the Tk thread, including failed final writes.
        root.after(0, load_accession_status, False, history_identity(options["output"], accession))


def start_pipeline():
    options = selected_run_options()
    try:
        plan = prepare_execution_plan(options)
        validate_execution_plan(options, plan)
    except (ValueError, OSError) as exc:
        status_var.set("Processing not started; check prerequisites.")
        messagebox.showerror("Processing Prerequisites", str(exc))
        return
    if not confirm_run(format_run_confirmation(plan, options)):
        return
    status_var.set("Starting selected processing...")
    run_button.config(state="disabled")
    set_inputs_locked(True)
    progress_bar.start(10)
    try:
        threading.Thread(target=run_pipeline, args=(options, plan), daemon=True).start()
    except Exception:
        restore_run_controls()
        raise


# ==========================
# BAG FRAME VISIBILITY
# ==========================

def on_profile_change(*_):
    toggle_bag_fields()


def update_ingest_controls(*_):
    enabled = run_ingest.get() and not inputs_locked
    chk_move.config(state="normal" if enabled else "disabled")
    chk_av.config(state="normal" if enabled and AV_AVAILABLE else "disabled")


def toggle_bag_fields():
    is_aptrust = (bag_profile_var.get() == "aptrust")
    enabled = run_bagging.get() and BAGIT_AVAILABLE and not inputs_locked
    chk_bag.config(state="normal" if BAGIT_AVAILABLE and not inputs_locked else "disabled")
    for widget in bag_controls:
        allowed = enabled and (is_aptrust or widget not in aptrust_only_controls)
        widget.config(state=("readonly" if isinstance(widget, ttk.Combobox) else "normal")
                      if allowed else "disabled")
    for widget in aptrust_only_widgets:
        if is_aptrust:
            widget.grid()
        else:
            widget.grid_remove()
    root.update_idletasks()


# ==========================
# GUI SETUP
# ==========================

root = tk.Tk()
root.title("Archival Pipeline")
root.geometry("700x820")
root.resizable(False, False)

input_dir_var    = tk.StringVar()
output_dir_var   = tk.StringVar()
accession_var    = tk.StringVar()
move_var         = tk.BooleanVar()
av_var           = tk.BooleanVar(value=AV_AVAILABLE)
# Five user-facing selections control independent operations in workflow order.
run_ingest = tk.BooleanVar(value=True)
run_format_identification = tk.BooleanVar(value=True)
run_reports = tk.BooleanVar(value=True)
run_fixity_selected = tk.BooleanVar(value=True)
run_bagging = tk.BooleanVar(value=True)
rerun_completed_var = tk.BooleanVar(value=False)
inputs_locked = False
loaded_history = None
details_window = None
step_history_vars = {name: tk.StringVar(value="Not Loaded") for name in
                     ("ingest", "format_identification", "reports", "fixity", "bagging")}
history_message_var = tk.StringVar(value="Status not loaded")
status_var       = tk.StringVar(value="Idle")
av_status_var    = tk.StringVar()

bag_profile_var   = tk.StringVar(value="aptrust")
source_org_var    = tk.StringVar()
contact_name_var  = tk.StringVar()
contact_email_var = tk.StringVar()
bag_title_var     = tk.StringVar()
bag_access_var    = tk.StringVar(value="Institution")
bag_storage_var   = tk.StringVar(value="Standard")
bag_desc_var      = tk.StringVar()
serialize_tar_var = tk.BooleanVar(value=True)
validate_bag_var  = tk.BooleanVar(value=False)

# Uniform padding used throughout
pad    = {"padx": 10, "pady": 3}   # outer form rows
ipad   = {"padx": 6,  "pady": 3}   # inner frame rows (labels)
epad   = {"padx": 0,  "pady": 3}   # inner frame rows (entries/widgets)

# Input Directory
tk.Label(root, text="Input Directory:").grid(row=0, column=0, sticky="e", **pad)
ent_input = tk.Entry(root, textvariable=input_dir_var, width=42)
ent_input.grid(row=0, column=1, **pad)
btn_input = tk.Button(root, text="Browse",
                      command=lambda: input_dir_var.set(filedialog.askdirectory()))
btn_input.grid(row=0, column=2, padx=5)

# Output Directory
tk.Label(root, text="Output Directory:").grid(row=1, column=0, sticky="e", **pad)
ent_output = tk.Entry(root, textvariable=output_dir_var, width=42)
ent_output.grid(row=1, column=1, **pad)
btn_output = tk.Button(root, text="Browse",
                       command=lambda: output_dir_var.set(filedialog.askdirectory()))
btn_output.grid(row=1, column=2, padx=5)

# Accession Number
tk.Label(root, text="Accession Number:").grid(row=2, column=0, sticky="e", **pad)
ent_accession = tk.Entry(root, textvariable=accession_var, width=28)
ent_accession.grid(row=2, column=1, sticky="w", **pad)

# ---- Five user-facing processing steps ----
steps_frame = tk.LabelFrame(root, text="Processing Steps", padx=8, pady=4)
steps_frame.grid(row=3, column=0, columnspan=3, sticky="ew", padx=10, pady=3)
steps_frame.columnconfigure(1, weight=1)
chk_ingest = tk.Checkbutton(steps_frame, text="Step 1 — Ingest", variable=run_ingest)
chk_ingest.grid(row=0, column=0, sticky="w")
av_frame = tk.Frame(steps_frame)
av_frame.grid(row=1, column=0, columnspan=2, sticky="w", padx=22)

chk_av = tk.Checkbutton(av_frame, text="Scan files with Microsoft Defender",
                        variable=av_var,
                        state="normal" if AV_AVAILABLE else "disabled")
chk_av.grid(row=0, column=0, sticky="w")

if AV_AVAILABLE:
    av_status_var.set("Microsoft Defender available")
elif DEFENDER_PATH is not None:
    av_status_var.set("Microsoft Defender installed but not operational")
else:
    av_status_var.set("Microsoft Defender not found")
tk.Label(av_frame, textvariable=av_status_var, fg="gray",
         font=("TkDefaultFont", 8)).grid(row=1, column=0, columnspan=2, sticky="w", padx=4)
chk_move = tk.Checkbutton(av_frame, text="Move files instead of copy", variable=move_var)
chk_move.grid(row=2, column=0, sticky="w")

chk_format = tk.Checkbutton(steps_frame, text="Step 2 — Format Identification",
                            variable=run_format_identification)
chk_format.grid(row=2, column=0, sticky="w")
chk_reports = tk.Checkbutton(steps_frame, text="Step 3 — Reports", variable=run_reports)
chk_reports.grid(row=3, column=0, sticky="w")
chk_fixity = tk.Checkbutton(steps_frame, text="Step 4 — Fixity", variable=run_fixity_selected)
chk_fixity.grid(row=4, column=0, sticky="w")

# BagIt checkbox
bag_label = ("Step 5 — Bagging (optional)" if BAGIT_AVAILABLE
             else "Step 5 — Bagging (install bagit-python to enable)")
chk_bag = tk.Checkbutton(steps_frame, text=bag_label, variable=run_bagging,
                         state="normal" if BAGIT_AVAILABLE else "disabled")
chk_bag.grid(row=5, column=0, sticky="w")
for row, name in ((0, "ingest"), (2, "format_identification"), (3, "reports"),
                  (4, "fixity"), (5, "bagging")):
    tk.Label(steps_frame, textvariable=step_history_vars[name], anchor="w",
             justify="left", wraplength=300, fg="gray", font=("TkDefaultFont", 8)).grid(
        row=row, column=1, sticky="w", padx=(8, 0))

# ---- BagIt metadata frame ----
bag_frame = tk.LabelFrame(steps_frame, text="BagIt Metadata", padx=8, pady=4)
bag_frame.grid(row=6, column=0, columnspan=2, sticky="ew", padx=(22, 0), pady=3)
aptrust_only_widgets = []
r = 0

tk.Label(bag_frame, text="BagIt Profile:").grid(row=r, column=0, sticky="e", **ipad)
pf = tk.Frame(bag_frame)
pf.grid(row=r, column=1, columnspan=2, sticky="w", **epad)
rb_aptrust = tk.Radiobutton(pf, text="APTrust", variable=bag_profile_var,
                             value="aptrust", command=on_profile_change)
rb_aptrust.pack(side="left")
rb_generic = tk.Radiobutton(pf, text="Generic BagIt", variable=bag_profile_var,
                              value="generic", command=on_profile_change)
rb_generic.pack(side="left", padx=10)
r += 1

tk.Label(bag_frame, text="Source-Organization: *").grid(row=r, column=0, sticky="e", **ipad)
ent_source_org = tk.Entry(bag_frame, textvariable=source_org_var, width=36)
ent_source_org.grid(row=r, column=1, sticky="w", **epad); r += 1

tk.Label(bag_frame, text="Contact Name:").grid(row=r, column=0, sticky="e", **ipad)
ent_contact_name = tk.Entry(bag_frame, textvariable=contact_name_var, width=36)
ent_contact_name.grid(row=r, column=1, sticky="w", **epad); r += 1

tk.Label(bag_frame, text="Contact Email:").grid(row=r, column=0, sticky="e", **ipad)
ent_contact_email = tk.Entry(bag_frame, textvariable=contact_email_var, width=36)
ent_contact_email.grid(row=r, column=1, sticky="w", **epad); r += 1

lbl_title = tk.Label(bag_frame, text="Title: *")
lbl_title.grid(row=r, column=0, sticky="e", **ipad)
ent_title = tk.Entry(bag_frame, textvariable=bag_title_var, width=36)
ent_title.grid(row=r, column=1, sticky="w", **epad)
aptrust_only_widgets += [lbl_title, ent_title]; r += 1

lbl_access = tk.Label(bag_frame, text="Access: *")
lbl_access.grid(row=r, column=0, sticky="e", **ipad)
access_frame = tk.Frame(bag_frame)
access_frame.grid(row=r, column=1, sticky="w", **epad)
cmb_access = ttk.Combobox(access_frame, textvariable=bag_access_var,
                           values=APTRUST_ACCESS_VALUES, state="readonly", width=16)
cmb_access.pack(side="left")
tk.Label(access_frame, text="Institution = visible to all staff at your org",
         fg="gray", font=("TkDefaultFont", 8)).pack(side="left", padx=6)
aptrust_only_widgets += [lbl_access, access_frame]; r += 1

lbl_storage = tk.Label(bag_frame, text="Storage-Option: *")
lbl_storage.grid(row=r, column=0, sticky="e", **ipad)
cmb_storage = ttk.Combobox(bag_frame, textvariable=bag_storage_var,
                            values=APTRUST_STORAGE_OPTIONS, state="readonly", width=18)
cmb_storage.grid(row=r, column=1, sticky="w", **epad)
aptrust_only_widgets += [lbl_storage, cmb_storage]; r += 1

lbl_desc = tk.Label(bag_frame, text="Description:")
lbl_desc.grid(row=r, column=0, sticky="e", **ipad)
ent_desc = tk.Entry(bag_frame, textvariable=bag_desc_var, width=36)
ent_desc.grid(row=r, column=1, sticky="w", **epad)
aptrust_only_widgets += [lbl_desc, ent_desc]; r += 1

chk_tar = tk.Checkbutton(bag_frame,
                          text="Serialize to .tar (required for APTrust upload)",
                          variable=serialize_tar_var)
chk_tar.grid(row=r, column=1, sticky="w", padx=0, pady=2)
aptrust_only_widgets.append(chk_tar); r += 1

chk_validate = tk.Checkbutton(bag_frame,
                               text="Validate bag after creation (slower — rehashes all files)",
                               variable=validate_bag_var)
chk_validate.grid(row=r, column=1, sticky="w", padx=0, pady=2)
r += 1

lbl_req = tk.Label(bag_frame, text="* Required for APTrust",
                    fg="gray", font=("TkDefaultFont", 8))
lbl_req.grid(row=r, column=1, sticky="w", padx=2, pady=(0, 2))
aptrust_only_widgets.append(lbl_req)

# ---- Lockable inputs (disabled during pipeline run) ----
lockable_inputs = [
    ent_input, btn_input,
    ent_output, btn_output,
    ent_accession,
    chk_move, chk_av, chk_ingest, chk_format, chk_reports, chk_fixity, chk_bag,
    rb_aptrust, rb_generic,
    ent_source_org, ent_contact_name, ent_contact_email,
    ent_title, cmb_access, cmb_storage, ent_desc, chk_tar, chk_validate,
]

history_frame = tk.Frame(root)
history_frame.grid(row=4, column=0, columnspan=3, sticky="ew", padx=10, pady=3)
rerun_completed_check = tk.Checkbutton(history_frame, text="Rerun completed selected steps", variable=rerun_completed_var)
rerun_completed_check.grid(row=1, column=0, columnspan=3, sticky="w")
lockable_inputs.append(rerun_completed_check)
refresh_status_button = tk.Button(history_frame, text="Load / Refresh Status", command=load_accession_status)
refresh_status_button.grid(row=0, column=0, sticky="w")
status_details_button = tk.Button(history_frame, text="Status Details", command=show_status_details, state="disabled")
status_details_button.grid(row=0, column=1, sticky="w", padx=6)
tk.Label(history_frame, textvariable=history_message_var, anchor="w", justify="left",
         wraplength=330, font=("TkDefaultFont", 8)).grid(row=0, column=2, sticky="w")
lockable_inputs += [refresh_status_button, status_details_button]
output_dir_var.trace_add("write", clear_loaded_history)
accession_var.trace_add("write", clear_loaded_history)

bag_controls = [rb_aptrust, rb_generic, ent_source_org, ent_contact_name,
                ent_contact_email, ent_title, cmb_access, cmb_storage,
                ent_desc, chk_tar, chk_validate]
aptrust_only_controls = [ent_title, cmb_access, cmb_storage, ent_desc, chk_tar]
run_ingest.trace_add("write", update_ingest_controls)
run_bagging.trace_add("write", lambda *_: toggle_bag_fields())
bag_profile_var.trace_add("write", on_profile_change)
update_ingest_controls()
toggle_bag_fields()

# Status
tk.Label(root, textvariable=status_var, anchor="w", fg="blue").grid(
    row=5, column=0, columnspan=3, sticky="w", padx=10, pady=3)

# Run button
run_button = tk.Button(root, text="Run Selected Steps", command=start_pipeline,
                       bg="#4CAF50", fg="white", width=20)
run_button.grid(row=6, column=1, pady=6)

# Progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=420, mode="indeterminate")
progress_bar.grid(row=7, column=0, columnspan=3, padx=10, pady=(0, 8))

# Accommodate larger system fonts/DPI while keeping the default size compact.
root.update_idletasks()
root.geometry(f"{max(700, root.winfo_reqwidth() + 20)}x{max(820, root.winfo_reqheight() + 16)}")

root.mainloop()
