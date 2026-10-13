"""Versioned change-detection evidence, not preservation integrity verification.

Payload/bag membership uses stat metadata; TAR contents are never hashed here.
Only small metadata artifacts use exact-byte MD5. Reconciliation does not execute
operations or replace historical evidence. Execution state and freshness are separate.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from lxml import etree as ET

from . import status as pipeline_status

METHOD = "fingerprint-v1"
DA = "http://dataaccessioner.org/schema/dda-1-1"
PREMIS = "info:lc/xmlns/premis-v2"
FITS = "http://hul.harvard.edu/ois/xml/ns/fits/fits_output"


def _digest(value):
    return hashlib.md5(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8")).hexdigest()


def file_md5(path):
    path = Path(path)
    before = path.stat()
    digest = hashlib.md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("artifact_changed_during_read")
    return digest.hexdigest()


def _node(element):
    return [element.tag, sorted(element.attrib.items()), (element.text or "").strip(),
            [_node(child) for child in element if isinstance(child.tag, str)]]


def _xml(path):
    tree = ET.parse(str(path), ET.XMLParser(resolve_entities=False, no_network=True))
    if tree.getroot().tag != f"{{{DA}}}collection":
        raise ValueError("invalid_accession_xml")
    files = tree.findall(f".//{{{DA}}}file")
    names = [record.get("name", "") for record in files]
    if len(set(names)) != len(names) or any(not name for name in names):
        raise ValueError("invalid_inventory_membership")
    return tree, sorted(files, key=lambda element: element.get("name"))


def inventory_md5(path):
    tree, files = _xml(path)
    records = []
    for file in files:
        records.append(dict(path=file.get("name"), size=file.get("size"), md5=file.get("MD5"),
                            identifiers=[_node(n) for n in file.findall(f".//{{{PREMIS}}}objectIdentifier")],
                            fixity=[_node(n) for n in file.findall(f".//{{{PREMIS}}}fixity")],
                            premis_size=[n.text for n in file.findall(f".//{{{PREMIS}}}objectCharacteristics/{{{PREMIS}}}size")]))
    return _digest(dict(accessions=[n.get("number") for n in tree.findall(f"{{{DA}}}accession")], files=records))


def fits_md5(path):
    _, files = _xml(path)
    records = []
    for file in files:
        embedded = file.findall(f".//{{{FITS}}}fits")
        values = {text for report in embedded for node in report.iter() for text in
                  [node.text, *node.attrib.values()] if text and text.strip()}
        formats = []
        for format in file.findall(f".//{{{PREMIS}}}format"):
            notes = " ".join(format.itertext()).lower()
            matching = any((node.text or "").strip() in values for node in format.iter())
            if "fits" in notes or "droid" in notes or matching:
                formats.append(_node(format))
        records.append(dict(path=file.get("name"), formats=formats, embedded=[_node(n) for n in embedded]))
    return _digest(records)


def _no_link(path):
    if path.is_symlink() or path.is_junction():
        raise ValueError("payload_links_not_supported")


def resolve_payload_root(payload, layout):
    """Resolve physical layout for inspection only, never post-bag execution."""
    payload = Path(payload)
    _no_link(payload)
    if not payload.is_dir():
        raise FileNotFoundError(payload)
    names = {p.name.casefold() for p in payload.iterdir()}
    basic = ((payload / "data").is_dir() and (payload / "bagit.txt").is_file()
             and (payload / "bag-info.txt").is_file()
             and any(p.is_file() for p in payload.glob("manifest-*.txt")))
    indicators = bool(names & {"data", "bagit.txt", "bag-info.txt", "aptrust-info.txt", "fetch.txt"}) or any(
        re.fullmatch(r"(?:tag)?manifest-.*\.txt", name) for name in names)
    if layout == "ambiguous" or (indicators and not basic) or (layout == "bagged" and not basic):
        raise ValueError("ambiguous_payload_layout")
    root = payload / "data" if basic else payload
    _no_link(root)
    return root


def _membership(root, include_dirs=False):
    result = []
    _no_link(root)
    def walk_error(exc):
        raise exc
    for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in sorted(directories + files):
            path = Path(directory) / name
            _no_link(path)
            relative = path.relative_to(root).as_posix()
            if path.is_file():
                stat = path.stat()
                result.append([relative, "file", stat.st_size, stat.st_mtime_ns])
            elif path.is_dir():
                if include_dirs:
                    result.append([relative, "dir"])
            else:
                raise ValueError("unsupported_payload_entry")
    return sorted(result)


def payload_stat_md5(payload, layout):
    return _digest(_membership(resolve_payload_root(payload, layout)))


def bag_stat_md5(bag):
    bag = Path(bag)
    if resolve_payload_root(bag, "bagged") != bag / "data":
        raise ValueError("ambiguous_payload_layout")
    critical = {}
    for path in sorted(bag.iterdir()):
        if path.name.casefold() in {"bagit.txt", "bag-info.txt", "aptrust-info.txt", "fetch.txt"} or re.fullmatch(r"(?:tag)?manifest-.*\.txt", path.name.casefold()):
            _no_link(path)
            critical[path.name] = file_md5(path)
    return _digest(dict(membership=_membership(bag, include_dirs=True), metadata=critical))


def file_stat(path):
    stat = Path(path).stat()
    return dict(size=stat.st_size, mtime_ns=stat.st_mtime_ns)


def _specs(stage, status, accession, input_side, recording=False):
    record = status["steps"][stage]
    xml, payload = f"{accession}.xml", accession
    def descriptor(method, path, reason, scope="output"):
        return dict(method=method, path=path, scope=scope, reason=reason)
    inventory = descriptor("inventory-md5-v1", xml, "baseline_inventory_changed")
    logical = descriptor("payload-stat-md5-v1", payload, "payload_changed")
    exact_xml = descriptor("file-md5-v1", xml, "xml_changed")
    bag = descriptor("bag-stat-md5-v1", accession, "bag_changed")
    inputs = {
        "antivirus": {}, "ingest": {}, "fits": dict(inventory=inventory, payload=logical),
        "reports": dict(xml=exact_xml, csv_stylesheet=descriptor("file-md5-v1", "files.csv.xslt", "csv_stylesheet_changed", "stylesheets"),
                        html_stylesheet=descriptor("file-md5-v1", "files.html.xslt", "html_stylesheet_changed", "stylesheets"),
                        payload=logical),
        "summary": dict(csv=descriptor("file-md5-v1", f"{accession}_files.csv", "csv_changed"),
                        xml=exact_xml, csv_stylesheet=descriptor("file-md5-v1", "files.csv.xslt", "csv_stylesheet_changed", "stylesheets"), payload=logical),
        "fixity": dict(inventory=inventory, payload=logical),
        "bag_construct": dict(inventory=inventory, payload=logical),
        "bag_validate": dict(bag=bag), "tar_serialize": dict(bag=bag),
    }
    if stage == "bag_validate":
        inputs[stage]["bag"] = dict(bag, reason="bag_changed_since_validation")
    if stage == "tar_serialize":
        inputs[stage]["bag"] = dict(bag, reason="bag_changed_since_serialization")
    if input_side:
        return inputs[stage]
    outputs = record["outputs"]
    evidence = {
        "antivirus": {name: descriptor("file-md5-v1", path, f"{name}_output_changed") for name, path in outputs.items()},
        "ingest": dict(inventory=inventory, payload=logical),
        "fits": dict(fits=descriptor("fits-md5-v1", xml, "fits_enrichment_changed")),
        "reports": {name: descriptor("file-md5-v1", outputs.get(name), f"{name}_output_changed") for name in ("csv", "html")},
        "summary": dict(text=descriptor("file-md5-v1", outputs.get("text"), "summary_output_changed")),
        "fixity": {name: descriptor("file-md5-v1", outputs.get(name), f"fixity_{name}_changed") for name in ("csv", "log")},
        "bag_construct": dict(bag=bag), "bag_validate": {},
        "tar_serialize": dict(tar=descriptor("file-stat-v1", outputs.get("tar"), "tar_changed")),
    }
    return evidence[stage]


def _snapshot(descriptor, output, layout, stylesheets):
    value = descriptor["path"]
    if not isinstance(value, str) or not value or Path(value).is_absolute() or "\\" in value or ":" in value:
        raise ValueError("invalid_evidence_path")
    root = stylesheets if descriptor["scope"] == "stylesheets" else output
    path = root / value
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("invalid_evidence_path")
    _no_link(path)
    method = descriptor["method"]
    functions = {"file-md5-v1": file_md5, "inventory-md5-v1": inventory_md5, "fits-md5-v1": fits_md5,
                 "bag-stat-md5-v1": bag_stat_md5, "file-stat-v1": file_stat}
    digest = payload_stat_md5(path, layout) if method == "payload-stat-md5-v1" else functions[method](path)
    return dict(method=method, value=digest, path=value, scope=descriptor["scope"])


def capture_stage(stage, status, output, accession, input_side, stylesheets=None):
    """Best-effort evidence capture; errors never invalidate technical completion."""
    output = Path(output).resolve()
    stylesheets = Path(stylesheets or Path(__file__).resolve().parents[1]).resolve()
    captured, errors = {}, []
    specs = _specs(stage, status, accession, input_side, recording=True)
    for name, descriptor in specs.items():
        if stage == "bag_construct" and input_side and name == "inventory" and not (output / f"{accession}.xml").exists():
            continue  # Construction without an XML baseline is an established API path.
        try:
            captured[name] = _snapshot(descriptor, output, status["layout"], stylesheets)
        except Exception:
            errors.append(f"evidence_capture_unavailable_{name}")
    if stage == "bag_construct" and input_side:
        captured["settings"] = deepcopy(status["steps"][stage]["settings"])
    return captured, errors


def apply_execution_evidence(stage, candidate, output, accession, captured_inputs, input_errors):
    record = candidate["steps"][stage]
    evidence, errors = capture_stage(stage, candidate, output, accession, input_side=False)
    record["inputs"], record["evidence"] = captured_inputs, evidence
    reasons = sorted(set(input_errors + errors))
    if stage == "antivirus":
        reasons.append("time_sensitive_scan")
    record["freshness"].update(state="unverified" if reasons else "current", checked_at=record["finished_at"],
                               method=METHOD, reasons=reasons)


def reconcile_status(status, output, accession, stylesheets=None):
    """Return a copy with freshness updates only. No historical evidence is created."""
    pipeline_status._validate(status, accession)
    output = Path(output).resolve()
    pipeline_status._status_path(output, accession)
    stylesheets = Path(stylesheets or Path(__file__).resolve().parents[1]).resolve()
    candidate = deepcopy(status)
    cache = {}
    for stage, record in candidate["steps"].items():
        if stage not in pipeline_status.STAGE_IDS or record["state"] != "completed":
            continue
        stale, unknown = [], []
        has_evidence = bool(record["inputs"] or record["evidence"])
        if not has_evidence:
            if record["freshness"]["state"] == "current":
                record["freshness"].update(state="unverified", method=METHOD, reasons=["missing_evidence"])
            continue  # Pre-fingerprint history is not retrospectively verified.
        for side in ("inputs", "evidence"):
            specs = _specs(stage, candidate, accession, side == "inputs")
            if stage == "bag_construct" and "inventory" not in record["inputs"]:
                specs.pop("inventory", None)
            for name, descriptor in specs.items():
                previous = record[side].get(name)
                if not isinstance(previous, dict) or not {"method", "value", "path", "scope"} <= previous.keys():
                    unknown.append("missing_evidence")
                    continue
                if previous.get("method") != descriptor["method"]:
                    unknown.append("unsupported_evidence_method")
                    continue
                try:
                    key = (descriptor["method"], descriptor["scope"], descriptor["path"])
                    if key not in cache:
                        cache[key] = _snapshot(descriptor, output, candidate["layout"], stylesheets)
                    current = cache[key]
                    if previous != current:
                        stale.append(descriptor["reason"])
                except FileNotFoundError:
                    stale.append("missing_output" if side == "evidence" else "missing_input")
                    stale.append(descriptor["reason"])
                except (OSError, ValueError, TypeError, ET.XMLSyntaxError, KeyError) as exc:
                    if str(exc) in ("ambiguous_payload_layout", "invalid_inventory_membership", "invalid_accession_xml", "payload_links_not_supported", "unsupported_payload_entry"):
                        stale.append(str(exc))
                    else:
                        unknown.append("fingerprint_unavailable")
        if stage == "bag_construct" and record["inputs"].get("settings") != record["settings"]:
            stale.append("settings_changed")
        if stage == "antivirus":
            unknown.append("time_sensitive_scan")
        if any(reason.startswith("evidence_capture_unavailable") for reason in record["freshness"]["reasons"]):
            unknown.append("missing_evidence")
        state = "stale" if stale else "unverified" if unknown else "current"
        reasons = sorted(set(stale + unknown))
        fresh = record["freshness"]
        if (fresh["state"], fresh["method"], fresh["reasons"]) != (state, METHOD, reasons):
            fresh.update(state=state, method=METHOD, reasons=reasons)
    _invalidate_dependencies(candidate)
    for stage in pipeline_status.STAGE_IDS:
        before, after = status["steps"][stage]["freshness"], candidate["steps"][stage]["freshness"]
        if any(before[key] != after[key] for key in ("state", "method", "reasons")):
            after["checked_at"] = datetime.now(timezone.utc).isoformat()
    return candidate


def _invalidate_dependencies(status):
    """Propagate known upstream changes only where consumer lineage is insufficient.

    New Reports/Summary capture lineage themselves, so re-generated work that
    matches current inputs is not poisoned by an older upstream stale record.
    """
    dependencies = {
        "ingest": (("fits", "inventory"), ("reports", "xml"), ("summary", "xml"), ("fixity", "inventory"), ("bag_construct", "inventory")),
        "fits": (("reports", "xml"), ("summary", "xml")),
        "reports": (("summary", "csv"),),
        "bag_construct": (("bag_validate", "bag"), ("tar_serialize", "bag")),
    }
    for source, targets in dependencies.items():
        origin = status["steps"][source]
        if origin["freshness"]["state"] != "stale":
            continue
        causes = origin["freshness"]["reasons"]
        if source == "reports" and not any(c in causes for c in ("xml_changed", "csv_output_changed", "csv_stylesheet_changed", "payload_changed", "baseline_inventory_changed", "fits_enrichment_changed")):
            continue  # HTML-only modifications are not Summary dependencies.
        if source == "ingest" and not any(c in causes for c in ("baseline_inventory_changed", "payload_changed", "missing_output", "ambiguous_payload_layout")):
            continue
        for target, lineage in targets:
            record = status["steps"][target]
            if record["state"] != "completed" or (record["freshness"]["state"] == "current" and lineage in record["inputs"]):
                continue
            reason = f"upstream_{source}_changed"
            if reason not in record["freshness"]["reasons"]:
                record["freshness"].update(state="stale", method=METHOD,
                                           reasons=sorted(set(record["freshness"]["reasons"] + [reason])))


def load_reconciled_status(output, accession, stylesheets=None):
    status = pipeline_status.load_status(output, accession)
    candidate = reconcile_status(status, output, accession, stylesheets)
    return pipeline_status.save_status(output, accession, candidate) if candidate != status else status
