"""Fingerprint evidence and reconciliation without live Defender/FITS or payload hashing."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from pipeline_state import status as ps
from pipeline_state.recording import RunRecorder
from pipeline_state import freshness as fresh
from pipeline_state.resume import build_resume_plan, format_execution_plan
from pipeline_state.view import summarize_user_steps, format_stage_details
import test_gui_selective as fixture


class FreshnessTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.payload = self.root / "A"
        self.payload.mkdir()
        (self.payload / "file.txt").write_text("original")
        self.xml = self.root / "A.xml"
        self.xml.write_text('''<collection xmlns="http://dataaccessioner.org/schema/dda-1-1" xmlns:p="info:lc/xmlns/premis-v2">
          <accession number="A"><file name="file.txt" size="8" MD5="919c8b643b7133116b02fc0d9bb7df3f">
          <p:object><p:objectIdentifier><p:objectIdentifierType>uuid</p:objectIdentifierType><p:objectIdentifierValue>stable-uuid</p:objectIdentifierValue></p:objectIdentifier>
          <p:objectCharacteristics><p:fixity><p:messageDigestAlgorithm>MD5</p:messageDigestAlgorithm><p:messageDigest>919c8b643b7133116b02fc0d9bb7df3f</p:messageDigest></p:fixity><p:size>8</p:size></p:objectCharacteristics></p:object>
          </file></accession></collection>''', encoding="utf-8")

    def status(self):
        return ps.load_status(self.root, "A")

    def record(self, stage, operation=None):
        recorder = RunRecorder(self.root, "A")
        outputs = {
            "ingest": dict(payload=self.payload, xml=self.xml), "fits": dict(xml=self.xml),
            "reports": dict(csv=self.root / "A_files.csv", html=self.root / "A_files.html"),
            "summary": dict(text=self.root / "A.txt"),
            "fixity": dict(csv=self.root / "fixity_A.csv", log=self.root / "fixity_A.log"),
            "bag_construct": dict(bag=self.payload), "bag_validate": {}, "tar_serialize": dict(tar=self.root / "A.tar"),
            "antivirus": dict(csv=self.root / "antivirus_A.csv", log=self.root / "antivirus_A.log"),
        }[stage]
        outcomes = dict(ingest="generated", fits="processed", reports="generated", summary="generated", fixity="passed",
                        bag_construct="constructed", bag_validate="valid", tar_serialize="serialized", antivirus="clean")
        def execute():
            if operation:
                operation()
            for name, path in outputs.items():
                if name not in ("xml", "payload", "bag") and not path.exists():
                    path.write_text(f"{stage}-{name}")
        recorder.run(stage, execute, lambda _: dict(outcome=outcomes[stage], outputs=recorder.paths(**outputs)),
                     settings={"profile": "aptrust"} if stage == "bag_construct" else {},
                     layout="unbagged" if stage == "ingest" else "bagged" if stage == "bag_construct" else None)
        return recorder.status

    def fits_change(self, text="PDF"):
        xml = self.xml.read_text()
        extension = f'''<p:format><p:formatDesignation><p:formatName>{text}</p:formatName></p:formatDesignation><p:formatNote>FITS DROID</p:formatNote></p:format>
          <p:objectCharacteristicsExtension><f:fits xmlns:f="http://hul.harvard.edu/ois/xml/ns/fits/fits_output"><f:identification><f:identity format="{text}" mimetype="application/pdf"><f:tool toolname="DROID"/></f:identity></f:identification></f:fits></p:objectCharacteristicsExtension>'''
        self.xml.write_text(xml.replace("</p:objectCharacteristics>", extension + "</p:objectCharacteristics>"))

    def bag(self):
        data = self.payload / "data"
        data.mkdir()
        for path in list(self.payload.iterdir()):
            if path != data:
                shutil.move(str(path), data / path.name)
        for name in ("bagit.txt", "bag-info.txt", "manifest-md5.txt", "tagmanifest-md5.txt", "aptrust-info.txt"):
            (self.payload / name).write_text(f"fixture-{name}")

    def reconciled(self):
        return fresh.reconcile_status(self.status(), self.root, "A")

    def assertFresh(self, stage, expected, reason=None):
        record = self.reconciled()["steps"][stage]
        self.assertEqual(record["freshness"]["state"], expected)
        self.assertEqual(record["state"], "completed")
        if reason:
            self.assertIn(reason, record["freshness"]["reasons"])

    def test_ingest_records_inventory_payload(self):
        status = self.record("ingest")
        evidence = status["steps"]["ingest"]["evidence"]
        self.assertEqual(evidence["inventory"]["method"], "inventory-md5-v1")
        self.assertEqual(evidence["payload"]["method"], "payload-stat-md5-v1")
        self.assertFresh("ingest", "current")

    def test_fits_records_input_inventory_payload_and_enrichment(self):
        status = self.record("fits", self.fits_change)
        record = status["steps"]["fits"]
        self.assertEqual(set(record["inputs"]), {"inventory", "payload"})
        self.assertEqual(record["evidence"]["fits"]["method"], "fits-md5-v1")
        self.assertFresh("fits", "current")

    def test_reports_record_xml_stylesheets_and_outputs(self):
        status = self.record("reports")
        record = status["steps"]["reports"]
        self.assertTrue({"xml", "csv_stylesheet", "html_stylesheet"} <= record["inputs"].keys())
        self.assertEqual(set(record["evidence"]), {"csv", "html"})
        self.assertFresh("reports", "current")

    def test_summary_records_csv_text(self):
        self.record("reports")
        record = self.record("summary")["steps"]["summary"]
        self.assertEqual(record["inputs"]["csv"]["method"], "file-md5-v1")
        self.assertEqual(record["evidence"]["text"]["method"], "file-md5-v1")

    def test_fixity_records_inventory_payload_reports(self):
        record = self.record("fixity")["steps"]["fixity"]
        self.assertEqual(set(record["inputs"]), {"inventory", "payload"})
        self.assertEqual(set(record["evidence"]), {"csv", "log"})

    def test_construction_records_bag_and_settings(self):
        record = self.record("bag_construct", self.bag)["steps"]["bag_construct"]
        self.assertEqual(record["evidence"]["bag"]["method"], "bag-stat-md5-v1")
        self.assertEqual(record["inputs"]["settings"], {"profile": "aptrust"})
        self.assertFresh("bag_construct", "current")

    def test_validation_records_bag_input(self):
        self.record("bag_construct", self.bag)
        record = self.record("bag_validate")["steps"]["bag_validate"]
        self.assertEqual(record["inputs"]["bag"]["method"], "bag-stat-md5-v1")

    def test_tar_records_bag_and_stat_never_tar_hash(self):
        self.record("bag_construct", self.bag)
        original = fresh.file_md5
        def hash_small(path):
            self.assertNotEqual(Path(path).suffix, ".tar")
            return original(path)
        with patch.object(fresh, "file_md5", side_effect=hash_small):
            record = self.record("tar_serialize")["steps"]["tar_serialize"]
            self.reconciled()
        self.assertEqual(record["evidence"]["tar"]["method"], "file-stat-v1")

    def test_baseline_change_stales_ingest(self):
        self.record("ingest")
        self.xml.write_text(self.xml.read_text().replace("stable-uuid", "changed-uuid"))
        self.assertFresh("ingest", "stale", "baseline_inventory_changed")

    def test_fits_enrichment_does_not_stale_ingest_or_fixity(self):
        self.record("ingest")
        self.record("fixity")
        self.fits_change()
        self.assertFresh("ingest", "current")
        self.assertFresh("fixity", "current")

    def test_fits_change_stales_fits_reports_summary(self):
        self.record("fits")
        self.record("reports")
        self.record("summary")
        self.fits_change()
        self.assertFresh("fits", "stale", "fits_enrichment_changed")
        self.assertFresh("reports", "stale", "xml_changed")
        self.assertFresh("summary", "stale", "xml_changed")

    def test_exact_xml_whitespace_change_stales_reports_not_inventory(self):
        self.record("ingest")
        self.record("reports")
        self.xml.write_text(self.xml.read_text() + "\n")
        self.assertFresh("reports", "stale", "xml_changed")
        self.assertFresh("ingest", "current")

    def test_csv_change_stales_reports_and_summary(self):
        self.record("reports")
        self.record("summary")
        (self.root / "A_files.csv").write_text("changed")
        self.assertFresh("reports", "stale", "csv_output_changed")
        self.assertFresh("summary", "stale", "csv_changed")

    def test_html_only_change_does_not_stale_summary(self):
        self.record("reports")
        self.record("summary")
        (self.root / "A_files.html").write_text("changed")
        self.assertFresh("reports", "stale", "html_output_changed")
        self.assertFresh("summary", "current")

    def test_summary_output_deleted(self):
        self.record("reports")
        self.record("summary")
        (self.root / "A.txt").unlink()
        self.assertFresh("summary", "stale", "missing_output")

    def test_payload_membership_size_and_mtime_detected(self):
        self.record("ingest")
        self.record("fits")
        self.record("fixity")
        (self.payload / "extra.txt").write_text("extra")
        for stage in ("ingest", "fits", "fixity"):
            self.assertFresh(stage, "stale", "payload_changed")

    def test_payload_mtime_only_change_detected(self):
        self.record("fixity")
        path = self.payload / "file.txt"
        stat = path.stat()
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1000000))
        self.assertFresh("fixity", "stale", "payload_changed")

    def test_packaged_payload_change_stales_construction_validation_tar(self):
        self.record("bag_construct", self.bag)
        self.record("bag_validate")
        self.record("tar_serialize")
        (self.payload / "data/file.txt").write_text("different size")
        for stage in ("bag_construct", "bag_validate", "tar_serialize"):
            self.assertFresh(stage, "stale")

    def test_manifest_change_stales_validation_and_tar(self):
        self.record("bag_construct", self.bag)
        self.record("bag_validate")
        self.record("tar_serialize")
        (self.payload / "manifest-md5.txt").write_text("changed")
        self.assertFresh("bag_validate", "stale", "bag_changed_since_validation")
        self.assertFresh("tar_serialize", "stale", "bag_changed_since_serialization")

    def test_fits_change_does_not_stale_bag_baseline_continuity(self):
        self.record("bag_construct", self.bag)
        self.fits_change()
        self.assertFresh("bag_construct", "current")

    def test_tar_replacement_stales_tar_only(self):
        self.record("bag_construct", self.bag)
        self.record("bag_validate")
        self.record("tar_serialize")
        (self.root / "A.tar").write_text("replacement archive")
        self.assertFresh("tar_serialize", "stale", "tar_changed")
        self.assertFresh("bag_construct", "current")
        self.assertFresh("bag_validate", "current")

    def test_missing_report_output_stale(self):
        self.record("reports")
        (self.root / "A_files.csv").unlink()
        self.assertFresh("reports", "stale", "missing_output")

    def test_older_missing_evidence_not_retrospectively_fingerprinted(self):
        status = ps.create_status(self.root, "A")
        status["steps"]["ingest"].update(state="completed", outcome="generated", outputs={"payload": "A", "xml": "A.xml"})
        status = ps.save_status(self.root, "A", status)
        self.assertEqual(fresh.reconcile_status(status, self.root, "A"), status)
        self.assertEqual(fresh.load_reconciled_status(self.root, "A"), status)

    def test_reconciliation_preserves_execution_fields_and_evidence(self):
        self.record("ingest")
        before = self.status()
        (self.payload / "file.txt").write_text("changed")
        after = self.reconciled()
        for stage in ps.STAGE_IDS:
            for key in ("state", "outcome", "attempt", "started_at", "finished_at", "inputs", "evidence"):
                self.assertEqual(before["steps"][stage][key], after["steps"][stage][key])

    def test_noop_current_and_stale_reconciliation_does_not_save_again(self):
        self.record("ingest")
        first = fresh.load_reconciled_status(self.root, "A")
        self.assertEqual(first["revision"], self.status()["revision"])
        self.assertEqual(first, fresh.load_reconciled_status(self.root, "A"))
        (self.payload / "file.txt").write_text("changed")
        stale = fresh.load_reconciled_status(self.root, "A")
        self.assertEqual(stale, fresh.load_reconciled_status(self.root, "A"))

    def test_normal_bag_relocation_preserves_ingest_fits(self):
        self.record("ingest")
        self.record("fits", self.fits_change)
        before = self.status()
        self.record("bag_construct", self.bag)
        after = self.reconciled()
        for stage in ("ingest", "fits"):
            self.assertEqual(after["steps"][stage]["freshness"]["state"], "current")
            self.assertEqual(after["steps"][stage]["evidence"], before["steps"][stage]["evidence"])

    def test_stale_safe_stages_run_and_protected_stages_review(self):
        self.record("ingest")
        self.record("fits")
        self.record("reports")
        self.record("summary")
        self.record("fixity")
        status = self.status()
        for stage in ("ingest", "fits", "reports", "summary", "fixity"):
            status["steps"][stage]["freshness"].update(state="stale", reasons=["payload_changed"])
            selected = {"ingest": stage == "ingest", "fits": stage == "fits", "reports": stage in ("reports", "summary"), "fixity": stage == "fixity"}
            plan = {item["stage"]: item for item in build_resume_plan(status, selected, {}, self.root, "A")}
            self.assertEqual(plan[stage]["action"], "review" if stage == "ingest" else "run")
            status["steps"][stage]["freshness"]["state"] = "current"

    def test_stale_bag_construction_review_validation_tar_not_reused(self):
        self.record("bag_construct", self.bag)
        self.record("bag_validate")
        self.record("tar_serialize")
        status = self.status()
        status["steps"]["bag_construct"]["freshness"]["state"] = "stale"
        plan = {item["stage"]: item for item in build_resume_plan(status, {"bagging": True}, dict(profile="aptrust", validate=True, tar=True), self.root, "A")}
        self.assertEqual(plan["bag_construct"]["action"], "review")
        self.assertNotEqual(plan["bag_validate"]["action"], "reuse")
        self.assertNotEqual(plan["tar_serialize"]["action"], "reuse")

    def test_stale_validation_and_tar_run_with_current_construction(self):
        self.record("bag_construct", self.bag)
        self.record("bag_validate")
        self.record("tar_serialize")
        status = self.status()
        for stage in ("bag_validate", "tar_serialize"):
            status["steps"][stage]["freshness"].update(state="stale", reasons=["bag_changed"])
        plan = {item["stage"]: item for item in build_resume_plan(status, {"bagging": True}, dict(profile="aptrust", validate=True, tar=True), self.root, "A")}
        self.assertEqual(plan["bag_validate"]["action"], "run")
        self.assertEqual(plan["tar_serialize"]["action"], "run")

    def test_view_and_preview_show_stale_reasons(self):
        self.record("reports")
        self.xml.write_text(self.xml.read_text() + "\n")
        status = self.reconciled()
        self.assertIn("Stale", summarize_user_steps(status)["reports"]["label"])
        self.assertIn("xml_changed", format_stage_details(status))
        plan = build_resume_plan(status, {"reports": True}, {}, self.root, "A")
        self.assertIn("xml changed", format_execution_plan(plan))

    def test_fresh_rerun_not_poisoned_by_older_stale_history(self):
        self.record("fits")
        self.record("reports")
        self.record("summary")
        self.fits_change()
        self.record("reports", lambda: (self.root / "A_files.csv").write_text("new CSV"))
        self.record("summary", lambda: (self.root / "A.txt").write_text("new Summary"))
        self.assertFresh("fits", "stale")
        self.assertFresh("reports", "current")
        self.assertFresh("summary", "current")

    def test_optional_capture_failure_does_not_fail_processing(self):
        with patch.object(fresh, "inventory_md5", side_effect=OSError("unreadable")):
            status = self.record("ingest")
        self.assertEqual(status["steps"]["ingest"]["state"], "completed")
        self.assertEqual(status["steps"]["ingest"]["freshness"]["state"], "unverified")

    def test_antivirus_remains_time_sensitive(self):
        self.record("antivirus")
        self.assertFresh("antivirus", "unverified", "time_sensitive_scan")
        (self.root / "antivirus_A.csv").write_text("changed")
        self.assertFresh("antivirus", "stale")

    def test_payload_inspection_never_hashes_payload_bytes(self):
        original = fresh.file_md5
        def hash_metadata(path):
            self.assertFalse(Path(path).is_relative_to(self.payload))
            return original(path)
        with patch.object(fresh, "file_md5", side_effect=hash_metadata):
            self.record("ingest")
            self.record("fixity")
            self.reconciled()

    def test_file_hash_exact_bytes_canonical_baseline_order(self):
        self.assertEqual(fresh.file_md5(self.xml), hashlib.md5(self.xml.read_bytes()).hexdigest())
        before = fresh.inventory_md5(self.xml)
        self.xml.write_text(self.xml.read_text().replace("  ", "    "))
        self.assertEqual(before, fresh.inventory_md5(self.xml))

    def test_stylesheet_changes_are_detected_without_changing_vendor_files(self):
        stylesheets = self.root / "styles"
        stylesheets.mkdir()
        for name in ("files.csv.xslt", "files.html.xslt"):
            (stylesheets / name).write_text("original")
        self.record("reports")
        self.record("summary")
        status = self.status()
        for stage in ("reports", "summary"):
            for key in ("csv_stylesheet", "html_stylesheet"):
                if key in status["steps"][stage]["inputs"]:
                    status["steps"][stage]["inputs"][key]["value"] = fresh.file_md5(stylesheets / status["steps"][stage]["inputs"][key]["path"])
        (stylesheets / "files.html.xslt").write_text("changed")
        result = fresh.reconcile_status(status, self.root, "A", stylesheets)
        self.assertIn("html_stylesheet_changed", result["steps"]["reports"]["freshness"]["reasons"])
        self.assertEqual(result["steps"]["summary"]["freshness"]["state"], "current")
        (stylesheets / "files.csv.xslt").write_text("changed")
        result = fresh.reconcile_status(status, self.root, "A", stylesheets)
        for stage in ("reports", "summary"):
            self.assertIn("csv_stylesheet_changed", result["steps"][stage]["freshness"]["reasons"])

    def test_atime_and_directory_mtime_do_not_stale_payload(self):
        self.record("ingest")
        path = self.payload / "file.txt"
        stat = path.stat()
        os.utime(path, ns=(stat.st_atime_ns + 1000000000, stat.st_mtime_ns))
        directory = self.payload.stat()
        os.utime(self.payload, ns=(directory.st_atime_ns, directory.st_mtime_ns + 1000000000))
        self.assertFresh("ingest", "current")

    def test_bag_metadata_same_stat_content_change_still_detected(self):
        self.record("bag_construct", self.bag)
        self.record("bag_validate")
        path = self.payload / "bag-info.txt"
        before = path.stat()
        original = path.read_bytes()
        path.write_bytes(b"X" + original[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertFresh("bag_validate", "stale", "bag_changed_since_validation")

    def test_unsupported_evidence_method_remains_unverified(self):
        self.record("ingest")
        status = self.status()
        status["steps"]["ingest"]["evidence"]["inventory"]["method"] = "inventory-md5-v999"
        result = fresh.reconcile_status(status, self.root, "A")
        self.assertEqual(result["steps"]["ingest"]["freshness"]["state"], "unverified")
        self.assertIn("unsupported_evidence_method", result["steps"]["ingest"]["freshness"]["reasons"])

    def test_current_without_evidence_cannot_claim_verification(self):
        status = ps.create_status(self.root, "A")
        status["steps"]["ingest"].update(state="completed", outcome="generated")
        status["steps"]["ingest"]["freshness"]["state"] = "current"
        result = fresh.reconcile_status(status, self.root, "A")
        self.assertEqual(result["steps"]["ingest"]["freshness"]["state"], "unverified")

    def test_unsafe_payload_resolution_does_not_follow_links(self):
        self.record("ingest")
        original = fresh._no_link
        def guard(path):
            if Path(path).name == "file.txt":
                raise ValueError("payload_links_not_supported")
            return original(path)
        with patch.object(fresh, "_no_link", side_effect=guard):
            self.assertFresh("ingest", "stale", "payload_links_not_supported")

    def test_changed_then_regenerated_stage_can_return_to_current(self):
        self.record("reports")
        (self.root / "A_files.csv").write_text("changed")
        stale = fresh.load_reconciled_status(self.root, "A")
        self.assertEqual(stale["steps"]["reports"]["freshness"]["state"], "stale")
        self.record("reports", lambda: (self.root / "A_files.csv").write_text("regenerated"))
        self.assertFresh("reports", "current")


class FreshnessGuiTests(unittest.TestCase):
    setUpClass = classmethod(fixture.SelectiveExecutionTests.setUpClass.__func__)
    setUp = fixture.SelectiveExecutionTests.setUp
    write_inventory = fixture.SelectiveExecutionTests.write_inventory
    fake_ingest = fixture.SelectiveExecutionTests.fake_ingest
    select = fixture.SelectiveExecutionTests.select
    execute = fixture.SelectiveExecutionTests.execute

    def test_reconcile_before_planning_prevents_changed_xml_reuse(self):
        self.calls.run_xslt_processor.side_effect = lambda xml, stylesheet, output: Path(output).write_text("report")
        self.calls.generate_summary_report.side_effect = lambda *a: (self.output / "A.txt").write_text("summary")
        self.execute(3)
        self.xml.write_text(self.xml.read_text() + "\n")
        self.select(3)
        options = self.g["selected_run_options"]()
        plan = {entry["stage"]: entry for entry in self.g["prepare_execution_plan"](options)}
        self.assertEqual(plan["reports"]["action"], "run")
        self.assertEqual(plan["summary"]["action"], "run")
        self.g["load_accession_status"]()
        self.assertIn("Stale", self.g["step_history_vars"]["reports"].get())

    def test_reused_current_stage_status_unchanged(self):
        self.execute(2)
        before = (self.output / "A_status.json").read_bytes()
        self.calls.reset_mock()
        self.execute(2)
        self.assertFalse(self.calls.mock_calls)
        self.assertEqual(before, (self.output / "A_status.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
