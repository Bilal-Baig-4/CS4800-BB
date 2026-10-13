"""Managed execution recording, using real sidecars and mocked operations."""
import csv
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pipeline
from pipeline_state import status as ps
import test_gui_selective as selective_fixture


class StatusIntegrationTests(unittest.TestCase):
    # Reuse the GUI fixture without inheriting/repeating its selective tests.
    setUpClass = classmethod(selective_fixture.SelectiveExecutionTests.setUpClass.__func__)
    setUp = selective_fixture.SelectiveExecutionTests.setUp
    write_inventory = selective_fixture.SelectiveExecutionTests.write_inventory
    fake_ingest = selective_fixture.SelectiveExecutionTests.fake_ingest
    select = selective_fixture.SelectiveExecutionTests.select
    execute = selective_fixture.SelectiveExecutionTests.execute
    assertOperations = selective_fixture.SelectiveExecutionTests.assertOperations
    existing_bag = selective_fixture.SelectiveExecutionTests.existing_bag

    def status(self):
        return ps.load_status(self.output, "A")

    def step(self, stage):
        return self.status()["steps"][stage]

    def scan(self, outcome="clean", skipped=False, detections=None):
        def operation(*args, result_callback=None, **kwargs):
            path = self.output / "antivirus_A.csv"
            path.write_text("fixture")
            result_callback(dict(state="failed" if skipped else "completed", outcome=outcome,
                                 scanned_count=1, detection_count=len(detections or {}),
                                 error_count=1 if skipped else 0, outputs={"csv": path}))
            return set(), detections or {}, skipped
        self.calls.run_antivirus_scan.side_effect = operation

    def test_new_managed_run_fits_running_before_operation(self):
        observed = []
        self.calls.enrich_accession_with_fits.side_effect = lambda *a, **k: observed.append(self.step("fits"))
        self.execute(2)
        self.assertEqual(observed[0]["state"], "running")
        self.assertEqual(observed[0]["attempt"], 1)
        self.assertIsNone(observed[0]["finished_at"])
        self.assertEqual(self.step("fits")["state"], "completed")
        self.assertEqual(self.step("fits")["outcome"], "processed")
        self.assertEqual(self.step("fits")["outputs"], {"xml": "A.xml"})
        self.assertNotIn("identified_count", self.step("fits")["result"])

    def test_ingest_without_av_outputs_settings_and_attempt(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["av_var"].set(False)
        self.g["move_var"].set(True)
        self.execute(1)
        step = self.step("ingest")
        self.assertEqual((step["state"], step["outcome"], step["attempt"]), ("completed", "generated", 1))
        self.assertEqual(step["outputs"], {"payload": "A", "xml": "A.xml"})
        self.assertEqual(step["settings"], {"move_files": True})
        self.assertEqual(step["result"], {"file_count": 1})
        self.assertEqual(self.step("antivirus")["state"], "not_started")
        self.assertTrue(step["started_at"].endswith("+00:00"))
        self.assertTrue(step["finished_at"].endswith("+00:00"))

    def test_antivirus_clean(self):
        self.g["input_dir_var"].set(str(self.source))
        self.scan()
        self.execute(1)
        self.assertEqual((self.step("antivirus")["state"], self.step("antivirus")["outcome"]), ("completed", "clean"))
        self.assertEqual(self.step("antivirus")["result"]["scanned_count"], 1)
        self.assertEqual(self.step("antivirus")["outputs"], {"csv": "antivirus_A.csv"})

    def test_antivirus_detections_completed_before_cancel(self):
        self.g["input_dir_var"].set(str(self.source))
        self.scan("detections", detections={self.source / "bad": "finding"})
        self.messages.askyesno.return_value = False
        self.execute(1)
        self.assertEqual((self.step("antivirus")["state"], self.step("antivirus")["outcome"]), ("completed", "detections"))
        self.assertEqual(self.step("ingest")["attempt"], 0)

    def test_unavailable_requested_antivirus_failed_ingest_continues(self):
        self.g["input_dir_var"].set(str(self.source))
        with patch.object(pipeline, "AV_AVAILABLE", False):
            self.execute(1)
        self.assertEqual((self.step("antivirus")["state"], self.step("antivirus")["outcome"]), ("failed", "unavailable"))
        self.assertEqual(self.step("ingest")["state"], "completed")
        self.assertOperations("ingest_accession")

    def test_reports_summary_outputs_independent(self):
        self.calls.run_xslt_processor.side_effect = lambda xml, stylesheet, output: Path(output).write_text("report")
        self.calls.generate_summary_report.side_effect = lambda *a: (self.output / "A.txt").write_text("summary")
        self.execute(3)
        self.assertEqual(self.step("reports")["outputs"], {"csv": "A_files.csv", "html": "A_files.html"})
        self.assertEqual(self.step("reports")["result"], {"csv_generated": True, "html_generated": True})
        self.assertEqual(self.step("summary")["state"], "completed")
        self.assertEqual(self.step("summary")["outputs"], {"text": "A.txt"})

    def test_html_failure_reports_partial_summary_untouched(self):
        def transform(xml, stylesheet, output):
            if stylesheet.name == "files.html.xslt":
                raise OSError("HTML transform failed")
            Path(output).write_text("csv")
        self.calls.run_xslt_processor.side_effect = transform
        self.execute(3, 4)
        step = self.step("reports")
        self.assertEqual((step["state"], step["outcome"]), ("failed", "partial"))
        self.assertEqual(step["result"], {"csv_generated": True, "html_generated": False})
        self.assertEqual(step["outputs"], {"csv": "A_files.csv"})
        self.assertIn("HTML", step["message"])
        self.assertEqual(self.step("summary")["attempt"], 0)
        self.assertEqual(self.step("fixity")["attempt"], 0)

    def fixity(self, statuses):
        def operation(*args):
            path = self.output / "fixity_A.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["status"])
                writer.writeheader()
                writer.writerows({"status": s} for s in statuses)
            log = self.output / "fixity_A.log"
            log.write_text("fixture")
            return path, log
        self.calls.run_fixity.side_effect = operation

    def test_fixity_passed_counts(self):
        self.fixity(["OK", "OK"])
        self.execute(4)
        self.assertEqual((self.step("fixity")["state"], self.step("fixity")["outcome"]), ("completed", "passed"))
        self.assertEqual(self.step("fixity")["result"], dict(ok_count=2, mismatch_count=0, missing_count=0, error_count=0))

    def test_fixity_findings_completed(self):
        self.fixity(["OK", "MISMATCH", "MISSING", "ERROR"])
        self.execute(4)
        self.assertEqual((self.step("fixity")["state"], self.step("fixity")["outcome"]), ("completed", "findings"))
        self.assertEqual(self.step("fixity")["result"], dict(ok_count=1, mismatch_count=1, missing_count=1, error_count=1))

    def test_fixity_empty_and_unknown_counts_not_zero(self):
        self.fixity([])
        self.execute(4)
        self.assertEqual(self.step("fixity")["outcome"], "empty")
        self.calls.run_fixity.side_effect = None
        self.calls.run_fixity.return_value = (self.output / "absent.csv", None)
        self.g["rerun_completed_var"].set(True)
        self.execute(4)
        self.assertEqual(self.step("fixity")["outcome"], "processed")
        self.assertTrue(all(v is None for v in self.step("fixity")["result"].values()))

    def test_bag_construct_validate_tar_and_layout(self):
        self.g["validate_bag_var"].set(True)
        self.calls.serialize_bag_to_tar.side_effect = lambda *a: self.make_tar()
        self.execute(5)
        for stage, outcome in (("bag_construct", "constructed"), ("bag_validate", "valid"), ("tar_serialize", "serialized")):
            self.assertEqual((self.step(stage)["state"], self.step(stage)["outcome"]), ("completed", outcome))
        self.assertEqual(self.step("bag_validate")["result"], {"valid": True})
        self.assertEqual(self.step("tar_serialize")["outputs"], {"tar": "A.tar"})
        self.assertEqual(self.status()["layout"], "bagged")

    def make_tar(self):
        path = self.output / "A.tar"
        path.write_bytes(b"fixture")
        return path

    def test_invalid_validation_completed_tar_untouched(self):
        self.g["validate_bag_var"].set(True)
        self.calls.validate_bag.return_value = (False, "mismatch")
        self.execute(5)
        self.assertEqual((self.step("bag_validate")["state"], self.step("bag_validate")["outcome"]), ("completed", "invalid"))
        self.assertEqual(self.step("bag_validate")["result"], {"valid": False})
        self.assertEqual(self.step("tar_serialize")["attempt"], 0)

    def test_validation_dependency_error_indeterminate(self):
        self.g["validate_bag_var"].set(True)
        def validate(path, result_callback):
            result_callback(dict(state="failed", outcome="indeterminate", valid=None, message="unreadable"))
            return False, "unreadable"
        self.calls.validate_bag.side_effect = validate
        self.execute(5)
        self.assertEqual((self.step("bag_validate")["state"], self.step("bag_validate")["outcome"]), ("failed", "indeterminate"))
        self.assertIsNone(self.step("bag_validate")["result"]["valid"])

    def test_failed_ingest_records_diagnostic_stops_later(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["av_var"].set(False)
        self.calls.ingest_accession.side_effect = OSError("copy failed")
        self.execute(1, 2, 3)
        step = self.step("ingest")
        self.assertEqual(step["state"], "failed")
        self.assertEqual(step["message"], "copy failed")
        self.assertIsNotNone(step["finished_at"])
        self.assertEqual(self.step("fits")["attempt"], 0)

    def test_manual_rerun_increments_attempt_and_revisions(self):
        self.execute(2)
        first = self.status()
        self.g["rerun_completed_var"].set(True)
        self.execute(2)
        self.assertEqual(self.step("fits")["attempt"], 2)
        self.assertEqual(self.status()["revision"], first["revision"] + 2)

    def test_prior_history_unknown_fields_and_unselected_stages_preserved(self):
        status = ps.create_status(self.output, "A")
        status["extension"] = {"future": True}
        status["steps"]["ingest"].update(state="completed", outcome="generated", attempt=8)
        status["steps"]["ingest"]["freshness"]["state"] = "stale"
        status["steps"]["reports"]["extension"] = "preserved"
        status = ps.save_status(self.output, "A", status)
        self.execute(2)
        after = self.status()
        for stage in ps.STAGE_IDS:
            if stage != "fits":
                self.assertEqual(after["steps"][stage], status["steps"][stage])
        self.assertEqual(after["extension"], status["extension"])
        self.assertEqual(self.step("fits")["freshness"]["state"], "current")

    def test_malformed_and_newer_status_block_processing(self):
        path = self.output / "A_status.json"
        for text in ("{broken", '{"schema_version": 2}'):
            self.messages.reset_mock()
            path.write_text(text)
            self.execute(2)
            self.assertOperations()
            self.messages.showerror.assert_called_once()
            self.assertEqual(path.read_text(), text)

    def test_running_save_failure_operation_not_started(self):
        ps.create_status(self.output, "A")
        with patch.object(ps, "save_status", side_effect=OSError("disk full")):
            self.execute(2)
        self.assertOperations()
        self.assertEqual(self.step("fits")["attempt"], 0)
        self.assertIn("not started", self.messages.showerror.call_args.args[1])

    def test_completion_save_failure_leaves_running_and_artifacts(self):
        ps.create_status(self.output, "A")
        original_save = ps.save_status
        def save(output, accession, status):
            if status["steps"]["fits"]["state"] == "completed":
                raise OSError("final write failed")
            return original_save(output, accession, status)
        with patch.object(ps, "save_status", side_effect=save):
            self.execute(2, 3)
        self.assertOperations("enrich_accession_with_fits")
        self.assertEqual(self.step("fits")["state"], "running")
        self.assertTrue(self.xml.exists())
        self.messages.showinfo.assert_not_called()
        self.assertIn("final status", self.messages.showerror.call_args.args[1])

    def test_failure_save_error_preserves_original_processing_diagnostic(self):
        ps.create_status(self.output, "A")
        self.calls.enrich_accession_with_fits.side_effect = OSError("FITS original error")
        original_save = ps.save_status
        def save(output, accession, status):
            if status["steps"]["fits"]["state"] == "failed":
                raise OSError("save error")
            return original_save(output, accession, status)
        with patch.object(ps, "save_status", side_effect=save):
            self.execute(2)
        self.assertEqual(self.step("fits")["state"], "running")
        message = self.messages.showerror.call_args.args[1]
        self.assertIn("FITS original error", message)
        self.assertIn("save error", message)

    def test_unchecked_bag_substages_preserve_prior_records(self):
        status = ps.create_status(self.output, "A")
        status["steps"]["bag_validate"].update(state="completed", outcome="valid", attempt=4)
        status["steps"]["tar_serialize"].update(state="completed", outcome="serialized", attempt=5)
        status = ps.save_status(self.output, "A", status)
        self.g["serialize_tar_var"].set(False)
        self.execute(5)
        for stage in ("bag_validate", "tar_serialize"):
            self.assertEqual(self.step(stage), status["steps"][stage])

    def test_rejected_construct_failed_outcome(self):
        self.calls.construct_bag.side_effect = ValueError("baseline mismatch")
        self.execute(5)
        self.assertEqual((self.step("bag_construct")["state"], self.step("bag_construct")["outcome"]), ("failed", "rejected"))


class StructuredOperationResultsTests(unittest.TestCase):
    @unittest.skipUnless(pipeline.BAGIT_AVAILABLE, "bagit is not installed")
    def test_validation_result_callback_distinguishes_invalid_from_execution_error(self):
        for error, state, outcome in ((None, "completed", "valid"),
                                      (pipeline.bagit.BagValidationError("invalid"), "completed", "invalid"),
                                      (OSError("cannot open bag"), "failed", "indeterminate")):
            with self.subTest(outcome=outcome), patch.object(pipeline, "BAGIT_AVAILABLE", True), \
                 patch.object(pipeline.bagit, "Bag") as bag:
                bag.return_value.validate.side_effect = error
                results = []
                pipeline.validate_bag("fixture", result_callback=results.append)
                self.assertEqual((results[0]["state"], results[0]["outcome"]), (state, outcome))

    def test_antivirus_callback_clean_empty_and_partial_counts_without_live_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            result = SimpleNamespace(returncode=0, stdout="Found no threats", stderr="")
            with patch.object(pipeline, "AV_AVAILABLE", True), patch.object(pipeline, "DEFENDER_PATH", root / "defender"), \
                 patch.object(pipeline.subprocess, "run", return_value=result):
                observations = []
                pipeline.run_antivirus_scan(source, root / "out", "A", result_callback=observations.append)
                self.assertEqual(observations[-1]["outcome"], "empty")
                (source / "file.bin").write_bytes(b"fixture")
                pipeline.run_antivirus_scan(source, root / "out", "A", result_callback=observations.append)
                self.assertEqual(observations[-1]["outcome"], "clean")
                self.assertEqual(observations[-1]["scanned_count"], 1)
                self.assertEqual(observations[-1]["error_count"], 0)
                (source / "placeholder.gdoc").write_text("fixture")
                pipeline.run_antivirus_scan(source, root / "out", "A", result_callback=observations.append)
                self.assertEqual(observations[-1]["outcome"], "partial")
                self.assertEqual(observations[-1]["skipped_count"], 1)

    def test_antivirus_callback_omits_prior_reports_when_current_write_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            prior = root / "antivirus_A.csv"
            prior.write_text("previous attempt")
            with patch.object(pipeline, "AV_AVAILABLE", True), patch.object(pipeline, "DEFENDER_PATH", root / "defender"), \
                 patch("builtins.open", side_effect=OSError("write denied")):
                observations = []
                pipeline.run_antivirus_scan(source, root, "A", result_callback=observations.append)
            self.assertNotIn("csv", observations[0]["outputs"])
            self.assertEqual(prior.read_text(), "previous attempt")


if __name__ == "__main__":
    unittest.main()
