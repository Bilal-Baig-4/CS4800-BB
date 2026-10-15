"""Nine-stage read-only planning and execution-boundary resume tests."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pipeline_state as ps
from pipeline_state import build_resume_plan, format_execution_plan
import test_gui_selective as fixture


class ResumePlannerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name)
        self.payload = self.output / "A"
        self.payload.mkdir()
        (self.output / "A.xml").write_text("fixture")
        self.status = ps.create_status(self.output, "A")
        self.options = dict(antivirus=False, validate=True, tar=True, profile="aptrust", rerun_completed=False)

    def bag(self):
        (self.payload / "data").mkdir(exist_ok=True)
        for name in ("bagit.txt", "bag-info.txt", "manifest-md5.txt", "aptrust-info.txt"):
            (self.payload / name).write_text("fixture")

    def complete(self, stage, outcome=None):
        defaults = dict(antivirus="clean", ingest="generated", fits="processed", reports="generated",
                        summary="generated", fixity="passed", bag_construct="constructed", bag_validate="valid", tar_serialize="serialized")
        outputs = dict(antivirus={"csv": "antivirus_A.csv", "log": "antivirus_A.log"},
                       ingest={"payload": "A", "xml": "A.xml"}, fits={"xml": "A.xml"},
                       reports={"csv": "A_files.csv", "html": "A_files.html"}, summary={"text": "A.txt"},
                       fixity={"csv": "fixity_A.csv", "log": "fixity_A.log"}, bag_construct={"bag": "A"},
                       bag_validate={}, tar_serialize={"tar": "A.tar"})
        record = self.status["steps"][stage]
        record.update(state="completed", outcome=outcome or defaults[stage], outputs=outputs[stage], attempt=2)
        if stage == "antivirus":
            record["result"] = dict(scanned_count=1, detection_count=0, error_count=0)
        for value in outputs[stage].values():
            path = self.output / value
            if not path.is_dir():
                path.write_text("fixture")
        if stage.startswith("bag_") or stage == "tar_serialize":
            self.bag()

    def plan(self, *selected, status=True):
        steps = {key: key in selected for key in ("ingest", "fits", "reports", "fixity", "bagging")}
        result = build_resume_plan(self.status if status else None, steps, self.options, self.output, "A")
        return {entry["stage"]: entry for entry in result}

    def action(self, stage, *selected):
        return self.plan(*selected)[stage]["action"]

    def test_completed_ingest_reuse_even_rerun_override(self):
        self.complete("ingest")
        self.options["rerun_completed"] = True
        self.assertEqual(self.action("ingest", "ingest"), "reuse")

    def test_completed_fits_reuse(self):
        self.complete("fits")
        self.assertEqual(self.action("fits", "fits"), "reuse")

    def test_reports_reuse_summary_not_started_run(self):
        self.complete("reports")
        plan = self.plan("reports")
        self.assertEqual((plan["reports"]["action"], plan["summary"]["action"]), ("reuse", "run"))

    def test_reports_reuse_summary_failed_run(self):
        self.complete("reports")
        self.status["steps"]["summary"]["state"] = "failed"
        self.assertEqual(self.action("summary", "reports"), "run")

    def test_missing_reports_forces_reports_and_completed_summary_to_run(self):
        self.complete("reports")
        self.complete("summary")
        (self.output / "A_files.html").unlink()
        plan = self.plan("reports")
        self.assertEqual((plan["reports"]["action"], plan["summary"]["action"]), ("run", "run"))

    def test_fixity_passed_reuse(self):
        self.complete("fixity")
        self.assertEqual(self.action("fixity", "fixity"), "reuse")

    def test_fixity_findings_review_or_explicit_rerun(self):
        self.complete("fixity", "findings")
        self.assertEqual(self.action("fixity", "fixity"), "review")
        self.options["rerun_completed"] = True
        self.assertEqual(self.action("fixity", "fixity"), "run")

    def test_bag_construct_reused_never_rebuilt_with_override(self):
        self.complete("bag_construct")
        self.options["rerun_completed"] = True
        self.assertEqual(self.action("bag_construct", "bagging"), "reuse")

    def test_valid_validation_reused(self):
        self.complete("bag_construct")
        self.complete("bag_validate")
        self.assertEqual(self.action("bag_validate", "bagging"), "reuse")

    def test_invalid_validation_blocks_tar(self):
        self.complete("bag_construct")
        self.complete("bag_validate", "invalid")
        plan = self.plan("bagging")
        self.assertEqual(plan["bag_validate"]["action"], "review")
        self.assertEqual(plan["tar_serialize"]["action"], "block")

    def test_existing_tar_reused(self):
        self.complete("bag_construct")
        self.complete("tar_serialize")
        self.assertEqual(self.action("tar_serialize", "bagging"), "reuse")

    def test_missing_tar_runs_with_bag_prerequisite(self):
        self.complete("bag_construct")
        self.complete("tar_serialize")
        (self.output / "A.tar").unlink()
        self.assertEqual(self.action("tar_serialize", "bagging"), "run")

    def test_failed_and_interrupted_fits_run(self):
        for state in ("failed", "interrupted"):
            self.status["steps"]["fits"]["state"] = state
            self.assertEqual(self.action("fits", "fits"), "run")

    def test_running_fits_review_even_with_override(self):
        self.status["steps"]["fits"]["state"] = "running"
        self.options["rerun_completed"] = True
        self.assertEqual(self.action("fits", "fits"), "review")

    def test_interrupted_ingest_requires_review(self):
        self.status["steps"]["ingest"]["state"] = "interrupted"
        self.assertEqual(self.action("ingest", "ingest"), "review")

    def test_unknown_history_review(self):
        self.status["steps"]["fits"]["state"] = "unknown"
        self.assertEqual(self.action("fits", "fits"), "review")

    def test_no_status_existing_xml_is_not_completion_inference(self):
        plan = self.plan("fits", "reports", status=False)
        self.assertEqual(plan["fits"]["action"], "run")
        self.assertEqual(plan["reports"]["action"], "run")

    def test_partial_bagging_resumes_optional_stages_only(self):
        self.complete("bag_construct")
        plan = self.plan("bagging")
        self.assertEqual([plan[s]["action"] for s in ("bag_construct", "bag_validate", "tar_serialize")], ["reuse", "run", "run"])

    def test_unrequested_options_skip(self):
        self.complete("bag_construct")
        self.options.update(validate=False, tar=False)
        plan = self.plan("bagging", "ingest")
        self.assertEqual(plan["antivirus"]["action"], "skip")
        self.assertEqual(plan["bag_validate"]["action"], "skip")
        self.assertEqual(plan["tar_serialize"]["action"], "skip")

    def test_plan_is_read_only(self):
        self.complete("fits")
        before = deepcopy(self.status)
        files = {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob("*") if p.is_file()}
        self.plan("fits", "reports")
        self.assertEqual(before, self.status)
        self.assertEqual(files, {p.relative_to(self.output): p.read_bytes() for p in self.output.rglob("*") if p.is_file()})

    def test_preview_has_run_reuse_skip_and_partial_detail(self):
        self.complete("reports")
        text = format_execution_plan(list(self.plan("reports").values()))
        self.assertIn("Metadata Reports — Reuse", text)
        self.assertIn("Collection Summary — Run", text)
        self.assertIn("Bagging — Not Selected", text)

    def test_fixity_findings_block_bagging_until_passing_rerun(self):
        self.complete("fixity", "findings")
        self.assertEqual(self.action("bag_construct", "bagging"), "block")
        self.options["rerun_completed"] = True
        plan = self.plan("fixity", "bagging")
        self.assertEqual(plan["fixity"]["action"], "run")
        self.assertTrue(plan["bag_construct"]["requires_passing_fixity"])

    def test_missing_completed_ingest_artifacts_never_regenerate(self):
        self.complete("ingest")
        (self.output / "A.xml").unlink()
        self.assertEqual(self.action("ingest", "ingest"), "review")

    def test_recorded_paths_cannot_escape_output(self):
        self.complete("fits")
        self.status["steps"]["fits"]["outputs"]["xml"] = "../elsewhere.xml"
        self.assertNotEqual(self.action("fits", "fits"), "reuse")

    def test_antivirus_clean_usable_only_when_requested(self):
        self.complete("antivirus")
        self.complete("ingest")
        self.assertEqual(self.action("antivirus", "ingest"), "skip")
        self.options["antivirus"] = True
        self.assertEqual(self.action("antivirus", "ingest"), "reuse")

    def test_ambiguous_bag_blocks_construction(self):
        (self.payload / "data").mkdir()
        self.assertEqual(self.action("bag_construct", "bagging"), "block")


class ResumeExecutionTests(unittest.TestCase):
    setUpClass = classmethod(fixture.SelectiveExecutionTests.setUpClass.__func__)
    setUp = fixture.SelectiveExecutionTests.setUp
    write_inventory = fixture.SelectiveExecutionTests.write_inventory
    fake_ingest = fixture.SelectiveExecutionTests.fake_ingest
    select = fixture.SelectiveExecutionTests.select
    execute = fixture.SelectiveExecutionTests.execute
    existing_bag = fixture.SelectiveExecutionTests.existing_bag
    assertOperations = fixture.SelectiveExecutionTests.assertOperations

    def seed(self, stage, outcome, outputs):
        path = self.output / "A_status.json"
        status = ps.load_status(self.output, "A") if path.exists() else ps.create_status(self.output, "A")
        status["steps"][stage].update(state="completed", outcome=outcome, outputs=outputs, attempt=3)
        return ps.save_status(self.output, "A", status)

    def test_reused_fits_status_not_rewritten(self):
        self.seed("fits", "processed", {"xml": "A.xml"})
        before = (self.output / "A_status.json").read_bytes()
        self.execute(2)
        self.assertOperations()
        self.assertEqual((self.output / "A_status.json").read_bytes(), before)

    def test_explicit_fits_rerun_increments_attempt(self):
        self.seed("fits", "processed", {"xml": "A.xml"})
        self.g["rerun_completed_var"].set(True)
        self.execute(2)
        self.assertOperations("enrich_accession_with_fits")
        self.assertEqual(ps.load_status(self.output, "A")["steps"]["fits"]["attempt"], 4)

    def test_reports_reuse_summary_only_execution(self):
        for name in ("A_files.csv", "A_files.html"):
            (self.output / name).write_text("fixture")
        self.seed("reports", "generated", {"csv": "A_files.csv", "html": "A_files.html"})
        before = ps.load_status(self.output, "A")["steps"]["reports"]
        self.execute(3)
        self.assertOperations("generate_summary_report")
        self.assertEqual(ps.load_status(self.output, "A")["steps"]["reports"], before)

    def test_partial_bagging_reuses_construction(self):
        self.existing_bag()
        self.seed("bag_construct", "constructed", {"bag": "A"})
        self.g["validate_bag_var"].set(True)
        self.execute(5)
        self.assertOperations("validate_bag", "serialize_bag_to_tar")

    def test_completed_ingest_reused_without_input_directory(self):
        self.seed("ingest", "generated", {"payload": "A", "xml": "A.xml"})
        self.g["av_var"].set(False)
        self.execute(1)
        self.assertOperations()
        self.messages.showerror.assert_not_called()

    def test_review_blocks_thread_and_does_not_rewrite_running(self):
        status = ps.create_status(self.output, "A")
        status["steps"]["fits"]["state"] = "running"
        ps.save_status(self.output, "A", status)
        before = (self.output / "A_status.json").read_bytes()
        self.select(2)
        with patch.object(self.g["threading"], "Thread") as thread:
            self.g["start_pipeline"]()
        thread.assert_not_called()
        self.assertIn("previous attempt may still be running or was interrupted", self.messages.showerror.call_args.args[1])
        self.assertEqual(before, (self.output / "A_status.json").read_bytes())

    def test_preview_precedes_thread_and_does_not_change_selections(self):
        self.select(2)
        before = self.g["run_format_identification"].get()
        with patch.object(self.g["threading"], "Thread") as thread, \
             patch.dict(self.g, confirm_run=MagicMock(return_value=True)):
            self.g["start_pipeline"]()
            self.assertIn("Step 2 — Format Identification", self.g["confirm_run"].call_args.args[0])
        thread.return_value.start.assert_called_once()
        self.assertEqual(self.g["run_format_identification"].get(), before)
        self.g["restore_run_controls"]()

    def display_plan(self, **actions):
        return [dict(stage=stage, action=actions.get(stage, "skip"),
                     reason="no_managed_status" if stage in actions else "not_requested")
                for stage in ps.STAGE_IDS]

    def test_confirmation_new_ingest_hides_internal_details(self):
        plan = self.display_plan(antivirus="run", ingest="run")
        text = self.g["format_run_confirmation"](plan, {"move": False})
        self.assertIn("Step 1 — Ingest\n  • Microsoft Defender scan\n  • Copy files into accession", text)
        self.assertIn("Other steps will not run.", text)
        for hidden in ("managed", "Not Selected", "Freshness", "Step 2", "no_managed_status"):
            self.assertNotIn(hidden, text)
        self.assertEqual(plan, self.display_plan(antivirus="run", ingest="run"))
        self.assertIn("Move files into accession", self.g["format_run_confirmation"](plan, {"move": True}))

    def test_confirmation_partial_reports_and_bagging_reuse(self):
        plan = self.display_plan(reports="reuse", summary="run", fixity="run",
                                 bag_construct="reuse", bag_validate="run", tar_serialize="run")
        text = self.g["format_run_confirmation"](plan, {})
        self.assertIn("Step 3 — Reports\n  • Collection summary", text)
        self.assertNotIn("Metadata reports", text)
        self.assertIn("Step 4 — Fixity", text)
        self.assertIn("Step 5 — Bagging\n  • Validate BagIt package\n  • Create TAR archive", text)
        self.assertNotIn("Create BagIt package", text)
        self.assertEqual(text.count("Previously completed steps will be reused automatically."), 1)
        self.assertNotIn("bag_construct", text)

    def test_confirmation_reuse_only(self):
        plan = self.display_plan(fits="reuse")
        text = self.g["format_run_confirmation"](plan, {})
        self.assertIn("No steps need to run.", text)
        self.assertIn("Previously completed steps will be reused automatically.", text)
        self.assertNotIn("Step 2", text)

    def test_bagged_fits_and_fixity_show_working_copy_prerequisite(self):
        self.existing_bag()
        self.seed("fits", "processed", {"xml": "A.xml"})
        self.g["rerun_completed_var"].set(True)
        for step, stage, heading in ((2, "fits", "Step 2 — Format Identification"),
                                     (4, "fixity", "Step 4 — Fixity")):
            with self.subTest(step=step):
                self.select(step)
                options = self.g["selected_run_options"]()
                plan = self.g["prepare_execution_plan"](options)
                before = deepcopy(plan)
                status_bytes = (self.output / "A_status.json").read_bytes()
                text = self.g["format_run_confirmation"](plan, options)
                self.assertIn("already been packaged as a BagIt bag", text)
                self.assertIn("• " + heading, text)
                self.assertEqual(text.count("requires an unbagged working accession"), 1)
                self.assertIn("use an unbagged working copy", text)
                self.assertNotIn("No steps need to run", text)
                self.assertEqual(plan, before)
                decision = next(item for item in plan if item["stage"] == stage)
                self.assertEqual((decision["action"], decision["reason"]), ("block", "unbagged_payload_required"))
                with patch.object(self.g["threading"], "Thread") as thread:
                    self.g["start_pipeline"]()
                thread.assert_not_called()
                self.assertEqual(self.messages.showerror.call_args.args[0], "Processing Cannot Start")
                self.assertEqual((self.output / "A_status.json").read_bytes(), status_bytes)

    def test_bagged_fits_reports_dependency_explained_once(self):
        self.existing_bag()
        self.seed("fits", "processed", {"xml": "A.xml"})
        self.g["rerun_completed_var"].set(True)
        self.select(2, 3, 4)
        options = self.g["selected_run_options"]()
        plan = self.g["prepare_execution_plan"](options)
        text = self.g["format_run_confirmation"](plan, options)
        self.assertIn("• Step 2 — Format Identification", text)
        self.assertIn("• Step 4 — Fixity", text)
        self.assertEqual(text.count("Step 3 — Reports cannot proceed"), 1)
        self.assertIn("Reports can still be regenerated separately from the saved metadata", text)
        for hidden in ("No steps need to run", "Collection summary", "fits_requires_review",
                       "reports_requires_review", "Review metadata reports", "This work requires accession files"):
            self.assertNotIn(hidden, text)
        actions = {item["stage"]: item["action"] for item in plan}
        self.assertTrue(all(actions[stage] == "block" for stage in ("fits", "reports", "summary", "fixity")))

    def test_reports_alone_remain_allowed_on_bagged_accession(self):
        self.existing_bag()
        self.seed("fits", "processed", {"xml": "A.xml"})
        self.g["rerun_completed_var"].set(True)
        self.select(3)
        options = self.g["selected_run_options"]()
        plan = self.g["prepare_execution_plan"](options)
        self.g["validate_execution_plan"](options, plan)
        text = self.g["format_run_confirmation"](plan, options)
        self.assertIn("Step 3 — Reports", text)
        self.assertNotIn("unbagged working accession", text)
        self.execute(3)
        self.assertOperations("run_xslt_processor", "run_xslt_processor", "generate_summary_report")

    def test_review_or_block_without_running_work_is_not_reuse_only(self):
        for action in ("review", "block"):
            plan = self.display_plan(fits=action)
            plan[ps.STAGE_IDS.index("fits")]["reason"] = "unknown_history"
            text = self.g["format_run_confirmation"](plan, {})
            self.assertNotIn("No steps need to run", text)
            self.assertIn("Selected processing cannot start", text)

    def test_confirmation_preserves_stale_and_validation_warnings(self):
        plan = self.display_plan(fits="run", tar_serialize="block")
        plan[ps.STAGE_IDS.index("fits")].update(reason="recorded_stale", freshness_reasons=["fits_output_changed"])
        plan[ps.STAGE_IDS.index("tar_serialize")]["reason"] = "successful_validation_required"
        text = self.g["format_run_confirmation"](plan, {})
        self.assertIn("Outputs have changed; affected work will run again.", text)
        self.assertIn("must pass validation before creating a TAR archive", text)
        self.assertNotIn("fits_output_changed", text)
        self.assertNotIn("integrity verification", text)

    def test_confirmation_preserves_dependency_and_fixity_warnings(self):
        plan = self.display_plan(reports="block", bag_construct="run")
        plan[ps.STAGE_IDS.index("reports")]["reason"] = "fits_requires_review"
        plan[ps.STAGE_IDS.index("bag_construct")]["requires_passing_fixity"] = True
        text = self.g["format_run_confirmation"](plan, {})
        self.assertIn("Review format identification output before continuing.", text)
        self.assertIn("Fixity must pass before creating the BagIt package.", text)

    def test_cancel_does_not_start_thread_or_lock_controls(self):
        self.select(2)
        with patch.object(self.g["threading"], "Thread") as thread, \
             patch.dict(self.g, confirm_run=MagicMock(return_value=False)):
            self.g["start_pipeline"]()
        thread.assert_not_called()
        self.assertFalse(self.g["inputs_locked"])
        self.assertEqual(str(self.g["run_button"].cget("state")), "normal")
        self.assertFalse((self.output / "A_status.json").exists())

    def test_confirmation_buttons_return_run_or_cancel(self):
        def invoke(label):
            def visit(widget):
                for child in widget.winfo_children():
                    if child.winfo_class() == "TButton" and child.cget("text") == label:
                        child.invoke()
                        return True
                    if visit(child):
                        return True
                return False
            self.assertTrue(visit(self.g["root"]))

        for label, expected in (("Run", True), ("Cancel", False)):
            with self.subTest(button=label):
                self.g["root"].after(0, lambda name=label: invoke(name))
                self.assertEqual(self.g["confirm_run"]("Test confirmation"), expected)

    def test_new_fixity_findings_block_bagging_at_runtime(self):
        def fixity(*args):
            path = self.output / "fixity_A.csv"
            path.write_text("status\nMISMATCH\n")
            return path, None
        self.calls.run_fixity.side_effect = fixity
        self.execute(4, 5)
        self.assertOperations("run_fixity")
        self.assertIn("findings block Bagging", self.messages.showerror.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
