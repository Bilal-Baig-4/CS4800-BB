"""History presentation is pure and conservative; no Tk or artifact discovery."""
from copy import deepcopy
import unittest

import pipeline_state as view


def record():
    return dict(accession_number="A", revision=1, layout="unknown", steps={
        stage: dict(state="not_started", outcome=None, attempt=0, started_at=None,
                    finished_at=None, settings={}, outputs={}, freshness={"state": "unverified"})
        for stages in view.STEP_STAGES.values() for stage in stages})


class StatusSummaryTests(unittest.TestCase):
    def setUp(self):
        self.status = record()

    def set(self, stage, state, outcome=None):
        self.status["steps"][stage].update(state=state, outcome=outcome)

    def label(self, step):
        return view.summarize_user_steps(self.status)[step]["label"]

    def test_all_not_started_and_five_groups(self):
        summaries = view.summarize_user_steps(self.status)
        self.assertEqual(len(summaries), 5)
        self.assertTrue(all(s["label"] == "Not Started" for s in summaries.values()))

    def test_ingest_completed_optional_antivirus_not_run(self):
        self.set("ingest", "completed", "generated")
        self.assertEqual(self.label("ingest"), "Completed — Virus Scan Not Run")

    def test_ingest_completed_unavailable_antivirus(self):
        self.set("ingest", "completed", "generated")
        self.set("antivirus", "failed", "unavailable")
        self.assertEqual(self.label("ingest"), "Completed — Virus Scan Needs Attention")
        self.assertIn("Unavailable", view.summarize_user_steps(self.status)["ingest"]["detail"])

    def test_ingest_detections_are_not_failure(self):
        self.set("antivirus", "completed", "detections")
        self.set("ingest", "completed", "generated")
        self.assertEqual(self.label("ingest"), "Completed — Virus Scan Detections")

    def test_scan_completed_without_ingest_is_partial(self):
        self.set("antivirus", "completed", "clean")
        self.assertEqual(self.label("ingest"), "Partially Complete")

    def test_reports_completed_partial_failure_and_unknown(self):
        self.set("reports", "completed", "generated")
        self.assertEqual(self.label("reports"), "Partially Complete")
        self.set("summary", "completed", "generated")
        self.assertEqual(self.label("reports"), "Completed")
        self.set("summary", "failed", "error")
        self.assertEqual(self.label("reports"), "Needs Attention")
        self.set("reports", "failed", "partial")
        self.set("summary", "not_started")
        self.assertEqual(self.label("reports"), "Failed")
        self.set("reports", "unknown")
        self.assertEqual(self.label("reports"), "Unknown")

    def test_fixity_findings_and_passed_are_completed(self):
        for outcome in ("passed", "findings"):
            self.set("fixity", "completed", outcome)
            self.assertEqual(self.label("fixity"), f"Completed — {outcome.title()}")

    def test_fits_processed_displays_format_identification_finished(self):
        self.set("fits", "completed", "processed")
        before = deepcopy(self.status)
        self.assertEqual(self.label("format_identification"), "Completed — Format Identification Finished")
        self.assertIn("Format Identification: Completed — Detailed Results Unavailable",
                      view.format_stage_details(self.status))
        self.assertEqual(self.status, before)

    def test_fits_processed_other_states_keep_existing_wording(self):
        for state in ("failed", "interrupted", "running", "unknown", "not_started"):
            self.set("fits", state, "processed")
            self.assertEqual(self.label("format_identification"),
                             view.STATE_LABELS[state] + " — Detailed Results Unavailable")
        self.set("fits", "completed", "processed")
        self.status["steps"]["fits"]["freshness"].update(state="stale", reasons=["fits_output_changed"])
        self.assertEqual(self.label("format_identification"), "Completed — Detailed Results Unavailable — Stale")

    def test_bagging_construction_only_is_legitimate_completion(self):
        self.set("bag_construct", "completed", "constructed")
        self.assertEqual(self.label("bagging"), "Construction Completed")

    def test_bagging_validated_without_tar_does_not_assume_tar_required(self):
        self.set("bag_construct", "completed", "constructed")
        self.set("bag_validate", "completed", "valid")
        self.assertEqual(self.label("bagging"), "Bag Validated")
        self.set("tar_serialize", "completed", "serialized")
        self.assertEqual(self.label("bagging"), "Completed")

    def test_bag_invalid_is_attention_not_execution_failure(self):
        self.set("bag_construct", "completed", "constructed")
        self.set("bag_validate", "completed", "invalid")
        self.assertEqual(self.label("bagging"), "Needs Attention — Bag Invalid")
        self.assertEqual(view.stage_text(self.status["steps"]["bag_validate"]), "Completed — Invalid")

    def test_recorded_optional_requests_are_honored(self):
        self.set("bag_construct", "completed", "constructed")
        self.status["steps"]["bag_construct"]["settings"] = dict(validate=True, serialize_tar=True, profile="aptrust")
        self.assertIn("Partially Complete", self.label("bagging"))
        self.assertIn("Validation Pending", self.label("bagging"))
        self.assertIn("TAR Pending", self.label("bagging"))

    def test_unknown_bag_history_not_claimed_completed(self):
        self.set("bag_construct", "completed", "constructed")
        self.set("bag_validate", "unknown")
        self.assertEqual(self.label("bagging"), "Partially Complete — Unknown History")

    def test_running_displayed_conservatively_for_every_stage(self):
        for stage in self.status["steps"]:
            status = record()
            status["steps"][stage]["state"] = "running"
            summary = view.summarize_user_steps(status)
            group = next(name for name, stages in view.STEP_STAGES.items() if stage in stages)
            self.assertEqual(summary[group]["label"], "Running / Possibly Interrupted")
            self.assertEqual(status["steps"][stage]["state"], "running")

    def test_interrupted_unknown_and_failed_direct_states(self):
        for state, expected in (("interrupted", "Incomplete Previous Attempt"), ("unknown", "Unknown"), ("failed", "Failed")):
            self.set("fits", state)
            self.assertEqual(self.label("format_identification"), expected)

    def test_pure_helpers_preserve_all_records_and_show_nine_details(self):
        before = deepcopy(self.status)
        view.summarize_user_steps(self.status)
        detail = view.format_stage_details(self.status)
        for name in view.STAGE_NAMES.values():
            self.assertIn(name, detail)
        self.assertIn("freshness: unverified", detail)
        self.assertEqual(before, self.status)


if __name__ == "__main__":
    unittest.main()
