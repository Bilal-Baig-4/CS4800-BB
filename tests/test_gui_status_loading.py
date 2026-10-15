"""Status-driven GUI selections and durable refresh with real Tk controls."""
import unittest
from unittest.mock import patch

import pipeline_state as ps
import test_gui_selective as fixture


class GuiHistoryTests(unittest.TestCase):
    setUpClass = classmethod(fixture.SelectiveExecutionTests.setUpClass.__func__)
    setUp = fixture.SelectiveExecutionTests.setUp
    write_inventory = fixture.SelectiveExecutionTests.write_inventory
    fake_ingest = fixture.SelectiveExecutionTests.fake_ingest
    select = fixture.SelectiveExecutionTests.select
    execute = fixture.SelectiveExecutionTests.execute

    def selection(self):
        return {name: self.g[name].get() for name in fixture.SELECTIONS}

    def test_initial_and_missing_status_do_not_claim_not_started(self):
        g = self.g
        self.assertEqual(g["history_message_var"].get(), "Status not loaded")
        self.assertTrue(all(v.get() == "Not Loaded" for v in g["step_history_vars"].values()))
        self.select(1, 3, 5)
        before = self.selection()
        g["load_accession_status"]()
        self.assertIn("No managed status", g["history_message_var"].get())
        self.assertFalse((self.output / "A_status.json").exists())
        self.assertEqual(self.selection(), before)
        self.messages.showwarning.assert_not_called()

    def test_valid_sidecar_load_preserves_status_and_selects_unverified_work(self):
        status = ps.create_status(self.output, "A")
        status["steps"]["ingest"].update(state="completed", outcome="generated", attempt=2)
        ps.save_status(self.output, "A", status)
        path = self.output / "A_status.json"
        before_bytes = path.read_bytes()
        self.g["load_accession_status"]()
        self.assertEqual(self.g["step_history_vars"]["ingest"].get(), "Completed — Virus Scan Not Run")
        self.assertEqual(path.read_bytes(), before_bytes)
        self.assertEqual(list(self.selection().values()), [True, True, True, True, False])
        self.assertEqual(self.g["status_details_button"].cget("state"), "normal")

    def test_running_remains_running_without_recovery(self):
        status = ps.create_status(self.output, "A")
        status["steps"]["fits"].update(state="running", attempt=1)
        ps.save_status(self.output, "A", status)
        self.g["load_accession_status"]()
        self.assertEqual(self.g["step_history_vars"]["format_identification"].get(), "Running / Possibly Interrupted")
        self.assertEqual(ps.load_status(self.output, "A")["steps"]["fits"]["state"], "running")

    def test_identity_changes_clear_loaded_history(self):
        ps.create_status(self.output, "A")
        for field, value in (("accession_var", "B"), ("output_dir_var", str(self.base / "different"))):
            self.g["accession_var"].set("A")
            self.g["output_dir_var"].set(str(self.output))
            self.g["load_accession_status"]()
            self.g[field].set(value)
            self.assertIsNone(self.g["loaded_history"])
            self.assertTrue(all(v.get() == "Not Loaded" for v in self.g["step_history_vars"].values()))
            self.assertEqual(self.g["status_details_button"].cget("state"), "disabled")

    def test_malformed_newer_mismatched_and_invalid_status_preserved(self):
        path = self.output / "A_status.json"
        self.select(2, 4, 5)
        before_selection = self.selection()
        for contents in ("{broken", '{"schema_version":2}', '{"schema_version":1}',
                         None):
            if contents is None:
                status = ps.create_status(self.output, "A")
                status["accession_number"] = "B"
                import json
                contents = json.dumps(status)
            path.write_text(contents)
            before = path.read_bytes()
            self.messages.reset_mock()
            self.g["load_accession_status"]()
            self.messages.showerror.assert_called_once()
            self.assertEqual(path.read_bytes(), before)
            self.assertIsNone(self.g["loaded_history"])
            self.assertEqual(self.selection(), before_selection)
            self.messages.showwarning.assert_not_called()
            path.unlink()

    def test_refresh_after_completion_reloads_durable_file(self):
        self.select(2)
        queued = []
        with patch.object(self.g["root"], "after", side_effect=lambda delay, callback, *args: queued.append((callback, args))):
            self.g["run_pipeline"]()
        callback, args = queued[-1]
        callback(*args)
        self.assertIn("Completed", self.g["step_history_vars"]["format_identification"].get())
        self.assertEqual(self.g["loaded_history"], ps.load_status(self.output, "A"))

    def test_failed_final_save_refresh_shows_durable_running(self):
        ps.create_status(self.output, "A")
        original = ps.save_status
        def save(output, accession, status):
            if status["steps"]["fits"]["state"] == "completed":
                raise OSError("final save failed")
            return original(output, accession, status)
        self.select(2)
        queued = []
        with patch.object(ps, "save_status", side_effect=save), \
             patch.object(self.g["root"], "after", side_effect=lambda delay, callback, *args: queued.append((callback, args))):
            self.g["run_pipeline"]()
        callback, args = queued[-1]
        callback(*args)
        self.assertEqual(self.g["step_history_vars"]["format_identification"].get(), "Running / Possibly Interrupted")

    def test_queued_refresh_does_not_display_previous_accession(self):
        ps.create_status(self.output, "A")
        expected = self.g["history_identity"](str(self.output), "A")
        self.g["accession_var"].set("B")
        self.g["load_accession_status"](False, expected)
        self.assertEqual(self.g["history_message_var"].get(), "Status not loaded")

    def test_refresh_and_detail_controls_respect_run_lock(self):
        ps.create_status(self.output, "A")
        self.g["load_accession_status"]()
        self.g["set_inputs_locked"](True)
        for name in ("refresh_status_button", "status_details_button"):
            self.assertEqual(self.g[name].cget("state"), "disabled")
        self.g["set_inputs_locked"](False)
        for name in ("refresh_status_button", "status_details_button"):
            self.assertEqual(self.g[name].cget("state"), "normal")

    def test_details_window_is_read_only_and_closes_when_identity_changes(self):
        ps.create_status(self.output, "A")
        self.g["load_accession_status"]()
        self.g["show_status_details"]()
        window = self.g["details_window"]
        text = next(child for child in window.winfo_children() if child.winfo_class() == "Text")
        self.assertEqual(text.cget("state"), "disabled")
        self.assertIn("TAR Serialization", text.get("1.0", "end"))
        self.g["accession_var"].set("B")
        self.assertFalse(window.winfo_exists())

    def test_loading_completed_history_does_not_skip_manual_rerun(self):
        status = ps.create_status(self.output, "A")
        status["steps"]["fits"].update(state="completed", outcome="processed", attempt=1)
        ps.save_status(self.output, "A", status)
        self.select(2)
        self.g["load_accession_status"]()
        self.select(2)  # Deliberately reselect completed work after the load suggestions.
        self.g["rerun_completed_var"].set(True)
        self.g["run_pipeline"]()
        self.calls.enrich_accession_with_fits.assert_called_once()
        self.assertEqual(ps.load_status(self.output, "A")["steps"]["fits"]["attempt"], 2)

    def load_selection_status(self, status):
        ps.save_status(self.output, "A", status)
        # Isolate selection behavior from fingerprint reconciliation, tested separately.
        with patch.dict(self.g, load_reconciled_status=ps.load_status):
            self.g["load_accession_status"]()

    def new_selection_status(self):
        (self.output / "A_status.json").unlink(missing_ok=True)
        return ps.create_status(self.output, "A")

    def completed_current(self, status, *stages):
        for stage in stages:
            record = status["steps"][stage]
            record.update(state="completed", attempt=1)
            record["freshness"]["state"] = "current"

    def test_completed_ingest_fits_unchecked_reports_fixity_selected(self):
        status = ps.create_status(self.output, "A")
        self.completed_current(status, "ingest", "fits")
        self.select(1, 2, 5)
        self.load_selection_status(status)
        self.assertEqual(list(self.selection().values()), [False, False, True, True, False])

    def test_reports_need_both_reports_and_summary_completed_current(self):
        for summary_state in ("not_started", "failed", "completed"):
            with self.subTest(summary=summary_state):
                status = self.new_selection_status()
                self.completed_current(status, "reports")
                status["steps"]["summary"]["state"] = summary_state
                if summary_state == "completed":
                    self.completed_current(status, "summary")
                self.load_selection_status(status)
                self.assertEqual(self.g["run_reports"].get(), summary_state != "completed")

    def test_stale_reports_or_summary_selected(self):
        for stage in ("reports", "summary"):
            with self.subTest(stage=stage):
                status = self.new_selection_status()
                self.completed_current(status, "reports", "summary")
                status["steps"][stage]["freshness"]["state"] = "stale"
                self.load_selection_status(status)
                self.assertTrue(self.g["run_reports"].get())

    def test_fixity_stale_selected_current_unchecked(self):
        for freshness in ("stale", "current"):
            with self.subTest(freshness=freshness):
                status = self.new_selection_status()
                self.completed_current(status, "fixity")
                status["steps"]["fixity"]["freshness"]["state"] = freshness
                self.load_selection_status(status)
                self.assertEqual(self.g["run_fixity_selected"].get(), freshness != "current")

    def test_mandatory_stages_requiring_attention_selected(self):
        for stage, variable in (("ingest", "run_ingest"), ("fits", "run_format_identification"),
                                ("fixity", "run_fixity_selected")):
            for state, freshness in (("failed", "current"), ("running", "current"),
                                     ("interrupted", "current"), ("unknown", "current"),
                                     ("completed", "stale"), ("completed", "unverified")):
                with self.subTest(stage=stage, state=state, freshness=freshness):
                    status = self.new_selection_status()
                    status["steps"][stage]["state"] = state
                    status["steps"][stage]["freshness"]["state"] = freshness
                    self.select()
                    self.load_selection_status(status)
                    self.assertTrue(self.g[variable].get())

    def test_bagging_never_selected_without_unambiguous_requested_workflow(self):
        for constructed in (False, True):
            with self.subTest(constructed=constructed):
                status = self.new_selection_status()
                if constructed:
                    self.completed_current(status, "bag_construct")
                self.select(5)
                self.load_selection_status(status)
                self.assertFalse(self.g["run_bagging"].get())

    def test_status_selection_preserves_sub_options(self):
        names = ("av_var", "move_var", "bag_profile_var", "validate_bag_var",
                 "serialize_tar_var", "rerun_completed_var")
        self.g["move_var"].set(True)
        self.g["bag_profile_var"].set("generic")
        self.g["validate_bag_var"].set(True)
        self.g["rerun_completed_var"].set(True)
        before = {name: self.g[name].get() for name in names}
        self.load_selection_status(ps.create_status(self.output, "A"))
        self.assertEqual({name: self.g[name].get() for name in names}, before)

    def test_automatic_refresh_keeps_selections(self):
        ps.create_status(self.output, "A")
        self.select(2, 5)
        before = self.selection()
        self.g["load_accession_status"](False, self.g["history_identity"](str(self.output), "A"))
        self.assertEqual(self.selection(), before)

    def mark_completed_stale(self, status, *stages):
        self.completed_current(status, *stages)
        for stage in stages:
            status["steps"][stage]["freshness"].update(state="stale", reasons=["output_changed"])

    def test_one_stale_step_warns_after_checkbox_updates(self):
        status = ps.create_status(self.output, "A")
        self.mark_completed_stale(status, "fits")
        self.select()
        selections_at_warning = []
        self.messages.showwarning.side_effect = lambda *args: selections_at_warning.append(self.selection())
        self.load_selection_status(status)
        self.messages.showwarning.assert_called_once()
        title, message = self.messages.showwarning.call_args.args
        self.assertEqual(title, "Changes Detected")
        self.assertIn("• Step 2 — Format Identification", message)
        self.assertEqual(message.count("• Step"), 1)
        self.assertEqual(selections_at_warning, [self.selection()])
        self.assertTrue(self.g["run_format_identification"].get())
        for hidden in ("fingerprint", "freshness", "fits", "automatically rerun"):
            self.assertNotIn(hidden, message)

    def test_stale_internal_stages_list_each_gui_step_once(self):
        for stages, heading in ((("reports", "summary"), "Step 3 — Reports"),
                                (("bag_construct", "bag_validate", "tar_serialize"), "Step 5 — Bagging")):
            with self.subTest(heading=heading):
                status = self.new_selection_status()
                self.mark_completed_stale(status, *stages)
                self.messages.showwarning.reset_mock()
                self.load_selection_status(status)
                self.messages.showwarning.assert_called_once()
                message = self.messages.showwarning.call_args.args[1]
                self.assertEqual(message.count(heading), 1)
                self.assertEqual(message.count("• Step"), 1)
                self.assertFalse(self.g["run_bagging"].get())
                for stage in stages:
                    self.assertNotIn(stage, message)

    def test_multiple_stale_gui_steps_all_listed_once(self):
        status = ps.create_status(self.output, "A")
        self.mark_completed_stale(status, *ps.STAGE_IDS)
        self.load_selection_status(status)
        self.messages.showwarning.assert_called_once()
        message = self.messages.showwarning.call_args.args[1]
        for heading in ("Step 1 — Ingest", "Step 2 — Format Identification", "Step 3 — Reports",
                        "Step 4 — Fixity", "Step 5 — Bagging"):
            self.assertEqual(message.count(heading), 1)
        self.assertEqual(list(self.selection().values()), [True, True, True, True, False])
        self.assertIn("Bagging remains optional", message)

    def test_current_completed_stages_do_not_warn(self):
        status = ps.create_status(self.output, "A")
        self.completed_current(status, *ps.STAGE_IDS)
        self.load_selection_status(status)
        self.messages.showwarning.assert_not_called()

    def test_unverified_completed_stages_do_not_warn(self):
        status = ps.create_status(self.output, "A")
        for record in status["steps"].values():
            record["state"] = "completed"
        self.load_selection_status(status)
        self.messages.showwarning.assert_not_called()

    def test_unfinished_stale_stages_do_not_warn(self):
        status = ps.create_status(self.output, "A")
        for record in status["steps"].values():
            record.update(state="failed")
            record["freshness"].update(state="stale", reasons=["output_changed"])
        self.load_selection_status(status)
        self.messages.showwarning.assert_not_called()

    def test_automatic_refresh_with_stale_completed_stages_does_not_warn(self):
        status = ps.create_status(self.output, "A")
        self.mark_completed_stale(status, *ps.STAGE_IDS)
        ps.save_status(self.output, "A", status)
        self.select(2, 5)
        before = self.selection()
        with patch.dict(self.g, load_reconciled_status=ps.load_status):
            self.g["load_accession_status"](False, self.g["history_identity"](str(self.output), "A"))
        self.messages.showwarning.assert_not_called()
        self.assertEqual(self.selection(), before)


if __name__ == "__main__":
    unittest.main()
