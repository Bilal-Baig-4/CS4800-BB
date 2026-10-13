"""Read-only status loading and durable refresh with real Tk controls."""
import unittest
from unittest.mock import patch

from pipeline_state import status as ps
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
        before = self.selection()
        g["load_accession_status"]()
        self.assertIn("No managed status", g["history_message_var"].get())
        self.assertFalse((self.output / "A_status.json").exists())
        self.assertEqual(self.selection(), before)

    def test_valid_sidecar_load_is_read_only_and_does_not_change_selectors(self):
        status = ps.create_status(self.output, "A")
        status["steps"]["ingest"].update(state="completed", outcome="generated", attempt=2)
        ps.save_status(self.output, "A", status)
        path = self.output / "A_status.json"
        before_bytes = path.read_bytes()
        before = self.selection()
        self.g["load_accession_status"]()
        self.assertEqual(self.g["step_history_vars"]["ingest"].get(), "Completed — Virus Scan Not Run")
        self.assertEqual(path.read_bytes(), before_bytes)
        self.assertEqual(self.selection(), before)
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
        self.g["rerun_completed_var"].set(True)
        self.g["run_pipeline"]()
        self.calls.enrich_accession_with_fits.assert_called_once()
        self.assertEqual(ps.load_status(self.output, "A")["steps"]["fits"]["attempt"], 2)


if __name__ == "__main__":
    unittest.main()
