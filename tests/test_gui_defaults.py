"""Local directory preferences and debounced status loading; no processing changes."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import tkinter as tk
import unittest
from unittest.mock import patch

import pipeline_state as ps
import test_gui_selective as fixture
from test_gui_steps import GUI_PATH, SELECTIONS


class PreferenceTests(unittest.TestCase):
    setUpClass = classmethod(fixture.SelectiveExecutionTests.setUpClass.__func__)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.path = self.base / "ArchivesPipeline" / "settings.json"
        override = patch.dict(os.environ, LOCALAPPDATA=str(self.base))
        override.start()
        self.addCleanup(override.stop)

    def test_missing_settings(self):
        self.assertEqual(self.g["load_defaults"](), {})
        self.assertFalse(self.path.exists())

    def test_malformed_settings(self):
        self.path.parent.mkdir()
        for text in ("{broken", "[]", "null", '{"input": 42, "output": false}'):
            self.path.write_text(text)
            self.assertEqual(self.g["load_defaults"](), {})

    def test_nonexistent_paths_ignored(self):
        self.path.parent.mkdir()
        self.path.write_text(json.dumps(dict(input=str(self.base / "absent"), output=str(self.base))))
        self.assertEqual(self.g["load_defaults"](), dict(output=str(self.base.resolve())))

    def test_save_each_default_preserves_other(self):
        self.g["save_default"]("input", str(self.base))
        self.g["save_default"]("output", str(self.path.parent))
        self.assertEqual(self.g["load_defaults"](), dict(input=str(self.base.resolve()),
                                                          output=str(self.path.parent.resolve())))
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.g["save_default"]("input", str(self.base / "absent"))
        self.assertEqual(before, self.path.read_bytes())

    def test_startup_restores_saved_defaults_and_safe_fallbacks(self):
        self.g["save_default"]("input", str(self.base))
        self.g["save_default"]("output", str(self.path.parent))
        original_tk = tk.Tk
        for content, expected in ((self.path.read_text(), self.g["load_defaults"]()),
                                  ("{broken", {}), (None, {})):
            with self.subTest(content=content):
                if content is None:
                    self.path.unlink(missing_ok=True)
                else:
                    self.path.write_text(content)
                roots = []
                def hidden_root():
                    root = original_tk()
                    root.withdraw()
                    roots.append(root)
                    return root
                try:
                    with patch.object(tk, "Tk", side_effect=hidden_root), patch.object(original_tk, "mainloop"):
                        gui = runpy.run_path(str(GUI_PATH))
                    self.assertEqual(gui["input_dir_var"].get(), expected.get("input", ""))
                    self.assertEqual(gui["output_dir_var"].get(), expected.get("output", ""))
                finally:
                    for root in roots:
                        root.destroy()


class AutoStatusTests(unittest.TestCase):
    setUpClass = classmethod(fixture.SelectiveExecutionTests.setUpClass.__func__)
    write_inventory = fixture.SelectiveExecutionTests.write_inventory
    fake_ingest = fixture.SelectiveExecutionTests.fake_ingest
    select = fixture.SelectiveExecutionTests.select

    def setUp(self):
        fixture.SelectiveExecutionTests.setUp(self)
        self.g["cancel_status_refresh"]()
        self.addCleanup(self.g["cancel_status_refresh"])

    def selection(self):
        return [self.g[name].get() for name in SELECTIONS]

    def status(self, stale=False):
        status = ps.create_status(self.output, "A")
        for stage in ("ingest", "fits"):
            status["steps"][stage].update(state="completed", outcome="generated" if stage == "ingest" else "processed")
            status["steps"][stage]["freshness"]["state"] = "current"
        if stale:
            status["steps"]["fits"]["freshness"].update(state="stale", reasons=["output_changed"])
        return ps.save_status(self.output, "A", status)

    def test_accession_change_debounces_and_loads_current_selections(self):
        self.status()
        self.select(1, 2, 5)
        callbacks = []
        def queue(delay, callback, *args):
            callbacks.append((callback, args))
            self.assertEqual(delay, 600)
            return f"test-{len(callbacks)}"
        with patch.object(self.g["root"], "after", side_effect=queue), \
             patch.object(self.g["root"], "after_cancel") as cancel, \
             patch.dict(self.g, load_reconciled_status=ps.load_status):
            for value in ("", "A1", "A"):
                self.g["accession_var"].set(value)
            callback, args = callbacks[-1]
            callback(*args)
            self.assertIsNotNone(self.g["loaded_history"])
            self.assertEqual(self.selection(), [False, False, True, True, False])
            cancel.assert_any_call("test-1")
        self.messages.showerror.assert_not_called()
        self.messages.showwarning.assert_not_called()

    def test_output_change_schedules_refresh(self):
        with patch.object(self.g["root"], "after", return_value="test-output") as after, \
             patch.object(self.g["root"], "after_cancel"):
            self.g["output_dir_var"].set(str(self.base / "other"))
            self.assertEqual(after.call_args.args[0], 600)
            self.g["cancel_status_refresh"]()

    def test_missing_status_is_quiet_and_preserves_selections(self):
        self.select(2, 5)
        before = self.selection()
        self.g["auto_refresh_status"]()
        self.assertIsNone(self.g["loaded_history"])
        self.assertEqual(self.selection(), before)
        self.messages.showerror.assert_not_called()
        self.messages.showwarning.assert_not_called()

    def test_invalid_status_is_quiet_and_preserves_bytes_and_selections(self):
        path = self.output / "A_status.json"
        self.select(2, 5)
        before = self.selection()
        for text in ("{broken", '{"schema_version":2}'):
            path.write_text(text)
            original = path.read_bytes()
            self.g["auto_refresh_status"]()
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(self.selection(), before)
            self.assertIsNone(self.g["loaded_history"])
        self.messages.showerror.assert_not_called()

    def test_stale_auto_load_is_quiet_but_manual_refresh_still_warns(self):
        self.status(stale=True)
        with patch.dict(self.g, load_reconciled_status=ps.load_status):
            for _ in range(3):
                self.g["auto_refresh_status"]()
                self.assertEqual(self.selection(), [False, True, True, True, False])
            self.messages.showwarning.assert_not_called()
            self.g["load_accession_status"]()
        self.messages.showwarning.assert_called_once()

    def test_obsolete_or_locked_refresh_does_not_load(self):
        with patch.dict(self.g, load_reconciled_status=unittest.mock.MagicMock()) as namespace:
            self.g["auto_refresh_status"]((str(self.output), "different"))
            self.g["set_inputs_locked"](True)
            self.g["auto_refresh_status"]()
            namespace["load_reconciled_status"].assert_not_called()
        self.g["set_inputs_locked"](False)

    def test_save_buttons_use_local_preferences_and_handle_errors(self):
        path = self.base / "local-settings" / "settings.json"
        with patch.dict(self.g, settings_path=lambda: path):
            self.g["input_dir_var"].set(str(self.source))
            self.g["btn_default_input"].invoke()
            self.g["btn_default_output"].invoke()
            self.assertEqual(self.g["load_defaults"](), dict(input=str(self.source.resolve()),
                                                              output=str(self.output.resolve())))
            self.g["input_dir_var"].set(str(self.base / "absent"))
            self.g["btn_default_input"].invoke()
            self.messages.showerror.assert_called_once()
            self.assertFalse((self.output / "A_status.json").exists())
