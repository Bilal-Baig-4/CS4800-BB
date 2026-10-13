"""Exercise real Tk controls without starting mainloop or processing files."""
import ast
from pathlib import Path
import runpy
import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import patch


GUI_PATH = Path(__file__).resolve().parents[1] / "GUI.py"
SELECTIONS = ("run_ingest", "run_format_identification", "run_reports",
              "run_fixity_selected", "run_bagging")


class GuiStepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original_tk = tk.Tk

        def hidden_root():
            root = original_tk()
            root.withdraw()
            return root

        try:
            with patch.object(tk, "Tk", side_effect=hidden_root), \
                 patch.object(original_tk, "mainloop"):
                namespace = runpy.run_path(str(GUI_PATH))
        except tk.TclError as exc:
            raise unittest.SkipTest(f"Tk display unavailable: {exc}")
        cls.gui = namespace["run_pipeline"].__globals__
        cls.defaults = {name: cls.gui[name].get() for name in SELECTIONS}
        cls.addClassCleanup(cls.gui["root"].destroy)

    def setUp(self):
        g = self.gui
        g["set_inputs_locked"](False)
        for name in SELECTIONS:
            g[name].set(True)
        g["bag_profile_var"].set("aptrust")

    def assertState(self, name, state):
        self.assertEqual(str(self.gui[name].cget("state")), state)

    def test_five_selectors_and_defaults(self):
        g = self.gui
        for name in SELECTIONS:
            self.assertIsInstance(g[name], tk.BooleanVar)
            self.assertTrue(self.defaults[name])
        self.assertEqual(g["av_var"].get(), g["AV_AVAILABLE"])
        self.assertFalse(g["move_var"].get())
        self.assertEqual(g["bag_profile_var"].get(), "aptrust")
        self.assertTrue(g["serialize_tar_var"].get())
        self.assertFalse(g["validate_bag_var"].get())
        for name, label in zip(("chk_ingest", "chk_format", "chk_reports", "chk_fixity", "chk_bag"),
                               ("Ingest", "Format Identification", "Reports", "Fixity", "Bagging")):
            self.assertIn(label, g[name].cget("text"))
        self.assertEqual(g["run_button"].cget("text"), "Run Selected Steps")

    def test_ingest_toggle_preserves_options(self):
        g = self.gui
        original_av, original_move = g["av_var"].get(), g["move_var"].get()
        self.addCleanup(g["av_var"].set, original_av)
        self.addCleanup(g["move_var"].set, original_move)
        g["av_var"].set(True)
        g["move_var"].set(True)
        g["run_ingest"].set(False)
        self.assertState("chk_av", "disabled")
        self.assertState("chk_move", "disabled")
        g["run_ingest"].set(True)
        self.assertState("chk_move", "normal")
        self.assertState("chk_av", "normal" if g["AV_AVAILABLE"] else "disabled")
        self.assertTrue(g["av_var"].get())
        self.assertTrue(g["move_var"].get())

    def test_bagging_toggle_and_profiles_preserve_values(self):
        g = self.gui
        with patch.dict(g, BAGIT_AVAILABLE=True):
            original_title = g["bag_title_var"].get()
            self.addCleanup(g["bag_title_var"].set, original_title)
            g["bag_title_var"].set("Retained title")
            for profile in ("aptrust", "generic"):
                g["bag_profile_var"].set(profile)
                g["run_bagging"].set(False)
                for widget in g["bag_controls"]:
                    self.assertEqual(str(widget.cget("state")), "disabled")
                g["run_bagging"].set(True)
                for widget in g["bag_controls"]:
                    allowed = profile == "aptrust" or widget not in g["aptrust_only_controls"]
                    expected = ("readonly" if isinstance(widget, ttk.Combobox) else "normal") if allowed else "disabled"
                    self.assertEqual(str(widget.cget("state")), expected)
                for widget in g["aptrust_only_widgets"]:
                    self.assertEqual(bool(widget.winfo_manager()), profile == "aptrust")
            self.assertEqual(g["bag_title_var"].get(), "Retained title")
            self.assertTrue(g["serialize_tar_var"].get())

    def test_unlock_respects_parents_profiles_and_availability(self):
        g = self.gui
        for bag_available in (True, False):
            with patch.dict(g, BAGIT_AVAILABLE=bag_available, AV_AVAILABLE=False):
                g["run_ingest"].set(False)
                g["run_bagging"].set(False)
                g["set_inputs_locked"](True)
                for widget in g["lockable_inputs"]:
                    self.assertEqual(str(widget.cget("state")), "disabled")
                g["set_inputs_locked"](False)
                self.assertState("chk_move", "disabled")
                self.assertState("chk_av", "disabled")
                self.assertState("chk_bag", "normal" if bag_available else "disabled")
                for widget in g["bag_controls"]:
                    self.assertEqual(str(widget.cget("state")), "disabled")
                g["run_ingest"].set(True)
                self.assertState("chk_av", "disabled")
                g["run_bagging"].set(True)
                g["bag_profile_var"].set("generic")
                g["set_inputs_locked"](True)
                g["set_inputs_locked"](False)
                self.assertState("ent_title", "disabled")
                self.assertState("rb_generic", "normal" if bag_available else "disabled")

    def test_layout_fits_window_and_status_progress_work(self):
        g = self.gui
        root = g["root"]
        root.update_idletasks()
        width, height = map(int, root.geometry().split("+")[0].split("x"))
        self.assertLessEqual(root.winfo_reqwidth(), width)
        self.assertLessEqual(root.winfo_reqheight(), height)
        g["status_var"].set("Test status")
        self.assertEqual(g["status_var"].get(), "Test status")
        g["status_var"].set("Idle")
        g["progress_bar"].start(10)
        g["progress_bar"].stop()

class ExecutionBoundaryTests(unittest.TestCase):
    def test_execution_uses_selection_snapshot(self):
        tree = ast.parse(GUI_PATH.read_text(encoding="utf-8"))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        names = {node.id for node in ast.walk(functions["selected_run_options"])
                 if isinstance(node, ast.Name)}
        self.assertTrue(set(SELECTIONS) <= names)


if __name__ == "__main__":
    unittest.main()
