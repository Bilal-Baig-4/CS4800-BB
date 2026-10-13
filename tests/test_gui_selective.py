"""Selective GUI orchestration with real Tk controls and mocked processing."""
from pathlib import Path
import runpy
import tempfile
import tkinter as tk
import unittest
from unittest.mock import MagicMock, patch

import pipeline
from test_gui_steps import GUI_PATH, SELECTIONS


class SelectiveExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original_tk = tk.Tk

        def hidden_root():
            root = original_tk()
            root.withdraw()
            return root

        try:
            with patch.object(tk, "Tk", side_effect=hidden_root), patch.object(original_tk, "mainloop"):
                namespace = runpy.run_path(str(GUI_PATH))
        except tk.TclError as exc:
            raise unittest.SkipTest(f"Tk display unavailable: {exc}")
        cls.g = namespace["run_pipeline"].__globals__
        cls.addClassCleanup(cls.g["root"].destroy)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.output = self.base / "output"
        self.payload = self.output / "A"
        self.payload.mkdir(parents=True)
        self.xml = self.output / "A.xml"
        self.write_inventory()
        self.source = self.base / "source"
        self.source.mkdir()
        g = self.g
        g["set_inputs_locked"](False)
        g["rerun_completed_var"].set(False)
        for name in SELECTIONS:
            g[name].set(False)
        settings = dict(input_dir_var="", output_dir_var=str(self.output), accession_var="A",
                        av_var=True, move_var=False, bag_profile_var="aptrust",
                        bag_title_var="Collection", source_org_var="Archives",
                        bag_access_var="Institution", bag_storage_var="Standard",
                        contact_name_var="", contact_email_var="", bag_desc_var="",
                        validate_bag_var=False, serialize_tar_var=True)
        for name, value in settings.items():
            g[name].set(value)
        self.calls = MagicMock()
        functions = ("run_antivirus_scan", "ingest_accession", "enrich_accession_with_fits",
                     "run_xslt_processor", "generate_summary_report", "run_fixity",
                     "construct_bag", "validate_bag", "serialize_bag_to_tar")
        self.processing = {name: getattr(self.calls, name) for name in functions}
        self.messages = MagicMock()
        self.messages.askyesno.return_value = True
        self.processing.update(messagebox=self.messages, logging=MagicMock(), BAGIT_AVAILABLE=True)
        self.calls.run_antivirus_scan.return_value = (set(), {}, False)
        self.calls.ingest_accession.side_effect = self.fake_ingest
        self.calls.construct_bag.return_value = self.payload
        self.calls.validate_bag.return_value = (True, "")
        self.calls.serialize_bag_to_tar.return_value = self.output / "A.tar"
        self.addCleanup(patch.stopall)
        patch.dict(g, self.processing).start()
        patch.object(pipeline, "AV_AVAILABLE", True).start()

    def write_inventory(self):
        (self.payload / "item.bin").write_bytes(b"payload")
        self.xml.write_text('''<collection xmlns="http://dataaccessioner.org/schema/dda-1-1"
            xmlns:p="info:lc/xmlns/premis-v2"><accession number="A">
            <file name="item.bin" MD5="321c3cf486ed509164edec1e1981fec8" size="7">
              <p:object><p:objectCharacteristics/></p:object>
            </file></accession></collection>''', encoding="utf-8")

    def fake_ingest(self, *args, **kwargs):
        self.payload.mkdir(parents=True, exist_ok=True)
        self.write_inventory()
        return self.xml

    def select(self, *numbers):
        for index, variable in enumerate(SELECTIONS, 1):
            self.g[variable].set(index in numbers)

    def execute(self, *numbers):
        self.select(*numbers)
        self.g["run_pipeline"]()

    def assertOperations(self, *names):
        self.assertEqual([call[0] for call in self.calls.mock_calls], list(names))

    def assertRejected(self, *numbers, detail=None):
        self.execute(*numbers)
        self.assertOperations()
        self.messages.showerror.assert_called_once()
        self.messages.showinfo.assert_not_called()
        if detail:
            self.assertIn(detail, self.messages.showerror.call_args.args[1])

    def existing_bag(self, aptrust=True):
        (self.payload / "data").mkdir()
        for name in ("bagit.txt", "bag-info.txt", "manifest-md5.txt"):
            (self.payload / name).write_text("fixture")
        if aptrust:
            (self.payload / "aptrust-info.txt").write_text("fixture")

    def test_only_ingest_with_optional_av_and_move(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["move_var"].set(True)
        self.execute(1)
        self.assertOperations("run_antivirus_scan", "ingest_accession")
        self.assertTrue(self.calls.ingest_accession.call_args.kwargs["move_files"])
        self.messages.showinfo.assert_called_once()

    def test_ingest_without_antivirus(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["av_var"].set(False)
        self.execute(1)
        self.assertOperations("ingest_accession")

    def test_ingest_defender_unavailable_warns_and_continues(self):
        self.g["input_dir_var"].set(str(self.source))
        with patch.object(pipeline, "AV_AVAILABLE", False):
            self.execute(1)
        self.assertOperations("ingest_accession")
        self.messages.showwarning.assert_called_once()

    def test_defender_detections_preserve_exclusion_and_cancel(self):
        self.g["input_dir_var"].set(str(self.source))
        clean = {self.source / "clean.bin"}
        infected = {self.source / "infected.bin": "test detection"}
        self.calls.run_antivirus_scan.return_value = (clean, infected, False)
        self.execute(1)
        self.assertEqual(self.calls.ingest_accession.call_args.kwargs["clean_files_only"], clean)
        self.calls.reset_mock()
        self.messages.askyesno.return_value = False
        (self.output / "A_status.json").unlink(missing_ok=True)
        self.execute(1, 2, 3)
        self.assertOperations("run_antivirus_scan")

    def test_only_fits_existing_artifacts_no_source_required(self):
        self.execute(2)
        self.assertOperations("enrich_accession_with_fits")
        self.assertEqual(self.calls.enrich_accession_with_fits.call_args.args, (self.payload, self.xml))

    def test_only_reports(self):
        self.execute(3)
        self.assertOperations("run_xslt_processor", "run_xslt_processor", "generate_summary_report")
        transforms = self.calls.run_xslt_processor.call_args_list
        self.assertEqual([call.args[1].name for call in transforms], ["files.csv.xslt", "files.html.xslt"])

    def test_only_fixity(self):
        self.execute(4)
        self.assertOperations("run_fixity")

    def test_bagging_options_and_profile_policy(self):
        for profile in ("aptrust", "generic"):
            for validate in (False, True):
                for tar in (False, True):
                    with self.subTest(profile=profile, validate=validate, tar=tar):
                        (self.output / "A_status.json").unlink(missing_ok=True)
                        self.calls.reset_mock()
                        self.g["bag_profile_var"].set(profile)
                        self.g["validate_bag_var"].set(validate)
                        self.g["serialize_tar_var"].set(tar)
                        self.execute(5)
                        expected = ["construct_bag"]
                        if validate:
                            expected.append("validate_bag")
                        if tar and profile == "aptrust":
                            expected.append("serialize_bag_to_tar")
                        self.assertOperations(*expected)
                        self.assertEqual(self.calls.construct_bag.call_args.kwargs["xml_manifest"], self.xml)

    def test_ingest_and_reports_without_fits(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["av_var"].set(False)
        self.xml.unlink()
        (self.payload / "item.bin").unlink()
        self.payload.rmdir()
        self.execute(1, 3)
        self.assertOperations("ingest_accession", "run_xslt_processor", "run_xslt_processor", "generate_summary_report")

    def test_fits_and_fixity(self):
        self.execute(2, 4)
        self.assertOperations("enrich_accession_with_fits", "run_fixity")

    def test_all_steps_run_in_order(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["validate_bag_var"].set(True)
        self.execute(1, 2, 3, 4, 5)
        self.assertOperations("run_antivirus_scan", "ingest_accession", "enrich_accession_with_fits",
                              "run_xslt_processor", "run_xslt_processor", "generate_summary_report",
                              "run_fixity", "construct_bag", "validate_bag", "serialize_bag_to_tar")

    def test_no_steps_rejected_before_starting_thread(self):
        with patch.object(self.g["threading"], "Thread") as thread:
            self.g["start_pipeline"]()
        thread.assert_not_called()
        self.messages.showerror.assert_called_once()
        self.assertIn("at least one", self.messages.showerror.call_args.args[1])
        self.assertOperations()

    def test_fits_missing_xml(self):
        self.xml.unlink()
        self.assertRejected(2, detail="XML")

    def test_fits_missing_payload(self):
        (self.payload / "item.bin").unlink()
        self.payload.rmdir()
        self.assertRejected(2, detail="payload")

    def test_reports_missing_xml(self):
        self.xml.unlink()
        self.assertRejected(3, detail="XML")

    def test_fixity_missing_baseline_and_payload(self):
        self.xml.unlink()
        self.assertRejected(4, detail="XML")
        self.messages.reset_mock()
        self.write_inventory()
        (self.payload / "item.bin").unlink()
        self.payload.rmdir()
        self.assertRejected(4, detail="payload")

    def test_bagging_missing_payload(self):
        (self.payload / "item.bin").unlink()
        self.payload.rmdir()
        self.assertRejected(5, detail="payload")

    def test_bag_construction_preflight_failure_stops_validation_tar(self):
        self.g["validate_bag_var"].set(True)
        self.calls.construct_bag.side_effect = ValueError("Payload differs from XML baseline")
        self.execute(5)
        self.assertOperations("construct_bag")
        self.messages.showerror.assert_called_once()
        self.assertIn("baseline", self.messages.showerror.call_args.args[1])

    def test_failed_validation_blocks_tar(self):
        self.g["validate_bag_var"].set(True)
        self.calls.validate_bag.return_value = (False, "checksum mismatch")
        self.execute(5)
        self.assertOperations("construct_bag", "validate_bag")
        self.messages.showerror.assert_called_once()
        self.messages.showinfo.assert_not_called()
        self.assertIn("TAR serialization blocked", self.messages.showerror.call_args.args[1])

    def test_input_required_only_for_ingest(self):
        self.assertRejected(1, detail="Input Directory")

    def test_early_metadata_validation_only_for_construction(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["bag_title_var"].set("")
        self.assertRejected(1, 5, detail="Title")
        self.messages.reset_mock()
        self.execute(3)
        self.messages.showerror.assert_not_called()

    def test_existing_bag_validates_serializes_without_reconstruction(self):
        self.existing_bag()
        self.g["validate_bag_var"].set(True)
        self.g["bag_title_var"].set("")
        self.g["source_org_var"].set("")
        self.execute(5)
        self.assertOperations("validate_bag", "serialize_bag_to_tar")

    def test_existing_bag_construction_only_rejected(self):
        self.existing_bag()
        self.g["serialize_tar_var"].set(False)
        self.assertRejected(5, detail="cannot be reconstructed")

    def test_existing_generic_bag_validation_only(self):
        self.existing_bag(aptrust=False)
        self.g["bag_profile_var"].set("generic")
        self.g["validate_bag_var"].set(True)
        self.execute(5)
        self.assertOperations("validate_bag")

    def test_bagged_and_ambiguous_layouts_rejected_for_fits_fixity(self):
        (self.payload / "data").mkdir()
        for step in (2, 4, 5):
            with self.subTest(step=step):
                self.messages.reset_mock()
                self.assertRejected(step, detail="BagIt")
        self.existing_bag_files()
        for step in (2, 4):
            self.messages.reset_mock()
            self.assertRejected(step, detail="unbagged")

    def existing_bag_files(self):
        for name in ("bagit.txt", "bag-info.txt", "manifest-md5.txt"):
            (self.payload / name).write_text("fixture")

    def test_reports_can_run_with_bagged_payload(self):
        self.existing_bag()
        self.execute(3)
        self.assertOperations("run_xslt_processor", "run_xslt_processor", "generate_summary_report")

    def test_csv_and_html_errors_stop_summary_and_later_steps(self):
        for failing_index in (0, 1):
            self.calls.reset_mock()
            self.messages.reset_mock()
            self.calls.run_xslt_processor.side_effect = ([OSError("CSV failed")] if failing_index == 0
                                                       else [self.output / "A_files.csv", OSError("HTML failed")])
            self.execute(3, 4, 5)
            self.assertOperations(*(["run_xslt_processor"] * (failing_index + 1)))
            self.messages.showerror.assert_called_once()
            self.messages.showinfo.assert_not_called()

    def test_ingest_failure_stops_later_selected_steps(self):
        self.g["input_dir_var"].set(str(self.source))
        self.g["av_var"].set(False)
        self.calls.ingest_accession.side_effect = OSError("copy failed")
        self.execute(1, 2, 3, 4, 5)
        self.assertOperations("ingest_accession")
        self.messages.showerror.assert_called_once()

    def test_invalid_xml_identity_and_unsafe_baseline_rejected(self):
        for step, text in ((3, "<broken"), (3, self.xml.read_text().replace('number="A"', 'number="B"')),
                           (4, self.xml.read_text().replace('name="item.bin"', 'name="../outside"'))):
            with self.subTest(step=step):
                self.messages.reset_mock()
                self.xml.write_text(text)
                self.assertRejected(step)

    def test_output_accession_and_stylesheets_validated_early(self):
        for value in ("", "../escape", "C:\\absolute", "A/child", "NUL"):
            self.g["accession_var"].set(value)
            self.messages.reset_mock()
            self.assertRejected(3)
        self.g["accession_var"].set("A")
        self.g["output_dir_var"].set("")
        self.messages.reset_mock()
        self.assertRejected(3, detail="Output Directory")
        self.g["output_dir_var"].set(str(self.output))
        self.messages.reset_mock()
        with patch.dict(self.g, __file__=str(self.base / "GUI.py")):
            self.assertRejected(3, detail="stylesheet")

    def test_bag_without_xml_uses_explicit_fresh_hashing(self):
        self.xml.unlink()
        self.execute(5)
        self.assertOperations("construct_bag", "serialize_bag_to_tar")
        self.assertIsNone(self.calls.construct_bag.call_args.kwargs["xml_manifest"])

    def test_snapshot_locking_and_restore_after_worker(self):
        self.select(4)
        g = self.g
        with patch.object(g["threading"], "Thread") as thread:
            g["start_pipeline"]()
        self.assertTrue(g["inputs_locked"])
        for widget in g["lockable_inputs"]:
            self.assertEqual(str(widget.cget("state")), "disabled")
        options = thread.call_args.kwargs["args"][0]
        self.assertTrue(options["steps"]["fixity"])
        self.assertEqual(g["run_button"].cget("state"), "disabled")
        g["run_pipeline"](options)
        self.assertFalse(g["inputs_locked"])
        self.assertEqual(g["chk_move"].cget("state"), "disabled")
        self.assertEqual(g["rb_aptrust"].cget("state"), "disabled")
        self.assertEqual(g["run_button"].cget("state"), "normal")

    def test_failure_unlock_restores_profile_and_parent_rules(self):
        self.select(5)
        self.g["bag_profile_var"].set("generic")
        self.g["set_inputs_locked"](True)
        self.calls.construct_bag.side_effect = OSError("failed")
        self.g["run_pipeline"]()
        self.assertFalse(self.g["inputs_locked"])
        self.assertEqual(self.g["chk_move"].cget("state"), "disabled")
        self.assertEqual(self.g["rb_generic"].cget("state"), "normal")
        self.assertEqual(self.g["ent_title"].cget("state"), "disabled")
        self.assertEqual(self.g["run_button"].cget("state"), "normal")

    def test_managed_status_sidecar_created(self):
        self.execute(2, 3, 4)
        self.assertTrue((self.output / "A_status.json").exists())


if __name__ == "__main__":
    unittest.main()
