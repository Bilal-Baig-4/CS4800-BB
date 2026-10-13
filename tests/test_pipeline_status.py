"""Status persistence tests without pipeline, Java or GUI dependencies."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pipeline_state import status as ps


class StatusTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name) / "output"
        self.status = ps.create_status(self.output, "A")
        self.path = self.output / "A_status.json"

    def test_create_identity_location_and_defaults(self):
        self.assertTrue(self.path.is_file())
        self.assertFalse((self.output / "A").exists())
        self.assertEqual(self.status["accession_number"], "A")
        self.assertEqual(self.status["accession_path"], "A")
        self.assertEqual(self.status["schema_version"], 1)
        self.assertEqual(self.status["revision"], 1)
        self.assertEqual(self.status["layout"], "unbagged")
        self.assertEqual(set(self.status["steps"]), set(ps.STAGE_IDS))
        self.assertEqual(len(ps.STAGE_IDS), 9)
        for step in self.status["steps"].values():
            self.assertEqual(step, dict(
                state="not_started", outcome=None, attempt=0,
                started_at=None, finished_at=None,
                freshness=dict(state="unverified", checked_at=None, method="none", reasons=[]),
                settings={}, inputs={}, outputs={}, evidence={}, result={}))
        self.status["steps"]["fits"]["result"]["x"] = 1
        self.assertEqual(self.status["steps"]["ingest"]["result"], {})

    def test_load_valid(self):
        self.assertEqual(ps.load_status(self.output, "A"), self.status)

    def test_save_revision_and_no_input_mutation(self):
        saved = ps.save_status(self.output, "A", self.status)
        self.assertEqual(saved["revision"], 2)
        self.assertEqual(self.status["revision"], 1)
        self.assertEqual(saved["created_at"], self.status["created_at"])
        self.assertEqual(ps.save_status(self.output, "A", saved)["revision"], 3)
        with self.assertRaises(ps.StatusValidationError):
            ps.save_status(self.output, "A", self.status)

    def test_missing_distinct_from_malformed(self):
        with self.assertRaises(FileNotFoundError):
            ps.load_status(self.output, "missing")
        self.assertFalse((self.output / "missing_status.json").exists())
        self.path.write_text("{broken", encoding="utf-8")
        for action in (lambda: ps.load_status(self.output, "A"),
                       lambda: ps.save_status(self.output, "A", self.status)):
            with self.assertRaises(ps.StatusValidationError):
                action()
            self.assertEqual(self.path.read_text(), "{broken")

    def test_create_refuses_existing(self):
        self.path.write_text("broken")
        with self.assertRaises(FileExistsError):
            ps.create_status(self.output, "A")
        self.assertEqual(self.path.read_text(), "broken")

    def test_newer_schema_load_and_write_rejected(self):
        newer = deepcopy(self.status)
        newer["schema_version"] = 2
        self.path.write_text(json.dumps(newer))
        before = self.path.read_bytes()
        for action in (lambda: ps.load_status(self.output, "A"),
                       lambda: ps.save_status(self.output, "A", self.status),
                       lambda: ps.save_status(self.output, "A", newer)):
            with self.assertRaises(ps.UnsupportedSchemaError):
                action()
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_schema_fields(self):
        mutations = [
            lambda s: s.pop("created_at"),
            lambda s: s.update(revision=True),
            lambda s: s.update(revision=0),
            lambda s: s.update(revision=1.5),
            lambda s: s.update(schema_version=False),
            lambda s: s.update(layout="bad"),
            lambda s: s.update(created_at="bad"),
            lambda s: s["steps"].pop("fits"),
            lambda s: s["steps"]["fits"].update(state="completed_with_warnings"),
            lambda s: s["steps"]["fits"].update(attempt=-1),
            lambda s: s["steps"]["fits"].update(outcome="bad\nvalue"),
            lambda s: s["steps"]["fits"].update(outcome=5),
            lambda s: s["steps"]["fits"].update(result=[]),
            lambda s: s["steps"]["fits"]["freshness"].update(state="bad"),
            lambda s: s["steps"]["fits"]["freshness"].update(reasons=[1]),
            lambda s: s["steps"]["fits"]["freshness"].pop("method"),
        ]
        before = self.path.read_bytes()
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                invalid = deepcopy(self.status)
                mutate(invalid)
                with self.assertRaises(ps.StatusValidationError):
                    ps.save_status(self.output, "A", invalid)
                self.assertEqual(self.path.read_bytes(), before)
                self.path.write_text(json.dumps(invalid))
                with self.assertRaises(ps.StatusValidationError):
                    ps.load_status(self.output, "A")
                self.path.write_bytes(before)

    def test_unsafe_accessions(self):
        for accession in ("", ".", "..", "../A", "A/other", "A\\other", "/A",
                          "C:\\A", "A..B", "A:", "A\n", "NUL", " A", "A.", None):
            for action in (ps.create_status, ps.load_status,
                           lambda o, a: ps.save_status(o, a, self.status)):
                with self.subTest(accession=accession, action=action):
                    with self.assertRaises(ps.StatusValidationError):
                        action(self.output, accession)

    def test_embedded_identity_mismatch(self):
        for field in ("accession_number", "accession_path"):
            invalid = deepcopy(self.status)
            invalid[field] = "B"
            self.path.write_text(json.dumps(invalid))
            with self.assertRaises(ps.StatusValidationError):
                ps.load_status(self.output, "A")

    def test_unknown_fields_preserved(self):
        self.status["extension"] = {"unicode": "caf\u00e9"}
        self.status["steps"]["fits"]["extension"] = [1, 2]
        self.status["steps"]["fits"]["freshness"]["extension"] = True
        saved = ps.save_status(self.output, "A", self.status)
        self.assertEqual(ps.load_status(self.output, "A"), saved)
        self.assertEqual(saved["extension"], self.status["extension"])
        self.assertEqual(saved["steps"], self.status["steps"])

    def test_execution_outcome_and_freshness_independent(self):
        for state in ps.STATES:
            for fresh in ps.FRESHNESS_STATES:
                self.status["steps"]["fits"].update(state=state, outcome="generated")
                self.status["steps"]["fits"]["freshness"]["state"] = fresh
                self.status = ps.save_status(self.output, "A", self.status)
                self.assertEqual(ps.load_status(self.output, "A"), self.status)

    def test_atomic_failure_preserves_previous_and_cleans_temp(self):
        for operation in ("fsync", "replace"):
            before = self.path.read_bytes()
            with patch.object(ps.os, operation, side_effect=OSError("simulated failure")):
                with self.assertRaises(OSError):
                    ps.save_status(self.output, "A", self.status)
            self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(list(self.output.iterdir()), [self.path])
            self.assertEqual(self.status["revision"], 1)

    def test_serialization_failure_preserves_previous(self):
        self.status["steps"]["fits"]["result"]["bad"] = object()
        before = self.path.read_bytes()
        with self.assertRaises(ps.StatusValidationError):
            ps.save_status(self.output, "A", self.status)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.output.iterdir()), [self.path])


if __name__ == "__main__":
    unittest.main()
