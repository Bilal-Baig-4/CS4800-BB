"""Local packaging boundary tests; no Java, APTrust network or services."""
from pathlib import Path
import hashlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from lxml import etree as ET
import pipeline


@unittest.skipUnless(pipeline.BAGIT_AVAILABLE, "bagit is not installed")
class PackagingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "A"
        (self.root / "folder").mkdir(parents=True)
        (self.root / "folder/file.txt").write_bytes(b"original payload")
        (self.root / "another.bin").write_bytes(b"second file")
        self.xml = self.base / "A.xml"
        ns = "http://dataaccessioner.org/schema/dda-1-1"
        collection = ET.Element(f"{{{ns}}}collection", nsmap={None: ns})
        accession = ET.SubElement(collection, f"{{{ns}}}accession", number="A")
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                ET.SubElement(accession, f"{{{ns}}}file",
                              name=path.relative_to(self.root).as_posix(),
                              MD5=hashlib.md5(path.read_bytes()).hexdigest())
        ET.ElementTree(collection).write(str(self.xml))

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes() if p.is_file() else None
                for p in self.root.rglob("*")}

    def construct(self, **kwargs):
        return pipeline.construct_bag(self.root, "A", xml_manifest=self.xml, **kwargs)

    def assert_rejected_unchanged(self, **kwargs):
        before = self.snapshot()
        xml_before = self.xml.read_bytes()
        with self.assertRaises((ValueError, OSError)):
            self.construct(**kwargs)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.xml.read_bytes(), xml_before)

    def aptrust(self):
        return dict(profile="aptrust", title="Collection", source_organization="Archives",
                    description="Description", access="Institution", storage_option="Standard")

    def test_generic_construction_only_and_xml_unchanged(self):
        before_xml = self.xml.read_bytes()
        before = self.snapshot()
        with patch.object(pipeline, "validate_bag", side_effect=AssertionError("validation")), \
             patch.object(pipeline, "serialize_bag_to_tar", side_effect=AssertionError("serialization")):
            self.assertEqual(self.construct(), self.root.resolve())
        for name in ("bagit.txt", "bag-info.txt", "manifest-md5.txt", "tagmanifest-md5.txt"):
            self.assertTrue((self.root / name).is_file())
        for rel, content in before.items():
            if content is not None:
                self.assertEqual((self.root / "data" / rel).read_bytes(), content)
                self.assertFalse((self.root / rel).exists())
                expected = hashlib.md5(content).hexdigest() + "  data/" + rel
                self.assertIn(expected, (self.root / "manifest-md5.txt").read_text())
        self.assertEqual(self.xml.read_bytes(), before_xml)
        self.assertFalse((self.base / "A.tar").exists())

    def test_aptrust_metadata_and_tag_checksums(self):
        self.construct(**self.aptrust())
        info = (self.root / "aptrust-info.txt").read_text()
        for expected in ("Title: Collection", "Access: Institution", "Storage-Option: Standard",
                         "Description: Description"):
            self.assertIn(expected, info)
        self.assertIn(pipeline.APTRUST_PROFILE_IDENTIFIER, (self.root / "bag-info.txt").read_text())
        tags = (self.root / "tagmanifest-md5.txt").read_text()
        for name in ("bagit.txt", "bag-info.txt", "manifest-md5.txt", "aptrust-info.txt"):
            self.assertIn(hashlib.md5((self.root / name).read_bytes()).hexdigest() + "  " + name, tags)
        self.assertEqual(pipeline.validate_bag(self.root), (True, ""))

    def test_invalid_settings_rejected_before_mutation(self):
        for field, value in (("title", ""), ("source_organization", " "), ("access", "invalid"),
                             ("storage_option", "invalid"), ("title", "Injected\nTag: value")):
            with self.subTest(field=field):
                options = self.aptrust()
                options[field] = value
                self.assert_rejected_unchanged(**options)
        self.assert_rejected_unchanged(profile="unknown")

    def test_existing_bag_rerun_rejected_without_changes(self):
        self.construct(**self.aptrust())
        self.assert_rejected_unchanged(**self.aptrust())
        self.assertFalse((self.root / "data/bagit.txt").exists())
        self.assertEqual(pipeline.validate_bag(self.root), (True, ""))

    def test_ambiguous_data_directory_rejected(self):
        (self.root / "data").mkdir()
        (self.root / "data/original.txt").write_bytes(b"must not flatten")
        self.assert_rejected_unchanged()

    def test_existing_indicators_including_data_file_rejected(self):
        for name in ("data", "DATA", "bagit.txt", "bag-info.txt", "aptrust-info.txt",
                     "manifest-sha256.txt", "tagmanifest-sha512.txt", "fetch.txt"):
            with self.subTest(name=name):
                marker = self.root / name
                marker.write_bytes(b"original")
                self.assert_rejected_unchanged()
                marker.unlink()

    def test_md5_mismatch_rejected_before_movement(self):
        (self.root / "folder/file.txt").write_bytes(b"changed")
        self.assert_rejected_unchanged()

    def test_missing_baseline_file_rejected(self):
        (self.root / "another.bin").unlink()
        self.assert_rejected_unchanged()

    def test_extra_payload_file_rejected(self):
        (self.root / "extra.txt").write_bytes(b"unexpected")
        self.assert_rejected_unchanged()

    def test_unreadable_or_malformed_baseline_has_no_fallback(self):
        self.xml.write_text("not XML")
        self.assert_rejected_unchanged()
        self.xml.unlink()
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.construct()
        self.assertEqual(self.snapshot(), before)

    def test_invalid_duplicate_and_unsafe_inventory_entries_rejected(self):
        original = self.xml.read_bytes()
        for mode in ("duplicate", "digest", "path"):
            with self.subTest(mode=mode):
                tree = ET.fromstring(original)
                record = tree[0][0]
                if mode == "duplicate":
                    tree[0].append(ET.fromstring(ET.tostring(record)))
                elif mode == "digest":
                    record.set("MD5", "bad digest")
                else:
                    record.set("name", "../outside.txt")
                self.xml.write_bytes(ET.tostring(tree))
                self.assert_rejected_unchanged()

    def test_no_baseline_hashes_current_payload(self):
        (self.root / "extra.txt").write_bytes(b"explicitly included without baseline")
        pipeline.construct_bag(self.root, "A")
        self.assertEqual(pipeline.validate_bag(self.root), (True, ""))
        self.assertIn("data/extra.txt", (self.root / "manifest-md5.txt").read_text())

    def test_missing_or_nondirectory_root_rejected(self):
        for path in (self.base / "missing", self.root / "another.bin"):
            with self.subTest(path=path):
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    pipeline.construct_bag(path, "A")
                self.assertEqual(self.snapshot(), before)

    def test_independent_repeated_validation_does_not_reconstruct(self):
        self.construct()
        before = self.snapshot()
        with patch.object(pipeline, "construct_bag", side_effect=AssertionError("rebuild")), \
             patch.object(pipeline.shutil, "move", side_effect=AssertionError("move")):
            self.assertEqual(pipeline.validate_bag(self.root), (True, ""))
            self.assertEqual(pipeline.validate_bag(self.root), (True, ""))
        self.assertEqual(self.snapshot(), before)
        (self.root / "data/another.bin").write_bytes(b"damage")
        valid, error = pipeline.validate_bag(self.root)
        self.assertFalse(valid)
        self.assertTrue(error)

    def test_independent_tar_contains_bag_and_leaves_it_unchanged(self):
        self.construct()
        before = self.snapshot()
        with patch.object(pipeline, "construct_bag", side_effect=AssertionError("rebuild")), \
             patch.object(pipeline, "validate_bag", side_effect=AssertionError("validate")), \
             patch.object(pipeline.shutil, "move", side_effect=AssertionError("move")):
            path = pipeline.serialize_bag_to_tar(self.root)
            pipeline.serialize_bag_to_tar(self.root)
        self.assertEqual(path, self.base / "A.tar")
        self.assertEqual(self.snapshot(), before)
        with tarfile.open(path) as archive:
            self.assertIn("A/bagit.txt", archive.getnames())
            self.assertEqual(archive.extractfile("A/data/folder/file.txt").read(), b"original payload")
            self.assertNotIn("A.xml", archive.getnames())

    def test_failed_tar_write_and_replace_preserve_previous_deliverable(self):
        self.construct()
        path = pipeline.serialize_bag_to_tar(self.root)
        before = path.read_bytes()
        for target, attribute in ((pipeline.tarfile.TarFile, "add"), (pipeline.os, "replace")):
            with self.subTest(attribute=attribute):
                with patch.object(target, attribute, side_effect=OSError("injected failure")):
                    with self.assertLogs(level="ERROR"), self.assertRaises(OSError):
                        pipeline.serialize_bag_to_tar(self.root)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(list(self.base.glob("A.tar.*.tmp")), [])

    def test_tar_rejects_unbagged_directory(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            pipeline.serialize_bag_to_tar(self.root)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.base / "A.tar").exists())

    def test_requested_validation_failure_blocks_tar(self):
        with patch.object(pipeline, "validate_bag", return_value=(False, "invalid bag")), \
             patch.object(pipeline, "serialize_bag_to_tar") as serialize:
            with self.assertLogs(level="WARNING"):
                result = pipeline.create_bag(self.root, "A", validate=True, serialize_tar=True,
                                             xml_manifest=self.xml, **self.aptrust())
        serialize.assert_not_called()
        self.assertEqual(result, (self.root.resolve(), None, False, "invalid bag"))

    def test_compatibility_wrapper_success(self):
        root, tar, valid, error = pipeline.create_bag(
            self.root, "A", validate=True, serialize_tar=True, xml_manifest=self.xml, **self.aptrust())
        self.assertEqual(root, self.root.resolve())
        self.assertEqual(tar, self.base / "A.tar")
        self.assertTrue(tar.is_file())
        self.assertTrue(valid)
        self.assertEqual(error, "")

    def test_wrapper_without_validation_still_serializes_aptrust(self):
        with patch.object(pipeline, "validate_bag", side_effect=AssertionError("validation not requested")):
            root, tar, valid, error = pipeline.create_bag(
                self.root, "A", serialize_tar=True, xml_manifest=self.xml, **self.aptrust())
        self.assertTrue(tar.is_file())
        self.assertIsNone(valid)
        self.assertEqual(error, "")

    def test_wrapper_generic_does_not_serialize_and_missing_dependency_compatible(self):
        result = pipeline.create_bag(self.root, "A", serialize_tar=True, xml_manifest=self.xml)
        self.assertEqual(result, (self.root.resolve(), None, None, ""))
        with patch.object(pipeline, "BAGIT_AVAILABLE", False):
            result = pipeline.create_bag(self.root, "A")
        self.assertEqual(result, (None, None, False, "bagit-python is not installed."))

    def test_move_failure_is_reported_and_partial_rerun_rejected(self):
        move = pipeline.shutil.move
        calls = 0

        def fail_second(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected move failure")
            return move(*args)

        with patch.object(pipeline.shutil, "move", side_effect=fail_second):
            with self.assertLogs(level="ERROR") as logs, self.assertRaises(OSError):
                self.construct()
        self.assertTrue(any("partially modified" in message for message in logs.output))
        self.assertTrue((self.root / "data/another.bin").is_file())
        self.assertTrue((self.root / "folder/file.txt").is_file())
        self.assertFalse((self.root / "bagit.txt").exists())
        self.assert_rejected_unchanged()


if __name__ == "__main__":
    unittest.main()
