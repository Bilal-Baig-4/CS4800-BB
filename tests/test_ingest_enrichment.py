"""Independent ingest/enrichment contracts; no live FITS or Java needed."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from lxml import etree as ET
import pipeline
from test_premis import FITS, NS, ROOT


class IngestEnrichmentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "nested").mkdir()
        for name in ("nested/one.bin", "two.bin"):
            (self.source / name).write_bytes(name.encode())
            os.utime(self.source / name, (1600000000, 1600000000))
        self.out = self.base / "out"
        self.payload = self.out / "A"

    def ingest(self):
        with patch.object(pipeline, "configure_fits") as configure, \
             patch.object(pipeline, "identify_with_fits") as identify:
            self.xml = pipeline.ingest_accession(self.source, self.out, "A")
        configure.assert_not_called()
        identify.assert_not_called()
        return self.records()

    def records(self):
        return {f.get("name"): f for f in ET.parse(str(self.xml)).findall(".//d:file", NS)}

    def baseline(self):
        return {name: (dict(f.attrib), f.findtext(".//p:objectIdentifierValue", namespaces=NS),
                       ET.tostring(f.find(".//p:fixity", NS)),
                       f.findtext(".//p:size", namespaces=NS))
                for name, f in self.records().items()}

    def enrich(self, identify=None):
        with patch.object(pipeline, "configure_fits", return_value=("fits", "java")), \
             patch.object(pipeline, "identify_with_fits", side_effect=identify or
                          (lambda *args: ET.fromstring(FITS))) as mocked, \
             patch.object(pipeline.shutil, "copy2", side_effect=AssertionError("retransfer")), \
             patch.object(pipeline.shutil, "move", side_effect=AssertionError("retransfer")), \
             patch.object(pipeline, "compute_md5", side_effect=AssertionError("rehash")), \
             patch.object(pipeline.uuid, "uuid4", side_effect=AssertionError("new identity")):
            self.assertEqual(pipeline.enrich_accession_with_fits(self.payload, self.xml), self.xml)
        return mocked

    def test_ingest_without_fits_produces_usable_baseline(self):
        records = self.ingest()
        self.assertEqual(set(records), {"nested/one.bin", "two.bin"})
        for name, f in records.items():
            self.assertEqual((self.payload / name).read_bytes(), name.encode())
            self.assertEqual((self.payload / name).stat().st_mtime, 1600000000)
            uuid.UUID(f.findtext(".//p:objectIdentifierValue", namespaces=NS))
            self.assertEqual(f.get("MD5"), hashlib.md5(name.encode()).hexdigest())
            self.assertEqual(f.findtext(".//p:messageDigest", namespaces=NS), f.get("MD5"))
            self.assertIsNone(f.find(".//p:format", NS))
            self.assertIsNone(f.find(".//p:objectCharacteristicsExtension", NS))
        for ext in ("csv", "html"):
            pipeline.run_xslt_processor(self.xml, ROOT / f"files.{ext}.xslt", self.out / f"report.{ext}")
        pipeline.run_fixity(self.xml, self.out, "A")

    def test_enrichment_preserves_baseline_even_if_payload_changed(self):
        self.ingest()
        before = self.baseline()
        (self.payload / "two.bin").write_bytes(b"changed after ingest")
        (self.payload / "unlisted.bin").write_bytes(b"not in inventory")
        mocked = self.enrich()
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(self.baseline(), before)
        for f in self.records().values():
            self.assertEqual(f.findtext(".//p:formatRegistryKey", namespaces=NS), "fmt/18")

    def test_rerun_replaces_fits_and_preserves_unrelated_metadata(self):
        self.ingest()
        self.enrich()
        tree = ET.parse(str(self.xml))
        for f in tree.findall(".//d:file", NS):
            characteristics = f.find(".//p:objectCharacteristics", NS)
            manual = ET.SubElement(characteristics, f"{{{pipeline.PREMIS_NS}}}format")
            ET.SubElement(manual, f"{{{pipeline.PREMIS_NS}}}formatNote").text = "Manual description"
            extension = characteristics.find("p:objectCharacteristicsExtension", NS)
            ET.SubElement(extension, "{urn:local}note").text = "Keep this"
        tree.write(str(self.xml))
        before = self.baseline()

        def updated(*args):
            result = ET.fromstring(FITS)
            result[0][0].set("format", "Updated format")
            return result

        self.enrich(updated)
        self.enrich(updated)
        self.assertEqual(self.baseline(), before)
        for f in self.records().values():
            self.assertEqual(len(f.findall(".//p:format", NS)), 2)
            self.assertEqual(f.findtext(".//p:formatName", namespaces=NS), "Updated format")
            self.assertEqual(len(f.findall(f".//{{{pipeline.FITS_NS}}}fits")), 1)
            self.assertEqual(f.findtext(".//{urn:local}note"), "Keep this")

    def test_failure_retains_prior_enrichment_and_other_files_continue(self):
        self.ingest()
        self.enrich()
        before = self.baseline()
        old_failed = ET.tostring(self.records()["two.bin"])

        def identify(path, *args):
            if path.name == "two.bin":
                raise subprocess.TimeoutExpired("java", 300)
            result = ET.fromstring(FITS)
            result[0][0].set("format", "New identification")
            return result

        with self.assertLogs(level="WARNING") as logs:
            self.enrich(identify)
        self.assertTrue(any("FITS:TIMEOUT" in line for line in logs.output))
        self.assertEqual(self.baseline(), before)
        self.assertEqual(ET.tostring(self.records()["two.bin"]), old_failed)
        self.assertEqual(self.records()["nested/one.bin"].findtext(".//p:formatName", namespaces=NS),
                         "New identification")

    def test_unavailable_fits_leaves_xml_unchanged(self):
        self.ingest()
        before = self.xml.read_bytes()
        with patch.object(pipeline, "configure_fits", return_value=None), \
             patch.object(pipeline, "identify_with_fits") as identify:
            pipeline.enrich_accession_with_fits(self.payload, self.xml)
        identify.assert_not_called()
        self.assertEqual(self.xml.read_bytes(), before)

    def test_failed_save_preserves_existing_xml(self):
        self.ingest()
        before = self.xml.read_bytes()
        with patch.object(pipeline.os, "replace", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                self.enrich()
        self.assertEqual(self.xml.read_bytes(), before)
        self.assertEqual(list(self.out.glob("*.tmp")), [])
