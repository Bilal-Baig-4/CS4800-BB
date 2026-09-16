"""Run with python -m unittest discover -s tests -v.

The inline FITS XML is a synthetic schema fixture, not a live tool result.
Set PIPELINE_TEST_FITS_HOME to also run real PDF identification with FITS.
"""
import csv
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid
from contextlib import nullcontext

from lxml import etree as ET
import pipeline

ROOT = Path(__file__).resolve().parents[1]
NS = {"d": "http://dataaccessioner.org/schema/dda-1-1", "p": pipeline.PREMIS_NS}
FITS = b'''<fits xmlns="http://hul.harvard.edu/ois/xml/ns/fits/fits_output">
  <identification><identity format="Portable Document Format" mimetype="application/pdf">
    <tool toolname="Droid" toolversion="6"/><tool toolname="Jhove" toolversion="1"/>
    <version>1.4</version><externalIdentifier toolname="Droid" type="puid">fmt/18</externalIdentifier>
  </identity></identification>
  <fileinfo><size>123</size></fileinfo><metadata><document><pageCount>1</pageCount></document></metadata>
</fits>'''


def pdf_bytes():
    """A small valid PDF 1.4, generated independently of its filename."""
    data = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
    ], 1):
        offsets.append(len(data))
        data += str(number).encode() + b" 0 obj\n" + body + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 4\n0000000000 65535 f \n"
    for offset in offsets:
        data += f"{offset:010d} 00000 n \n".encode()
    return data + f"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()


class PremisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "nested").mkdir()
        self.file = self.source / "nested" / "document.bin"
        self.file.write_bytes(pdf_bytes())
        os.utime(self.file, (1600000000, 1600000000))
        self.output = self.base / "out"

    def reports(self, **kwargs):
        self.directory_mtime = (self.source / "nested").stat().st_mtime
        configuration = (patch.object(pipeline, "configure_fits", return_value=("configured-fits", "java"))
                         if kwargs.get("fits_home") == "configured-fits" else nullcontext())
        with configuration:
            manifest = pipeline.generate_data_accessioner_xml(self.source, self.output, "A", **kwargs)
        tree = ET.parse(str(manifest))
        for ext in ("html", "csv"):
            pipeline.run_xslt_processor(manifest, ROOT / f"files.{ext}.xslt", self.output / f"report.{ext}")
        with (self.output / "report.csv").open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        return tree, (self.output / "report.html").read_text(encoding="utf-8"), rows

    def assert_basics(self, tree, rows):
        file = tree.find(".//d:file", NS)
        self.assertEqual(file.get("name"), "nested/document.bin")
        self.assertEqual(file.get("size"), str(len(pdf_bytes())))
        digest = hashlib.md5(pdf_bytes()).hexdigest()
        self.assertEqual(file.get("MD5"), digest)
        self.assertEqual(tree.findtext(".//p:messageDigest", namespaces=NS), digest)
        uuid.UUID(tree.findtext(".//p:objectIdentifierValue", namespaces=NS))
        self.assertEqual(rows[0]["md5"], digest)
        self.assertEqual(rows[0]["size (bytes)"], file.get("size"))
        dest = self.output / "A/nested/document.bin"
        self.assertEqual(dest.read_bytes(), pdf_bytes())
        self.assertEqual(dest.stat().st_mtime, 1600000000)
        self.assertEqual(dest.parent.stat().st_mtime, self.directory_mtime)
        fixity_csv, _ = pipeline.run_fixity(self.output / "A.xml", self.output, "A")
        with fixity_csv.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(next(csv.DictReader(stream))["status"], "OK")

    def test_recognized_fixture_through_xml_html_csv(self):
        with patch.object(pipeline, "identify_with_fits", return_value=ET.fromstring(FITS)) as identify:
            tree, html, rows = self.reports(fits_home="configured-fits")
        identify.assert_called_once()
        self.assertEqual(tree.findtext(".//p:formatRegistryKey", namespaces=NS), "fmt/18")
        self.assertIn("fmt/18", html)
        self.assertIn("Fixity", html)
        self.assertIn("Portable Document Format 1.4", html)
        self.assertEqual(rows[0]["format registry key/PUID"], "fmt/18")
        self.assertEqual(rows[0]["format version"], "1.4")
        self.assertEqual(rows[0]["MIME Type"], "application/pdf")
        self.assertEqual(rows[0]["Identified By"], "Droid v6 | Jhove v1")
        self.assertIsNotNone(tree.find(".//p:objectCharacteristicsExtension/{%s}fits" % pipeline.FITS_NS, NS))
        self.assert_basics(tree, rows)

    def test_no_pronom_match(self):
        result = ET.fromstring(FITS)
        identity = result.find("{%s}identification/{%s}identity" % (pipeline.FITS_NS, pipeline.FITS_NS))
        identity.remove(identity.find("{%s}externalIdentifier" % pipeline.FITS_NS))
        with patch.object(pipeline, "identify_with_fits", return_value=result):
            tree, html, rows = self.reports(fits_home="configured-fits")
        self.assertIsNone(tree.find(".//p:formatRegistryKey", NS))
        self.assertNotIn("PUID/Registry", html)
        self.assertEqual(rows[0]["format registry key/PUID"], "")
        self.assertEqual(rows[0]["MIME Type"], "application/pdf")
        self.assert_basics(tree, rows)

    def test_missing_fits_preserves_move_and_filter(self):
        (self.source / "excluded.txt").write_text("excluded")
        with patch.dict(os.environ, {"FITS_HOME": ""}), \
             patch.object(pipeline, "__file__", str(self.base / "pipeline.py")), \
             patch.object(pipeline.shutil, "which", return_value=None):
            tree, html, rows = self.reports(move_files=True, clean_files_only={self.file})
        self.assertFalse(self.file.exists())
        self.assertFalse((self.output / "A/excluded.txt").exists())
        self.assertIn("Fixity", html)
        self.assertNotIn("<h4>Formats</h4>", html)
        self.assertEqual(len(rows), 1)
        self.assert_basics(tree, rows)

    def test_tool_failure_preserves_transfer(self):
        failures = [(FileNotFoundError("Java or FITS missing"), "EXECUTION_ERROR"),
                    (subprocess.TimeoutExpired("java", 300), "TIMEOUT"),
                    (subprocess.CalledProcessError(1, "java", stderr="tool diagnostic"), "EXIT_ERROR"),
                    (ET.XMLSyntaxError("Malformed FITS XML", 0, 1, 1), "INVALID_XML"),
                    (ValueError("Unexpected FITS XML root"), "INVALID_XML")]
        for failure, code in failures:
            with self.subTest(failure=type(failure).__name__):
                with patch.object(pipeline, "identify_with_fits", side_effect=failure):
                    with self.assertLogs(level="WARNING") as logs:
                        tree, html, rows = self.reports(fits_home="configured-fits")
                self.assertIn(f"FITS:{code}", logs.output[0])
                if code == "EXIT_ERROR":
                    self.assertIn("tool diagnostic", logs.output[0])
                self.assertEqual(rows[0]["format registry key/PUID"], "")
                self.assert_basics(tree, rows)

    def test_post_fits_timestamp_failure_is_nonfatal(self):
        original_utime = os.utime

        def fail_identification(*args):
            def fail_restore(path, *args, **kwargs):
                if Path(path).is_file():
                    raise PermissionError("Timestamp restoration denied")
                return original_utime(path, *args, **kwargs)
            restore = patch.object(pipeline.os, "utime", side_effect=fail_restore)
            restore.start()
            self.addCleanup(restore.stop)
            raise FileNotFoundError("FITS unavailable")

        with patch.object(pipeline, "identify_with_fits", side_effect=fail_identification):
            with self.assertLogs(level="WARNING") as logs:
                tree, _, rows = self.reports(fits_home="configured-fits")
        self.assertTrue(any("Could not restore timestamps after FITS" in line for line in logs.output))
        self.assert_basics(tree, rows)

    def test_multiple_registries_rendered(self):
        result = ET.fromstring(FITS)
        # Synthetic second registry match to exercise the repeated structure.
        ET.SubElement(result[0][0], "{%s}externalIdentifier" % pipeline.FITS_NS,
                      type="puid").text = "fmt/19"
        with patch.object(pipeline, "identify_with_fits", return_value=result):
            _, html, rows = self.reports(fits_home="configured-fits")
        self.assertIn("fmt/18", html)
        self.assertIn("fmt/19", html)
        self.assertEqual(rows[0]["format registry key/PUID"], "fmt/18 | fmt/19")

    def test_no_identification_is_logged_and_raw_xml_retained(self):
        result = ET.fromstring(b'<fits xmlns="http://hul.harvard.edu/ois/xml/ns/fits/fits_output">'
                               b'<identification><identity format="Unknown" mimetype="application/octet-stream"/>'
                               b'</identification></fits>')
        with patch.object(pipeline, "identify_with_fits", return_value=result):
            with self.assertLogs(level="INFO") as logs:
                tree, _, rows = self.reports(fits_home="configured-fits")
        self.assertTrue(any("FITS:NO_IDENTIFICATION" in line for line in logs.output))
        self.assertIsNone(tree.find(".//p:format", NS))
        self.assertIsNotNone(tree.find(".//p:objectCharacteristicsExtension", NS))
        self.assertEqual(rows[0]["format registry key/PUID"], "")
        self.assert_basics(tree, rows)

    def test_multiple_identities_and_csv_quotes(self):
        result = ET.fromstring(FITS)
        identity = ET.SubElement(result[0], "{%s}identity" % pipeline.FITS_NS,
                                 format='Alternate, "format"', mimetype="application/alternate")
        ET.SubElement(identity, "{%s}externalIdentifier" % pipeline.FITS_NS, type="other").text = "fmt/999"
        with patch.object(pipeline, "identify_with_fits", return_value=result):
            _, html, rows = self.reports(fits_home="configured-fits")
        self.assertEqual(rows[0]["file format"], 'Portable Document Format | Alternate, "format"')
        self.assertEqual(rows[0]["MIME Type"], "application/pdf | application/alternate")
        self.assertEqual(rows[0]["format registry key/PUID"], "fmt/18")
        self.assertNotIn("fmt/999", html)

    def test_fits_command_and_xml_validation(self):
        def run(command, **kwargs):
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["check"])
            self.assertEqual(command[command.index("-i") + 1], str(self.file.resolve()))
            Path(command[command.index("-o") + 1]).write_bytes(FITS)
        with patch.object(pipeline.subprocess, "run", side_effect=run):
            self.assertEqual(pipeline.identify_with_fits(self.file, self.base).tag, "{%s}fits" % pipeline.FITS_NS)
        with patch.object(pipeline.subprocess, "run", side_effect=lambda cmd, **kw: Path(cmd[-1]).write_text("<wrong/>")):
            with self.assertRaises(ValueError):
                pipeline.identify_with_fits(self.file, self.base)

    @unittest.skipUnless(os.environ.get("PIPELINE_TEST_FITS_HOME"), "Real FITS installation not configured")
    def test_live_fits_identifies_pdf_content_with_bin_extension(self):
        tree, html, rows = self.reports(fits_home=os.environ["PIPELINE_TEST_FITS_HOME"])
        self.assertIn("fmt/18", tree.xpath("//p:formatRegistryKey/text()", namespaces=NS))
        self.assertIn("fmt/18", html)
        self.assertIn("fmt/18", rows[0]["format registry key/PUID"])
        self.assertIn("application/pdf", rows[0]["MIME Type"])
        self.assertIn("1.4", rows[0]["format version"])
        self.assert_basics(tree, rows)


class FitsConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.launcher = self.home / ("fits.bat" if os.name == "nt" else "fits.sh")
        self.launcher.touch()
        (self.home / "lib").mkdir()
        (self.home / "lib/fits.jar").touch()
        env = patch.dict(os.environ, {"FITS_HOME": "", "JAVA_HOME": ""})
        env.start()
        self.addCleanup(env.stop)
        module_path = patch.object(pipeline, "__file__", str(self.home / "pipeline.py"))
        module_path.start()
        self.addCleanup(module_path.stop)

    def make_bundle(self):
        bundled = self.home / "tools/fits-1.6.0"
        (bundled / "lib").mkdir(parents=True)
        (bundled / self.launcher.name).touch()
        (bundled / "lib/fits.jar").touch()
        return bundled

    def test_bundled_discovery_is_relative_to_module_not_working_directory(self):
        bundled = self.make_bundle()
        previous = Path.cwd()
        try:
            os.chdir(self.home / "lib")
            with patch.object(pipeline.shutil, "which", return_value="java") as which, \
                 patch.object(pipeline.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "Java 17")):
                self.assertEqual(pipeline.configure_fits(), (bundled.resolve(), "java"))
            which.assert_called_once_with("java")  # never asks PATH for FITS
        finally:
            os.chdir(previous)

    def test_explicit_and_environment_override_bundle(self):
        self.make_bundle()
        for explicit in (True, False):
            with self.subTest(explicit=explicit), \
                 patch.dict(os.environ, {"FITS_HOME": str(self.home / "invalid") if explicit else str(self.home)}), \
                 patch.object(pipeline.shutil, "which", return_value="java") as which, \
                 patch.object(pipeline.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "Java 17")):
                self.assertEqual(pipeline.configure_fits(self.home if explicit else None), (self.home.resolve(), "java"))
                which.assert_called_once_with("java")

    def test_invalid_bundle_is_nonfatal_and_not_silently_replaced(self):
        # A directory exists but its launcher is missing: report it, do not use PATH.
        (self.home / "tools/fits-1.6.0").mkdir(parents=True)
        source = self.home / "source"
        source.mkdir()
        (source / "sample.pdf").write_bytes(pdf_bytes())
        with patch.object(pipeline.shutil, "which", return_value=str(self.launcher)) as which, \
             patch.object(pipeline, "identify_with_fits") as identify:
            with self.assertLogs(level="WARNING") as logs:
                manifest = pipeline.generate_data_accessioner_xml(source, self.home / "out", "A")
        which.assert_not_called()
        identify.assert_not_called()
        self.assertIn("FITS:LAUNCHER_MISSING", logs.output[0])
        self.assertEqual(len(logs.output), 1)
        self.assertIsNotNone(ET.parse(str(manifest)).find(".//p:fixity", NS))
        self.assertEqual((self.home / "out/A/sample.pdf").read_bytes(), pdf_bytes())

    def test_configuration_failures(self):
        cases = [(None, "NOT_CONFIGURED"), (self.home / "missing", "INVALID_HOME"),
                 (self.home / "lib", "LAUNCHER_MISSING"), (self.home, "JAVA_UNAVAILABLE")]
        for home, code in cases:
            with self.subTest(code=code), patch.object(pipeline.shutil, "which", return_value=None):
                with self.assertLogs(level="WARNING") as logs:
                    self.assertIsNone(pipeline.configure_fits(home))
                self.assertEqual(len(logs.output), 1)
                self.assertIn(f"FITS:{code}", logs.output[0])

    def test_env_and_path_discovery(self):
        for via_env in (True, False):
            with self.subTest(via_env=via_env):
                with patch.dict(os.environ, {"FITS_HOME": str(self.home) if via_env else ""}), \
                     patch.object(pipeline.shutil, "which", side_effect=lambda name: "java" if name == "java" else str(self.launcher)), \
                     patch.object(pipeline.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "java version 17")):
                    self.assertEqual(pipeline.configure_fits(), (self.home.resolve(), "java"))

    def test_java_cannot_execute(self):
        with patch.object(pipeline.shutil, "which", return_value="java"), \
             patch.object(pipeline.subprocess, "run", side_effect=FileNotFoundError("bad Java")):
            with self.assertLogs(level="WARNING") as logs:
                self.assertIsNone(pipeline.configure_fits(self.home))
            self.assertIn("FITS:JAVA_UNAVAILABLE", logs.output[0])

    def test_global_failure_logged_once_for_multiple_files(self):
        source = self.home / "source"
        source.mkdir()
        for name in ("one.pdf", "two.pdf"):
            (source / name).write_bytes(pdf_bytes())
        with patch.object(pipeline, "identify_with_fits") as identify:
            with self.assertLogs(level="WARNING") as logs:
                manifest = pipeline.generate_data_accessioner_xml(source, self.home / "out", "A",
                                                                  fits_home=self.home / "missing")
        identify.assert_not_called()
        self.assertEqual(len(logs.output), 1)
        self.assertEqual(len(ET.parse(str(manifest)).findall(".//p:fixity", NS)), 2)

    def test_mocked_execution_from_configuration_to_reports(self):
        source = self.home / "source"
        source.mkdir()
        (source / "sample.pdf").write_bytes(pdf_bytes())

        def run(command, **kwargs):
            if command[-1] != "-version":
                Path(command[-1]).write_bytes(FITS)
            return subprocess.CompletedProcess(command, 0, "", "")

        output = self.home / "out"
        with patch.object(pipeline.shutil, "which", return_value="java"), \
             patch.object(pipeline.subprocess, "run", side_effect=run) as execute:
            with self.assertLogs(level="INFO") as logs:
                manifest = pipeline.generate_data_accessioner_xml(source, output, "A", fits_home=self.home)
        self.assertEqual(execute.call_count, 2)  # one Java check, one FITS execution
        self.assertTrue(any("FITS:IDENTIFIED" in line for line in logs.output))
        for ext in ("html", "csv"):
            report = output / f"report.{ext}"
            pipeline.run_xslt_processor(manifest, ROOT / f"files.{ext}.xslt", report)
            self.assertIn("fmt/18", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
