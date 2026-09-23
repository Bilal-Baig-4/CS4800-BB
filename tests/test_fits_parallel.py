"""Deterministic concurrency and report equivalence tests; no Java required."""
from pathlib import Path
import csv
import re
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from lxml import etree as ET
import pipeline
from test_premis import FITS, NS, ROOT, pdf_bytes


class ParallelFitsTests(unittest.TestCase):
    def test_parallel_reports_match_sequential_with_order_filter_and_progress(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "source"
            source.mkdir()
            for name in ("first.pdf", "second.pdf", "third.pdf", "excluded.pdf"):
                (source / name).write_bytes(pdf_bytes())
            allowed = {p for p in source.iterdir() if p.name != "excluded.pdf"}
            order = [p.name for p in source.rglob("*") if p in allowed]
            results = []
            for workers in (1, 2):
                progress = []
                lock = threading.Lock()
                second_finished = threading.Event()
                active = 0
                peak = 0

                def identify(file, *args):
                    nonlocal active, peak
                    with lock:
                        active += 1
                        peak = max(peak, active)
                    try:
                        if workers == 2 and file.name == order[0]:
                            if not second_finished.wait(5):
                                raise AssertionError("Second worker did not run concurrently")
                        result = ET.fromstring(FITS)
                        # Distinct real-tool-style results catch file/result mixups.
                        result[0][0].set("format", file.name)
                        return result
                    finally:
                        if file.name == order[1]:
                            second_finished.set()
                        with lock:
                            active -= 1

                output = base / str(workers)
                with patch.object(pipeline, "configure_fits", return_value=("fits", "java")), \
                     patch.object(pipeline, "identify_with_fits", side_effect=identify):
                    xml = pipeline.generate_data_accessioner_xml(
                        source, output, "A", clean_files_only=allowed,
                        fits_workers=workers,
                        progress_callback=lambda *args: progress.append(args),
                    )
                self.assertEqual(peak, workers)
                self.assertEqual(progress, [(i + 1, 3, name) for i, name in enumerate(order)])
                tree = ET.parse(str(xml))
                files = tree.findall(".//d:file", NS)
                self.assertEqual([f.get("name") for f in files], order)
                for f in files:
                    self.assertEqual(f.findtext(".//p:formatName", namespaces=NS), f.get("name"))
                    self.assertEqual(f.findtext(".//p:formatRegistryKey", namespaces=NS), "fmt/18")
                for ext in ("csv", "html"):
                    pipeline.run_xslt_processor(xml, ROOT / f"files.{ext}.xslt", output / f"report.{ext}")
                characteristics = [ET.tostring(f.find("p:object/p:objectCharacteristics", NS)) for f in files]
                with (output / "report.csv").open(encoding="utf-8", newline="") as stream:
                    rows = list(csv.DictReader(stream))
                html = ET.HTML((output / "report.html").read_text(encoding="utf-8"))
                sections = [re.sub(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", "UUID",
                                   ET.tostring(el, encoding="unicode"))
                            for el in html.xpath('//div[@class="file"]')]
                results.append((characteristics, rows, sections))
            self.assertEqual(results[0], results[1])

    def test_one_timeout_does_not_drop_other_files_or_move_behavior(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "source"
            source.mkdir()
            for name in ("timeout.pdf", "ok.pdf"):
                (source / name).write_bytes(pdf_bytes())

            def identify(file, *args):
                if file.name == "timeout.pdf":
                    raise subprocess.TimeoutExpired("java", 300)
                return ET.fromstring(FITS)

            with patch.object(pipeline, "configure_fits", return_value=("fits", "java")), \
                 patch.object(pipeline, "identify_with_fits", side_effect=identify):
                with self.assertLogs(level="WARNING") as logs:
                    xml = pipeline.generate_data_accessioner_xml(source, base / "out", "A", move_files=True)
            self.assertIn("FITS:TIMEOUT", logs.output[0])
            files = {f.get("name"): f for f in ET.parse(str(xml)).findall(".//d:file", NS)}
            self.assertEqual(len(files), 2)
            self.assertIsNone(files["timeout.pdf"].find(".//p:format", NS))
            self.assertEqual(files["ok.pdf"].findtext(".//p:formatRegistryKey", namespaces=NS), "fmt/18")
            for name, f in files.items():
                self.assertFalse((source / name).exists())
                self.assertEqual((base / "out/A" / name).read_bytes(), pdf_bytes())
                self.assertIsNotNone(f.find(".//p:fixity", NS))


if __name__ == "__main__":
    unittest.main()
