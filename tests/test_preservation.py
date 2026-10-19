import csv
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from lxml import etree as ET
import pipeline as p
import pipeline_state as state


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'nested').mkdir()
        (self.source / 'nested' / 'file.txt').write_bytes(b'abc')
        self.output = self.root / 'output'
        self.xml = p.ingest_accession(self.source, self.output, 'A')
        self.payload = self.output / 'A'
        self.file = self.payload / 'nested' / 'file.txt'
        self.digest = hashlib.sha256(b'abc').hexdigest()

    def record(self):
        return ET.parse(str(self.xml)).find('.//{http://dataaccessioner.org/schema/dda-1-1}file')

    def legacy(self):
        tree = ET.parse(str(self.xml))
        record = tree.find('.//{http://dataaccessioner.org/schema/dda-1-1}file')
        del record.attrib['SHA256']
        record.set('MD5', hashlib.md5(b'abc').hexdigest())
        record.find('.//{%s}messageDigestAlgorithm' % p.PREMIS_NS).text = 'MD5'
        record.find('.//{%s}messageDigest' % p.PREMIS_NS).text = record.get('MD5')
        tree.write(str(self.xml))

    def fixity(self):
        report, _ = p.run_fixity(self.xml, self.output, 'A')
        with open(report, newline='', encoding='utf-8') as stream:
            return list(csv.DictReader(stream))[0]

    def test_ingest_and_metadata(self):
        self.assertEqual(p.compute_sha256(self.file, 1), self.digest)
        self.assertEqual(p.stored_checksum(self.record()), ('SHA-256', self.digest))
        self.assertNotIn('MD5', self.record().attrib)
        self.assertEqual(self.record().get('SHA256'), self.digest)
        self.assertEqual(self.file.stat().st_mtime_ns, (self.source / 'nested/file.txt').stat().st_mtime_ns)
        with self.assertRaises(ValueError):
            p.compute_sha256(self.file, 0)

    def test_fixity(self):
        result = self.fixity()
        self.assertEqual(result['status'], 'OK')
        self.assertEqual(result['computed_checksum'], self.digest)
        self.assertEqual(result['algorithm'], 'SHA-256')
        self.file.write_bytes(b'changed')
        self.assertEqual(self.fixity()['status'], 'MISMATCH')
        self.file.unlink()
        self.assertEqual(self.fixity()['status'], 'MISSING')

    def test_unreadable(self):
        with patch.object(p, 'compute_checksum', side_effect=PermissionError('unreadable')):
            self.assertEqual(self.fixity()['status'], 'ERROR')

    def test_conflicting_metadata(self):
        record = self.record()
        record.set('SHA256', '0' * 64)
        with self.assertRaises(ValueError):
            p.stored_checksum(record)

    def test_reports(self):
        for kind in ('csv', 'html'):
            report = self.output / ('report.' + kind)
            p.run_xslt_processor(self.xml, p.XSLT_DIR / ('files.' + kind + '.xslt'), report)
            text = report.read_text(encoding='utf-8')
            self.assertIn(self.digest, text)
            self.assertIn('SHA-256', text)
            self.assertIn('file.txt', text)

    def check_bag(self, profile='generic'):
        bag = p.construct_bag(self.payload, 'A', xml_manifest=self.xml, profile=profile,
                              title='Test', source_organization='Research')
        self.assertEqual((bag / 'manifest-sha256.txt').read_text(), self.digest + '  data/nested/file.txt\n')
        for line in (bag / 'tagmanifest-sha256.txt').read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.assertEqual(digest, hashlib.sha256((bag / name).read_bytes()).hexdigest())
        self.assertTrue(p.bagit.Bag(str(bag)).validate())
        self.assertFalse((bag / 'manifest-md5.txt').exists())

    @unittest.skipUnless(p.BAGIT_AVAILABLE, 'bagit-python unavailable')
    def test_generic_bag(self):
        self.check_bag()

    @unittest.skipUnless(p.BAGIT_AVAILABLE, 'bagit-python unavailable')
    def test_aptrust_bag(self):
        self.check_bag('aptrust')
        self.assertIn('aptrust-info.txt', (self.payload / 'tagmanifest-sha256.txt').read_text())

    @unittest.skipUnless(p.BAGIT_AVAILABLE, 'bagit-python unavailable')
    def test_legacy_fixity_and_bag(self):
        self.legacy()
        self.assertEqual(self.fixity()['algorithm'], 'MD5')
        self.assertEqual(self.fixity()['status'], 'OK')
        self.check_bag()

    @unittest.skipUnless(p.BAGIT_AVAILABLE, 'bagit-python unavailable')
    def test_bag_rejects_changed_payload_before_movement(self):
        self.file.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            p.construct_bag(self.payload, 'A', xml_manifest=self.xml)
        self.assertFalse((self.payload / 'data').exists())

    def test_status_version_and_inventory(self):
        recorder = state.RunRecorder(self.output, 'A')
        recorder.run('ingest', lambda: self.xml, lambda result: dict(outcome='generated',
                     outputs=recorder.paths(xml=result, payload=self.payload)), layout='unbagged')
        current = state.reconcile_status(recorder.status, self.output, 'A')
        self.assertEqual(current['steps']['ingest']['freshness']['state'], 'current')
        plan = state.build_resume_plan(current, {'ingest': True}, {}, self.output, 'A')
        self.assertEqual(next(x for x in plan if x['stage'] == 'ingest')['action'], 'reuse')
        old = current['steps']['ingest']
        old['settings'].pop('checksum_workflow')
        stale = state.reconcile_status(current, self.output, 'A')
        self.assertEqual(stale['steps']['ingest']['freshness']['state'], 'stale')
        plan = state.build_resume_plan(stale, {'ingest': True}, {}, self.output, 'A')
        self.assertEqual(next(x for x in plan if x['stage'] == 'ingest')['action'], 'review')
        before = state.inventory_fingerprint(self.xml)
        tree = ET.parse(str(self.xml))
        tree.find('.//{http://dataaccessioner.org/schema/dda-1-1}file').set('SHA256', '0'*64)
        tree.write(str(self.xml))
        self.assertNotEqual(before, state.inventory_fingerprint(self.xml))


if __name__ == '__main__':
    unittest.main()
