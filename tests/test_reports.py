import csv
from copy import deepcopy
import hashlib
import unittest
from lxml import etree as ET
import pipeline as p
import test_preservation


class ReportTests(unittest.TestCase):
    setUp = test_preservation.PreservationTests.setUp
    legacy = test_preservation.PreservationTests.legacy
    fixity = test_preservation.PreservationTests.fixity

    def reports(self):
        result = {}
        for kind in ('csv', 'html'):
            path = self.output / ('report.' + kind)
            p.run_xslt_processor(self.xml, p.XSLT_DIR / ('files.' + kind + '.xslt'), path)
            result[kind] = path.read_text(encoding='utf-8')
        with (self.output / 'report.csv').open(encoding='utf-8', newline='') as stream:
            reader = csv.DictReader(stream)
            result['headers'] = reader.fieldnames
            result['rows'] = list(reader)
        return result

    def assert_other_fields(self, result):
        self.assertEqual([h for h in result['headers'] if h not in ('SHA-256', 'MD5')],
            ['directory path', 'file name', 'file extension', 'last modified',
             'size (bytes)', 'file format', 'format version', 'format registry key/PUID',
             'Identified By', 'MIME Type', 'ID Warning'])
        self.assertEqual(result['rows'][0]['file name'], 'nested/file.txt')
        self.assertEqual(result['rows'][0]['size (bytes)'], '3')
        self.assertTrue(all(None not in row for row in result['rows']))

    def test_new_report_labels_and_values(self):
        result = self.reports()
        self.assertEqual(result['headers'].count('SHA-256'), 1)
        self.assertNotIn('MD5', result['csv'])
        self.assertNotIn('MD5', result['html'])
        self.assertNotIn('SHA256', result['html'])
        self.assertEqual(result['rows'][0]['SHA-256'], self.digest)
        self.assertEqual(len(result['rows'][0]['SHA-256']), 64)
        self.assertIn(self.digest, result['html'])
        self.assert_other_fields(result)
        self.assertEqual(self.fixity()['algorithm'], 'SHA-256')
        log = (self.output / 'fixity_A.log').read_text(encoding='utf-8')
        self.assertIn('algorithm=SHA-256', log)
        self.assertIn('computed=' + self.digest, log)
        self.assertNotIn('MD5', log)

    def test_historical_report_labels_and_values(self):
        self.legacy()
        before = self.xml.read_bytes()
        result = self.reports()
        digest = hashlib.md5(b'abc').hexdigest()
        self.assertEqual(result['headers'].count('MD5'), 1)
        self.assertNotIn('SHA-256', result['csv'])
        self.assertNotIn('SHA-256', result['html'])
        self.assertEqual(result['rows'][0]['MD5'], digest)
        self.assertIn(digest, result['html'])
        self.assert_other_fields(result)
        self.assertEqual(self.fixity()['algorithm'], 'MD5')
        self.assertIn('algorithm=MD5', (self.output / 'fixity_A.log').read_text(encoding='utf-8'))
        self.assertEqual(self.xml.read_bytes(), before)

    def test_mixed_inventory_keeps_algorithms_separate(self):
        self.legacy()
        tree = ET.parse(str(self.xml))
        old = tree.find('.//{%s}file' % 'http://dataaccessioner.org/schema/dda-1-1')
        new = deepcopy(old)
        new.set('name', 'sha-file.txt')
        del new.attrib['MD5']
        new.set('SHA256', self.digest)
        new.find('.//{%s}messageDigestAlgorithm' % p.PREMIS_NS).text = 'SHA-256'
        new.find('.//{%s}messageDigest' % p.PREMIS_NS).text = self.digest
        old.getparent().append(new)
        tree.write(str(self.xml))
        result = self.reports()
        self.assertEqual(result['headers'].count('SHA-256'), 1)
        self.assertEqual(result['headers'].count('MD5'), 1)
        legacy, current = result['rows']
        self.assertEqual(legacy['SHA-256'], '')
        self.assertEqual(legacy['MD5'], hashlib.md5(b'abc').hexdigest())
        self.assertEqual(current['SHA-256'], self.digest)
        self.assertEqual(current['MD5'], '')
        self.assert_other_fields(result)

    def test_premis_only_checksum_columns(self):
        for historical in (False, True):
            if historical:
                self.legacy()
            tree = ET.parse(str(self.xml))
            record = tree.find('.//{http://dataaccessioner.org/schema/dda-1-1}file')
            del record.attrib['MD5' if historical else 'SHA256']
            tree.write(str(self.xml))
            result = self.reports()
            algorithm = 'MD5' if historical else 'SHA-256'
            expected = hashlib.md5(b'abc').hexdigest() if historical else self.digest
            self.assertEqual(result['rows'][0][algorithm], expected)
            self.assertNotIn('SHA-256' if historical else 'MD5', result['headers'])
            # Restore the attribute so the legacy fixture can replace it next.
            record.set('MD5' if historical else 'SHA256', expected)
            tree.write(str(self.xml))
