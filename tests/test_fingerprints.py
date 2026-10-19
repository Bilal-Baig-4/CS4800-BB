import hashlib
import json
from copy import deepcopy
from unittest.mock import patch
import pipeline_state as state
import unittest
import test_resume


class FingerprintTests(unittest.TestCase):
    setUp = test_resume.ResumeTests.setUp
    record = test_resume.ResumeTests.record
    run_ingest_and_fits = test_resume.ResumeTests.run_ingest_and_fits
    def legacy_status(self):
        recorder = self.run_ingest_and_fits()
        status = deepcopy(recorder.status)
        for stage in ('ingest', 'fits'):
            record = status['steps'][stage]
            record['freshness']['method'] = 'fingerprint-v1'
            for side in ('inputs', 'evidence'):
                for name, value in list(record[side].items()):
                    if isinstance(value, dict) and value.get('method', '').endswith('-sha256-v1'):
                        descriptor = dict(value, method=value['method'].replace('sha256', 'md5'))
                        record[side][name] = state._snapshot(descriptor, self.output, status['layout'], state.XSLT_DIR)
        return status

    def test_sha256_primitives_and_all_evidence(self):
        status = self.run_ingest_and_fits().status
        self.assertEqual(state.file_fingerprint(self.file), hashlib.sha256(b'abc').hexdigest())
        membership = state._membership(self.payload)
        encoded = json.dumps(membership, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        self.assertEqual(state.payload_stat_fingerprint(self.payload, 'unbagged'), hashlib.sha256(encoded).hexdigest())
        for record in status['steps'].values():
            for side in ('inputs', 'evidence'):
                for value in record[side].values():
                    if isinstance(value, dict) and 'method' in value:
                        self.assertIn('sha256', value['method'])
                        self.assertEqual(len(value['value']), 64)
        self.assertNotIn('-md5-v1', json.dumps(status))

    def test_legacy_unchanged_upgrades_and_reopens(self):
        status = self.legacy_status()
        before_xml = self.xml.read_bytes()
        attempts = {stage: status['steps'][stage]['attempt'] for stage in ('ingest', 'fits')}
        state.save_status(self.output, 'A', status)
        for _ in range(2):
            status = state.load_reconciled_status(self.output, 'A')
            for stage in ('ingest', 'fits'):
                self.assertEqual(status['steps'][stage]['freshness']['state'], 'current')
                self.assertEqual(status['steps'][stage]['attempt'], attempts[stage])
        self.assertNotIn('-md5-v1', json.dumps(status))
        self.assertEqual(self.xml.read_bytes(), before_xml)

    def test_changed_legacy_not_rebased(self):
        status = self.legacy_status()
        previous = deepcopy(status['steps']['ingest']['evidence']['payload'])
        self.file.write_bytes(b'changed')
        for _ in range(2):
            status = state.reconcile_status(status, self.output, 'A')
            self.assertEqual(status['steps']['ingest']['freshness']['state'], 'stale')
            self.assertEqual(status['steps']['ingest']['evidence']['payload'], previous)

    def test_missing_legacy_not_upgraded(self):
        status = self.legacy_status()
        self.file.unlink()
        status = state.reconcile_status(status, self.output, 'A')
        self.assertEqual(status['steps']['ingest']['freshness']['state'], 'stale')

    def test_unknown_method_remains_unverified(self):
        status = self.legacy_status()
        status['steps']['ingest']['evidence']['payload']['method'] = 'future-method'
        status = state.reconcile_status(status, self.output, 'A')
        self.assertEqual(status['steps']['ingest']['freshness']['state'], 'unverified')

    def test_workflow_change_not_cleared_by_migration(self):
        status = self.legacy_status()
        status['steps']['ingest']['settings'].pop('checksum_workflow')
        status = state.reconcile_status(status, self.output, 'A')
        self.assertIn('checksum_workflow_changed', status['steps']['ingest']['freshness']['reasons'])

    def test_legacy_file_digest_known_value(self):
        descriptor = dict(method='file-md5-v1', path='A/nested/file.txt', scope='output')
        value = state._snapshot(descriptor, self.output, 'unbagged', state.XSLT_DIR)
        self.assertEqual(value['value'], '900150983cd24fb0d6963f7d28e17f72')

    def test_bag_and_report_evidence_upgrade(self):
        recorder = self.run_ingest_and_fits()
        csv = self.output / 'A_files.csv'
        html = self.output / 'A_files.html'
        def reports():
            import pipeline as p
            for kind, target in (('csv', csv), ('html', html)):
                p.run_xslt_processor(self.xml, p.XSLT_DIR / ('files.' + kind + '.xslt'), target)
        recorder.run('reports', reports, lambda _: dict(outcome='generated',
            outputs=recorder.paths(csv=csv, html=html)))
        import pipeline as p
        if not p.BAGIT_AVAILABLE:
            self.skipTest('bagit-python unavailable')
        recorder.run('bag_construct', lambda: p.construct_bag(self.payload, 'A', xml_manifest=self.xml),
            lambda bag: dict(outcome='constructed', outputs=recorder.paths(bag=bag,
                declaration=bag / 'bagit.txt', manifest=bag / 'manifest-sha256.txt')), layout='bagged')
        status = recorder.status
        for stage in ('reports', 'bag_construct'):
            for side in ('inputs', 'evidence'):
                for name, value in list(status['steps'][stage][side].items()):
                    if isinstance(value, dict) and value.get('method', '').endswith('-sha256-v1'):
                        status['steps'][stage][side][name] = state._snapshot(
                            dict(value, method=value['method'].replace('sha256', 'md5')),
                            self.output, 'bagged', state.XSLT_DIR)
        status = state.reconcile_status(status, self.output, 'A')
        for stage in ('reports', 'bag_construct'):
            self.assertEqual(status['steps'][stage]['freshness']['state'], 'current')
            self.assertNotIn('-md5-v1', json.dumps(status['steps'][stage]))
        (self.payload / 'bag-info.txt').write_text('changed')
        status = state.reconcile_status(status, self.output, 'A')
        self.assertIn('bag_changed', status['steps']['bag_construct']['freshness']['reasons'])
