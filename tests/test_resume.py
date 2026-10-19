import os
import unittest
from unittest.mock import patch
from lxml import etree as ET
import pipeline as p
import pipeline_state as state
import test_preservation


class ResumeTests(unittest.TestCase):
    setUp = test_preservation.PreservationTests.setUp
    record = test_preservation.PreservationTests.record
    def run_ingest_and_fits(self, identify=None):
        # Use a Windows-representable timestamp that loses precision via float seconds.
        exact = 1791921921320324300
        os.utime(self.file, ns=(exact, exact))
        recorder = state.RunRecorder(self.output, 'A')
        recorder.run('ingest', lambda: self.xml, lambda _: dict(outcome='generated',
            outputs=recorder.paths(xml=self.xml, payload=self.payload)),
            settings={'move_files': False}, layout='unbagged')
        report = ET.fromstring(('''<fits xmlns="%s"><identification>
            <identity format="Text" mimetype="text/plain" toolname="Droid">
            <externalIdentifier type="puid">fmt/0</externalIdentifier></identity>
            </identification></fits>''' % p.FITS_NS).encode())
        observation = {}
        with patch.object(p, 'configure_fits', return_value=(self.root, 'java')), \
             patch.object(p, 'identify_with_fits', side_effect=identify, return_value=report):
            recorder.run('fits', lambda: p.enrich_accession_with_fits(self.payload, self.xml,
                result_callback=observation.update), lambda _: dict(outcome=observation['outcome'],
                result=observation, outputs=recorder.paths(xml=self.xml)))
        self.assertEqual(self.file.stat().st_mtime_ns, exact)
        return recorder

    def test_reopen_after_fits(self):
        recorder = self.run_ingest_and_fits()
        for _ in range(2):
            reopened = state.load_reconciled_status(self.output, 'A')
            for stage in ('ingest', 'fits'):
                self.assertEqual(reopened['steps'][stage]['freshness']['state'], 'current')
            self.assertEqual(reopened['steps']['fits']['result']['identified_count'], 1)
            self.assertNotIn('Detailed Results Unavailable',
                state.summarize_user_steps(reopened)['format_identification']['label'])
            self.assertEqual(p.stored_checksum(self.record()), ('SHA-256', self.digest))

    def test_payload_change_after_fits(self):
        self.run_ingest_and_fits()
        self.file.write_bytes(b'changed')
        status = state.load_reconciled_status(self.output, 'A')
        for stage in ('ingest', 'fits'):
            self.assertIn('payload_changed', status['steps'][stage]['freshness']['reasons'])

    def test_settings_change(self):
        recorder = self.run_ingest_and_fits()
        recorder.status['steps']['ingest']['settings']['move_files'] = True
        status = state.reconcile_status(recorder.status, self.output, 'A')
        self.assertIn('settings_changed', status['steps']['ingest']['freshness']['reasons'])

    def test_fits_dependency_change(self):
        recorder = self.run_ingest_and_fits()
        original = state.file_fingerprint
        def changed(path):
            return 'changed-profile' if path == p.FITS_PROFILE else original(path)
        with patch.object(state, 'file_fingerprint', side_effect=changed):
            status = state.reconcile_status(recorder.status, self.output, 'A')
        self.assertIn('fits_profile_changed', status['steps']['fits']['freshness']['reasons'])
        self.assertEqual(status['steps']['ingest']['freshness']['state'], 'current')

    def test_failed_fits_does_not_change_timestamps(self):
        recorder = self.run_ingest_and_fits(identify=PermissionError('unreadable'))
        status = state.load_reconciled_status(self.output, 'A')
        self.assertEqual(status['steps']['fits']['result']['error_count'], 1)
        self.assertEqual(status['steps']['fits']['outcome'], 'partial')
        self.assertEqual(status['steps']['ingest']['freshness']['state'], 'current')
