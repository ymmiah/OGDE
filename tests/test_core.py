import base64
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from ogde.core import (SecurityError, generate_keypair, parse_sbom, parse_purl,
                       read_json, scan_signed_feed, sign_feed, verify_envelope, write_json)
from ogde.ledger import append_event, verify_ledger
from ogde.osv import scan_osv, _as_query
from ogde.core import Component
from ogde import osv


def sample_feed():
    def date(dt): return dt.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    now = datetime.now(timezone.utc)
    return {'schema_version': 1, 'feed_id': 'trusted-test', 'generated_at': date(now),
            'expires_at': date(now + timedelta(days=1)), 'advisories': [
        {'id': 'OGDE-DEMO-1', 'title': 'Synthetic demonstration advisory',
         'severity': 'high', 'affected': [{'purl': 'pkg:pypi/example-lib', 'versions': ['1.0.0']}],
         'remediation': 'Replace the demonstration component.', 'references': []}]}


def bom(name='example-lib', version='1.0.0'):
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'components': [
        {'type': 'library', 'name': name, 'version': version, 'purl': f'pkg:pypi/{name}@{version}'}]}

class SigningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.private = Path(self.tmp.name) / 'publisher.pem'
        self.public = Path(self.tmp.name) / 'publisher.pub'
        generate_keypair(self.private, self.public)
    def tearDown(self): self.tmp.cleanup()

    def test_round_trip_and_match(self):
        envelope = sign_feed(sample_feed(), self.private)
        verified = verify_envelope(envelope, self.public)
        report = scan_signed_feed(verified, parse_sbom(bom()))
        self.assertEqual(report['finding_count'], 1)
        self.assertEqual(report['findings'][0]['advisory_id'], 'OGDE-DEMO-1')

    def test_no_match(self):
        envelope = sign_feed(sample_feed(), self.private)
        report = scan_signed_feed(verify_envelope(envelope, self.public), parse_sbom(bom(version='1.0.1')))
        self.assertEqual(report['finding_count'], 0)

    def test_tampering_rejected(self):
        envelope = sign_feed(sample_feed(), self.private)
        envelope['payload']['advisories'][0]['severity'] = 'low'
        with self.assertRaises(SecurityError): verify_envelope(envelope, self.public)

    def test_wrong_trust_anchor_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            generate_keypair(Path(tmp)/'key', Path(tmp)/'pub')
            with self.assertRaises(SecurityError): verify_envelope(sign_feed(sample_feed(), self.private), Path(tmp)/'pub')

    def test_truncated_signature_rejected(self):
        envelope = sign_feed(sample_feed(), self.private)
        envelope['signature']['value'] = base64.b64encode(b'X').decode()
        with self.assertRaises(SecurityError): verify_envelope(envelope, self.public)

    def test_expired_feed_rejected(self):
        feed = sample_feed()
        feed['expires_at'] = '2020-01-01T00:00:00Z'
        with self.assertRaises(SecurityError): sign_feed(feed, self.private)

    def test_duplicate_id_rejected(self):
        feed = sample_feed(); feed['advisories'].append(dict(feed['advisories'][0]))
        with self.assertRaises(SecurityError): sign_feed(feed, self.private)

    def test_unsafe_format_rejected(self):
        feed = sample_feed(); feed['advisories'][0]['affected'][0]['versions'] = []
        with self.assertRaises(SecurityError): sign_feed(feed, self.private)

    @unittest.skipIf(os.name == 'nt', 'Unix file permissions')
    def test_private_key_permissions(self):
        self.assertEqual(self.private.stat().st_mode & 0o777, 0o600)

    def test_refuses_key_overwrite(self):
        with self.assertRaises(SecurityError): generate_keypair(self.private, self.public)

class SBOMTests(unittest.TestCase):
    def test_pypi_normalisation(self):
        self.assertEqual(parse_purl('pkg:pypi/My_Lib@1.2'), ('pypi', 'my-lib', '1.2'))
    def test_scoped_npm(self):
        self.assertEqual(parse_purl('pkg:npm/%40scope/name@2.0'), ('npm', '@scope/name', '2.0'))
    def test_version_conflict_rejected(self):
        b = bom(); b['components'][0]['version'] = '9.0'
        with self.assertRaises(SecurityError): parse_sbom(b)
    def test_nested_packages(self):
        b = bom(); b['components'][0]['components'] = bom(name='child')['components']
        self.assertEqual(len(parse_sbom(b)), 2)
    def test_path_traversal_rejected(self):
        with self.assertRaises(SecurityError): parse_purl('pkg:pypi/../bad@1.0')
    def test_duplicate_json_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td)/'dup.json'; file.write_text('{"x":1,"x":2}')
            with self.assertRaises(SecurityError): read_json(file)

class LedgerTests(unittest.TestCase):
    def test_chain_and_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'audit.jsonl'
            append_event(path, {'type': 'scan', 'findings': 1})
            append_event(path, {'type': 'scan', 'findings': 0})
            self.assertEqual(verify_ledger(path)['events'], 2)
            value = path.read_text().replace('"findings":1', '"findings":7')
            path.write_text(value)
            with self.assertRaises(SecurityError): verify_ledger(path)

class OSVTests(unittest.TestCase):
    def test_maven_ecosystem_uses_group_colon_artifact(self):
        c = Component("maven", "org.example/library", "1.0.0", "pkg:maven/org.example/library@1.0.0")
        self.assertEqual(_as_query(c)["package"]["name"], "org.example:library")

    def test_queries_and_deduplicates(self):
        original = osv.query_batch
        osv.query_batch = lambda queries: [{'vulns': [{'id': 'GHSA-TEST-111'}]} for _ in queries]
        try:
            report = scan_osv(parse_sbom(bom()))
            self.assertEqual(report['finding_count'], 1)
            self.assertEqual(report['findings'][0]['basis'], 'OSV version query')
        finally: osv.query_batch = original

    def test_pagination_follows_token(self):
        original = osv.query_batch
        calls = []
        def fake(queries):
            calls.append(queries)
            return [{'vulns': [{'id': 'TEST-1'}], 'next_page_token': 'page2'}] if len(calls)==1 else [{'vulns': [{'id': 'TEST-2'}]}]
        osv.query_batch = fake
        try:
            report = scan_osv(parse_sbom(bom()))
            self.assertEqual(report['finding_count'], 2)
            self.assertEqual(calls[1][0]['page_token'], 'page2')
        finally: osv.query_batch = original

if __name__ == '__main__': unittest.main()
