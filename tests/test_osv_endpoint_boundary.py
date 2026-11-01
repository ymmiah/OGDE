"""Offline regression tests for consented OSV endpoint restrictions."""
import io
import unittest
from unittest.mock import patch
from urllib.request import HTTPError
from ogde import osv
from ogde.core import SecurityError


class _Response:
    status = 200
    def __init__(self, url):
        self.url = url
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def geturl(self):
        return self.url
    def read(self, size):
        return b'{"results":[{"vulns":[]}]}'


class OSVEndpointTests(unittest.TestCase):
    def test_redirect_handler_refuses_redirect(self):
        with self.assertRaises(SecurityError):
            osv._RejectRedirects().redirect_request(None, None, 307, 'redirect', {}, 'https://example.org/')

    def test_mismatched_final_url_rejected(self):
        class Opener:
            def open(self, request, timeout):
                return _Response('https://example.org/collect')
        with patch.object(osv, 'build_opener', return_value=Opener()):
            with self.assertRaisesRegex(SecurityError, 'URL differs'):
                osv.query_batch([{'package': {'name': 'demo', 'ecosystem': 'PyPI'}}])

    def test_expected_url_accepted(self):
        class Opener:
            def open(self, request, timeout):
                return _Response(osv.API_URL)
        with patch.object(osv, 'build_opener', return_value=Opener()):
            self.assertEqual(osv.query_batch([{'package': {'name': 'demo', 'ecosystem': 'PyPI'}}]), [{'vulns': []}])


if __name__ == '__main__':
    unittest.main()
