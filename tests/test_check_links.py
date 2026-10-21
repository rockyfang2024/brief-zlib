import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('checker', Path(__file__).resolve().parents[1] / 'scripts/check_links.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class Checks(unittest.TestCase):
    def classify(self, code, body, host='zlib.bz'):
        return checker.classify(code, body, 'https://' + host + '/', ['zlib.bz'])[0]

    def test_generic_503_is_not_available(self):
        self.assertEqual(self.classify(503, '<h1>Service unavailable</h1>'), 'http_error')

    def test_known_challenge_is_available(self):
        body = '<title>Checking your browser ...</title><script>document.cookie="c_token=abc";document.cookie="c_time=1";</script>'
        self.assertEqual(self.classify(503, body), 'challenge')
        self.assertEqual(self.classify(503, body, 'unrelated.example'), 'unconfirmed')

    def test_title_alone_is_insufficient(self):
        self.assertEqual(self.classify(200, '<title>Z-Library</title>'), 'unconfirmed')
        body = '<title>Z-Library</title><form><input name="q"></form>'
        self.assertEqual(self.classify(200, body), 'homepage')
        self.assertEqual(self.classify(200, body + 'domain for sale'), 'unconfirmed')

    def test_median_excludes_failures_and_reports_instability(self):
        report = checker.summarize([
            {'status': 'challenge', 'seconds': 1, 'checked_at': 'a'},
            {'status': 'network_error', 'seconds': 20, 'checked_at': 'b'},
            {'status': 'homepage', 'seconds': 3, 'checked_at': 'c'}])
        self.assertEqual(report['median_seconds'], 2)
        self.assertEqual(report['successful_attempts'], 2)
        self.assertEqual(report['latest_available_at'], 'c')
        self.assertTrue(report['unstable'])
        self.assertIsNone(checker.summarize([{'status': 'network_error'}])['median_seconds'])


if __name__ == '__main__':
    unittest.main()
