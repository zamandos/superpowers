"""OCR tests: workflow with a fake engine, plus a real Tesseract run when it is installed."""
import shutil
import struct
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_server import Client, server  # noqa: E402  (also puts the app on sys.path)
from ocr import OcrEngine, sniff_image  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'gpo_password_policy.png'


def tiny_png():
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b'\x00\x00')) + chunk(b'IEND', b''))


class FakeOcr:
    available, enhanced, version, lang = True, False, 'fake-ocr 1.0', 'eng'

    def __init__(self):
        self.fail = False
        self.calls = 0

    def describe(self):
        return {'available': self.available, 'engine': self.version, 'enhanced': False, 'lang': 'eng'}

    def read(self, path):
        self.calls += 1
        if self.fail:
            raise RuntimeError('image is unreadable')
        return 'Minimum password length   8 characters', 91.5


class NoOcr(FakeOcr):
    available, version = False, None


class Base(unittest.TestCase):
    engine = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.srv, cls.app = server.make_server(cls.tmp.name, port=0, ocr=cls.engine)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.app.bootstrap_admin('admin-password-1')
        cls.c = Client(cls.srv.server_address[1])
        cls.c.ok('POST', 'login', {'username': 'admin', 'password': 'admin-password-1'})
        e = cls.c.ok('POST', 'engagements', {'name': 'OCR'})
        cls.wp = cls.c.ok('POST', 'workpapers', {'engagement_id': e['id'], 'ref': 'AC-05', 'title': 'Password settings'})

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def attach(self, data, name='screenshot.png'):
        return self.c.ok('POST', f"workpapers/{self.wp['id']}/attach", raw=data, headers={'X-Filename': name})['file']

    def wait(self, fid, timeout=90):
        end = time.time() + timeout
        while time.time() < end:
            f = self.c.ok('GET', 'files?id=' + fid)[0]
            if f['ocr_status'] not in ('queued', 'running'):
                return f
            time.sleep(0.1)
        self.fail('OCR did not finish')


class OcrWorkflowTest(Base):
    engine = FakeOcr()

    def test_image_is_read_automatically_and_logged(self):
        f = self.attach(tiny_png())
        self.assertIn(f['ocr_status'], ('queued', 'running', 'done'))
        f = self.wait(f['id'])
        self.assertEqual((f['ocr_status'], f['ocr_text'], f['ocr_confidence'], f['ocr_engine']),
                         ('done', 'Minimum password length   8 characters', '91.5', 'fake-ocr 1.0'))
        log = self.c.ok('GET', 'audit_log?record_id=' + f['id'])
        done = [r for r in log if r['action'] == 'ocr_done']
        self.assertEqual(done[0]['user_name'], 'OCR service')

    def test_type_comes_from_content_not_name(self):
        f = self.attach(b'name,enabled\nalice,1\n', name='looks_like.png')
        self.assertIsNone(f['ocr_status'])
        self.assertEqual(self.c.req('GET', f"files/{f['id']}/view")[0], 415)
        self.assertEqual(self.c.req('POST', f"files/{f['id']}/ocr", {})[0], 400)
        g = self.attach(tiny_png(), name='no_extension')
        self.assertIsNotNone(g['ocr_status'])

    def test_failure_then_rerun(self):
        self.engine.fail = True
        f = self.wait(self.attach(tiny_png())['id'])
        self.assertEqual(f['ocr_status'], 'failed')
        self.assertIn('unreadable', f['ocr_text'])
        self.engine.fail = False
        self.c.ok('POST', f"files/{f['id']}/ocr", {})
        f = self.wait(f['id'])
        self.assertEqual(f['ocr_status'], 'done')
        actions = [r['action'] for r in self.c.ok('GET', 'audit_log?record_id=' + f['id'])]
        self.assertEqual(actions[:3], ['ocr_done', 'ocr_requested', 'ocr_failed'])

    def test_view_serves_image_inline_and_is_logged(self):
        png = tiny_png()
        f = self.attach(png)
        status, body = self.c.req('GET', f"files/{f['id']}/view")
        self.assertEqual((status, body), (200, png))
        self.assertIn('view', [r['action'] for r in self.c.ok('GET', 'audit_log?record_id=' + f['id'])])

    def test_status_endpoint(self):
        self.assertEqual(self.c.ok('GET', 'ocr')['engine'], 'fake-ocr 1.0')


class OcrNotInstalledTest(Base):
    engine = NoOcr()

    def test_upload_still_works_and_is_marked(self):
        f = self.attach(tiny_png())
        self.assertEqual(f['ocr_status'], 'unavailable')
        self.assertEqual(self.c.req('POST', f"files/{f['id']}/ocr", {})[0], 503)
        self.assertFalse(self.c.ok('GET', 'ocr')['available'])


@unittest.skipUnless(shutil.which('tesseract'), 'Tesseract is not installed')
class RealTesseractTest(Base):
    engine = OcrEngine()

    def test_reads_password_policy_screenshot(self):
        self.assertEqual(sniff_image(FIXTURE), 'image/png')
        f = self.wait(self.attach(FIXTURE.read_bytes(), name='gpo.png')['id'])
        self.assertEqual(f['ocr_status'], 'done', f['ocr_text'])
        self.assertIn('Minimum password length    8 characters', f['ocr_text'].splitlines())
        self.assertNotIn('     ', f['ocr_text'])  # column gaps are shortened
        lines = [' '.join(ln.split()) for ln in f['ocr_text'].splitlines()]
        # Each setting must stay on the same line as its value.
        for expected in ('Minimum password length 8 characters', 'Maximum password age 90 days',
                         'Account lockout threshold 5 invalid logon attempts', 'Enforce password history 24 passwords remembered'):
            self.assertIn(expected, lines)
        self.assertGreater(float(f['ocr_confidence']), 80)


if __name__ == '__main__':
    unittest.main()
