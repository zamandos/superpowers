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

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
FIXTURE = FIXTURES / 'gpo_password_policy.png'


def tiny_png():
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b'\x00\x00')) + chunk(b'IEND', b''))


class FakeOcr:
    available, pdf_available, enhanced, version, lang = True, True, False, 'fake-ocr 1.0', 'eng'

    def __init__(self):
        self.fail = False

    def can_read(self, mime):
        return self.pdf_available if mime == 'application/pdf' else self.available

    def describe(self):
        return {'available': self.available, 'engine': self.version, 'enhanced': False, 'lang': 'eng', 'pdf': self.pdf_available}

    def read(self, path, mime=None):
        if self.fail:
            raise RuntimeError('image is unreadable')
        return {'text': 'Minimum password length   8 characters', 'confidence': 91.5, 'method': 'Image OCR', 'pages': None}


class NoOcr(FakeOcr):
    available, pdf_available, version = False, False, None


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
        pdf = self.attach(b'%PDF-1.4\n%fake', name='policy.pdf')
        self.assertEqual((pdf['kind'], pdf['ocr_status']), ('pdf', 'unavailable'))
        self.assertEqual(self.c.req('GET', f"files/{pdf['id']}/page/1")[0], 503)
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


@unittest.skipUnless(shutil.which('pdftotext') and shutil.which('pdftoppm') and shutil.which('pdfinfo'), 'Poppler is not installed')
class RealPdfTest(Base):
    engine = OcrEngine()

    def read(self, name):
        f = self.wait(self.attach((FIXTURES / name).read_bytes(), name=name)['id'])
        self.assertEqual((f['kind'], f['ocr_status']), ('pdf', 'done'), f['ocr_text'])
        return f

    def test_digital_policy_uses_exact_text_layer(self):
        f = self.read('policy_digital.pdf')
        self.assertEqual((f['ocr_method'], f['pages'], f['ocr_confidence']), ('PDF text', '2', None))
        text = ' '.join(f['ocr_text'].split())
        self.assertIn('--- Page 2 --- ACME Corp', text)
        self.assertIn('Passwords must be a minimum of 12 characters', text)
        self.assertIn('disabled within 1 business day', text)

    @unittest.skipUnless(shutil.which('tesseract'), 'Tesseract is not installed')
    def test_scanned_and_mixed_pdfs_are_ocrd_page_by_page(self):
        f = self.read('policy_scanned.pdf')
        self.assertEqual(f['ocr_method'], 'OCR of scanned PDF')
        self.assertIn('Minute reference: ITSC-2026-02-07', f['ocr_text'])
        self.assertGreater(float(f['ocr_confidence']), 80)
        m = self.read('policy_mixed.pdf')
        self.assertEqual((m['ocr_method'], m['pages']), ('PDF text + OCR of 1 scanned page', '3'))
        page3 = m['ocr_text'].split('--- Page 3 ---')[1]
        self.assertIn('Approved by the IT Steering Committee on 12 February 2026', page3)

    def test_page_previews_render_cache_and_clean_up(self):
        f = self.read('policy_digital.pdf')
        status, png = self.c.req('GET', f"files/{f['id']}/page/2")
        self.assertEqual((status, png[:8]), (200, b'\x89PNG\r\n\x1a\n'))
        self.assertEqual(self.c.req('GET', f"files/{f['id']}/page/3")[0], 404)
        self.assertEqual(self.c.req('GET', f"files/{f['id']}/view")[0], 415)  # PDFs are previewed as rendered pages only
        previews = Path(self.tmp.name) / 'previews'
        self.assertEqual(len(list(previews.glob(f['id'] + '-*.png'))), 1)
        self.c.ok('DELETE', 'files/' + f['id'])
        self.assertEqual(list(previews.glob(f['id'] + '-*.png')), [])

    def test_broken_pdf_fails_cleanly(self):
        f = self.wait(self.attach(b'%PDF-1.4\nthis is not really a pdf', name='broken.pdf')['id'])
        self.assertEqual(f['ocr_status'], 'failed')
        self.assertIn('Text extraction failed', f['ocr_text'])


if __name__ == '__main__':
    unittest.main()
