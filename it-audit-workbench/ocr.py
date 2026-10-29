"""Text extraction for evidence: OCR for screenshots and text extraction for PDFs.

Everything runs on the server; nothing leaves it. All tools are optional:
  * Tesseract  - reads images and scanned PDF pages.
  * Poppler    - pdftotext / pdftoppm / pdfinfo, reads PDFs (text layer and page rendering).
  * Pillow     - greyscales and enlarges screenshots before OCR, which markedly improves accuracy.
Without a tool, uploads still work and the file is marked as not readable.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

try:
    from PIL import Image, ImageOps
except ImportError:  # Pillow is optional
    Image = None

# Magic bytes of image formats Tesseract (via Leptonica) can read.
SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 'image/png'),
    (b'\xff\xd8\xff', 'image/jpeg'),
    (b'GIF87a', 'image/gif'),
    (b'GIF89a', 'image/gif'),
    (b'BM', 'image/bmp'),
    (b'II*\x00', 'image/tiff'),
    (b'MM\x00*', 'image/tiff'),
]
PDF = 'application/pdf'
TIMEOUT = 180
MAX_UPSCALED_PIXELS = 24_000_000
PDF_MAX_PAGES = int(os.environ.get('AUDIT_PDF_MAX_PAGES', 500))
PDF_MAX_OCR_PAGES = int(os.environ.get('AUDIT_PDF_MAX_OCR_PAGES', 50))
MIN_PAGE_TEXT = 25  # non-space characters; fewer than this and a PDF page is treated as scanned
PAGE_MARK = '--- Page {} ---'


def sniff_image(path):
    """Return the image MIME type from the file's content, or None if it isn't a supported image."""
    with open(path, 'rb') as f:
        head = f.read(16)
    if head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'image/webp'
    for sig, mime in SIGNATURES:
        if head.startswith(sig):
            return mime
    return None


def sniff(path):
    """Return the MIME type of a readable file (image or PDF) from its content, else None."""
    with open(path, 'rb') as f:
        if b'%PDF-' in f.read(1024):  # the header may follow a few junk bytes
            return PDF
    return sniff_image(path)


def kind_of(mime):
    return 'pdf' if mime == PDF else 'image' if mime else None


def clean_text(text):
    # Column gaps come back as long runs of spaces; shorten them so a setting and its value
    # stay together when the text wraps in a narrow pane or is pasted into notes.
    lines = [re.sub(r' {3,}', '    ', ln.rstrip()) for ln in text.replace('\f', '').splitlines()]
    cleaned, blank = [], False
    for ln in lines:  # collapse runs of blank lines
        if ln or not blank:
            cleaned.append(ln)
        blank = not ln
    return '\n'.join(cleaned).strip()


def _tool(name):
    d = os.environ.get('AUDIT_POPPLER_DIR')
    return shutil.which(name, path=d) if d else shutil.which(name)


class OcrEngine:
    def __init__(self, cmd=None, lang=None):
        self.cmd = cmd or os.environ.get('AUDIT_TESSERACT') or shutil.which('tesseract')
        self.lang = lang or os.environ.get('AUDIT_OCR_LANG', 'eng')
        self.version = None
        if self.cmd:
            try:
                out = subprocess.run([self.cmd, '--version'], capture_output=True, text=True, timeout=20)
                self.version = (out.stdout or out.stderr).splitlines()[0].strip()
            except (OSError, subprocess.SubprocessError, IndexError):
                self.cmd = None
        self.pdftotext, self.pdftoppm, self.pdfinfo = _tool('pdftotext'), _tool('pdftoppm'), _tool('pdfinfo')

    @property
    def available(self):
        return bool(self.cmd)

    @property
    def pdf_available(self):
        return bool(self.pdftotext and self.pdftoppm and self.pdfinfo)

    @property
    def enhanced(self):
        return Image is not None

    def can_read(self, mime):
        return self.pdf_available if mime == PDF else bool(mime) and self.available

    def describe(self):
        return {'available': self.available, 'engine': self.version, 'enhanced': self.enhanced, 'lang': self.lang,
                'pdf': self.pdf_available, 'pdf_ocr': self.pdf_available and self.available}

    # ---------- images ----------
    def _prepare(self, path, workdir):
        """Greyscale and enlarge small images; screenshots are low-DPI and OCR prefers ~300 DPI text."""
        if Image is None:
            return path
        try:
            with Image.open(path) as im:
                im.seek(0)
                im = ImageOps.exif_transpose(im).convert('L')
                scale = 3 if max(im.size) < 1000 else 2
                if im.width * im.height * scale * scale > MAX_UPSCALED_PIXELS:
                    scale = 1
                if scale > 1:
                    im = im.resize((im.width * scale, im.height * scale), Image.LANCZOS)
                out = Path(workdir) / 'prepared.png'
                im.save(out)
                return out
        except Exception:
            return path  # let Tesseract try the original

    def _tesseract(self, src, workdir):
        """Run Tesseract on one image. Returns (text, mean word confidence or None)."""
        base = Path(workdir) / 'out'
        # psm 4 = a single column of text of variable sizes: keeps each setting on the same line as its value.
        proc = subprocess.run([self.cmd, str(src), str(base), '-l', self.lang, '--psm', '4',
                               '-c', 'preserve_interword_spaces=1', 'txt', 'tsv'],
                              capture_output=True, text=True, timeout=TIMEOUT)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or 'Tesseract failed').strip().splitlines()[-1][:300])
        text = Path(str(base) + '.txt').read_text(encoding='utf-8', errors='replace')
        confs = []
        for line in Path(str(base) + '.tsv').read_text(encoding='utf-8', errors='replace').splitlines()[1:]:
            cols = line.split('\t')
            if len(cols) == 12 and cols[11].strip():
                try:
                    c = float(cols[10])
                except ValueError:
                    continue
                if c >= 0:
                    confs.append(c)
        return clean_text(text), (round(sum(confs) / len(confs), 1) if confs else None)

    # ---------- PDFs ----------
    def _run(self, args, what):
        proc = subprocess.run(args, capture_output=True, timeout=TIMEOUT)
        if proc.returncode != 0:
            err = proc.stderr.decode('utf-8', 'replace')
            if 'password' in err.lower():
                raise RuntimeError('The PDF is password-protected. Ask the auditee for an unprotected copy.')
            raise RuntimeError(f'{what} failed: ' + (err.strip().splitlines() or ['unknown error'])[-1][:300])
        return proc.stdout

    def pdf_pages(self, path):
        info = self._run([self.pdfinfo, str(path)], 'Reading the PDF').decode('utf-8', 'replace')
        m = re.search(r'^Pages:\s+(\d+)', info, re.M)
        if not m:
            raise RuntimeError('Could not read the number of pages.')
        return int(m.group(1))

    def render_page(self, path, page, out_png, dpi=110):
        """Render one PDF page to a PNG file (used for previews and for OCR of scanned pages)."""
        out_png = Path(out_png)
        self._run([self.pdftoppm, '-r', str(dpi), '-png', '-singlefile', '-f', str(page), '-l', str(page),
                   str(path), str(out_png.with_suffix(''))], 'Rendering the page')
        return out_png

    def _read_pdf(self, path):
        total = self.pdf_pages(path)
        pages = min(total, PDF_MAX_PAGES)
        layer = self._run([self.pdftotext, '-layout', '-enc', 'UTF-8', '-f', '1', '-l', str(pages), str(path), '-'],
                          'Extracting text').decode('utf-8', 'replace').split('\f')
        parts, confs, scanned, skipped = [], [], 0, 0
        for i in range(1, pages + 1):
            text = clean_text(layer[i - 1] if i <= len(layer) else '')
            if len(re.sub(r'\s', '', text)) < MIN_PAGE_TEXT:
                if self.available and scanned < PDF_MAX_OCR_PAGES:
                    with tempfile.TemporaryDirectory() as d:
                        png = self.render_page(path, i, Path(d) / 'page.png', dpi=300)
                        ocr_text, conf = self._tesseract(png, d)
                    scanned += 1
                    if conf is not None and ocr_text:
                        confs.append(conf)
                    text = ocr_text or text
                elif not text:
                    skipped += 1
                    text = ('(Scanned page not read: OCR page limit reached.)' if self.available
                            else '(Scanned page not read: install Tesseract to read scanned pages.)')
            parts.append(PAGE_MARK.format(i) + '\n' + (text or '(No text on this page.)'))
        if total > pages:
            parts.append(f'(Only the first {pages} of {total} pages were read.)')
        if scanned == 0:
            method = 'PDF text'
        elif scanned == pages:
            method = 'OCR of scanned PDF'
        else:
            method = f'PDF text + OCR of {scanned} scanned page{"s" if scanned > 1 else ""}'
        if skipped:
            method += f' ({skipped} scanned page{"s" if skipped > 1 else ""} not read)'
        conf = round(sum(confs) / len(confs), 1) if confs else None
        return {'text': '\n\n'.join(parts), 'confidence': conf, 'method': method, 'pages': total}

    # ---------- entry point ----------
    def read(self, path, mime=None):
        """Return {'text', 'confidence' (0-100 or None), 'method', 'pages'}."""
        mime = mime or sniff(path)
        if mime == PDF:
            if not self.pdf_available:
                raise RuntimeError('PDF tools (Poppler) are not installed.')
            return self._read_pdf(path)
        if not self.available:
            raise RuntimeError('Tesseract is not installed.')
        with tempfile.TemporaryDirectory() as d:
            text, conf = self._tesseract(self._prepare(path, d), d)
        return {'text': text, 'confidence': conf, 'method': 'Image OCR', 'pages': None}
