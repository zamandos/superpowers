"""OCR for screenshot evidence, using a locally installed Tesseract.

Nothing leaves the server. Tesseract is optional: without it, uploads still
work and image files are marked "OCR not installed". Pillow is also optional;
when present, images are converted to greyscale and enlarged before OCR, which
markedly improves accuracy on small screenshot text.
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
TIMEOUT = 180
MAX_UPSCALED_PIXELS = 24_000_000


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

    @property
    def available(self):
        return bool(self.cmd)

    @property
    def enhanced(self):
        return Image is not None

    def describe(self):
        return {'available': self.available, 'engine': self.version, 'enhanced': self.enhanced, 'lang': self.lang}

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

    def read(self, path):
        """Return (text, mean word confidence 0-100 or None)."""
        if not self.available:
            raise RuntimeError('Tesseract is not installed.')
        with tempfile.TemporaryDirectory() as d:
            src = self._prepare(path, d)
            base = Path(d) / 'out'
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
        # Column gaps come back as long runs of spaces; shorten them so a setting and its value
        # stay together when the text wraps in a narrow pane or is pasted into notes.
        lines = [re.sub(r' {3,}', '    ', ln.rstrip()) for ln in text.replace('\f', '').splitlines()]
        cleaned, blank = [], False
        for ln in lines:  # collapse runs of blank lines
            if ln or not blank:
                cleaned.append(ln)
            blank = not ln
        return '\n'.join(cleaned).strip(), (round(sum(confs) / len(confs), 1) if confs else None)
