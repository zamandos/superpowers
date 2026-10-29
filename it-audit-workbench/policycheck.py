"""Compare required settings (usually from a policy) with actual settings read from evidence.

Works on the text already extracted from screenshots and PDFs. Every result records the
file and the exact line it came from so the auditor can trace and verify it.
"""
import re

OPERATORS = {'>=': 'at least', '<=': 'at most', '=': 'equal to', '!=': 'not equal to'}
_MODAL = re.compile(r'\b(must|shall|should|will|are required|is required|required to|need to|needs to)\b', re.I)

# Common settings: how they appear in system screens, and how policies usually state them.
LIBRARY = [
    {'key': 'min_length', 'label': 'Minimum password length', 'op': '>=', 'unit': 'characters', 'topic': r'password|passphrase',
     'policy': r'(?:minimum (?:length )?of|at least|no (?:fewer|less) than|minimum)\s+(\d+)\s*(?:characters|chars)'},
    {'key': 'history', 'label': 'Enforce password history', 'op': '>=', 'unit': 'passwords', 'topic': r'password',
     'policy': r'(?:last|previous|prior)\s+(\d+)\s+passwords'},
    {'key': 'max_age', 'label': 'Maximum password age', 'op': '<=', 'unit': 'days', 'topic': r'password',
     'policy': r'(?:every|at least every|maximum (?:age )?of|no (?:more|longer) than|after|within)\s+(\d+)\s+days'},
    {'key': 'min_age', 'label': 'Minimum password age', 'op': '>=', 'unit': 'days', 'topic': r'minimum password age|changed more than once',
     'policy': r'(?:minimum (?:age )?of|at least)\s+(\d+)\s+days?'},
    {'key': 'lockout', 'label': 'Account lockout threshold', 'op': '<=', 'unit': 'attempts', 'topic': r'lock',
     'policy': r'(?:after|following|maximum of|no more than)\s+(\d+)\s+(?:consecutive\s+)?(?:invalid|failed|unsuccessful|incorrect|bad)'},
    {'key': 'lockout_duration', 'label': 'Account lockout duration', 'op': '>=', 'unit': 'minutes', 'topic': r'lock',
     'policy': r'(?:for|duration of|period of)\s+(?:at least\s+)?(\d+)\s+minutes'},
    {'key': 'complexity', 'label': 'Password must meet complexity requirements', 'op': '=', 'expected': 'Enabled', 'topic': r'password',
     'policy': r'(complexity)'},
    {'key': 'reversible', 'label': 'Store passwords using reversible encryption', 'op': '=', 'expected': 'Disabled', 'topic': r'reversibl',
     'policy': r'(reversible)'},
]


def _norm(s):
    return re.sub(r'\s+', ' ', s or '').strip()


def _sentences(text):
    """Split extracted document text into sentences, tracking the page each starts on."""
    page, out = None, []
    for block in re.split(r'\n\s*\n', text or ''):
        m = re.match(r'--- Page (\d+) ---', block.strip())
        if m:
            page = int(m[1])
            block = block.strip()[m.end():]
        # Lines with column gaps are table rows (setting  value): keep them whole. Other lines are
        # wrapped prose, joined and split into sentences.
        prose = []
        for line in block.splitlines() + [None]:  # None flushes the last prose
            if line is None or '    ' in line.strip():
                for s in re.split(r'(?<=[.;])\s+(?=[A-Z0-9(])', _norm(' '.join(prose))):
                    if s:
                        out.append((s, page))
                prose = []
                if line and line.strip():
                    out.append((_norm(line), page))
            else:
                prose.append(line)
    return out


def _is_setting_line(sentence, label):
    """True for '<setting name> <short value>' lines from settings screens/reports, which can contain 'must'."""
    low = sentence.lower()
    i = low.find(label.lower())
    return i >= 0 and i < 15 and len(low[i + len(label):].split()) <= 4


def suggest(files):
    """Propose checks from policy text. files: [{'id','name','text'}]. Returns proposals with the source sentence."""
    found = {}
    for f in files:
        if f.get('kind') == 'image':
            continue  # screenshots show settings, not requirements
        for sentence, page in _sentences(f['text']):
            if not _MODAL.search(sentence):
                continue  # policies say what *must* happen
            for item in LIBRARY:
                if item['key'] in found or not re.search(item['topic'], sentence, re.I):
                    continue
                if _is_setting_line(sentence, item['label']):
                    continue  # e.g. "Password must meet complexity requirements  Enabled" in a settings report
                m = re.search(item['policy'], sentence, re.I)
                if not m:
                    continue
                expected = item.get('expected') or m.group(1)
                ref = f"{f['name']}{f', page {page}' if page else ''}: \"{sentence[:300]}\""
                found[item['key']] = {'label': item['label'], 'match_text': item['label'], 'operator': item['op'],
                                      'expected': expected, 'unit': item.get('unit', ''), 'policy_ref': ref}
    return [found[i['key']] for i in LIBRARY if i['key'] in found]


_NUM = re.compile(r'-?\d+(?:[.,]\d+)?')
_OCR_DIGITS = {'I': '1', 'l': '1', '|': '1', 'O': '0', 'o': '0'}


def _value_after(rest, numeric):
    """The value following a setting's label on the same line. Returns (value, note)."""
    rest = rest.strip(' :\t-=|')
    if re.match(r'not (defined|configured|set)', rest, re.I):
        return 'Not defined', None
    if numeric:
        m = _NUM.search(rest)
        if m and m.start() < 40:
            return float(m.group(0).replace(',', '.')), None
        # OCR sometimes reads "1 days" as "I days"
        m = re.match(r'([Il|Oo])\s+[A-Za-z]', rest)
        if m:
            return float(_OCR_DIGITS[m.group(1)]), f'read "{m.group(0)}" as {_OCR_DIGITS[m.group(1)]}; verify against the image'
        return None, None
    m = re.match(r'([A-Za-z][\w-]*)', rest)
    return (m.group(1), None) if m else (None, None)


def _is_number(s):
    return bool(re.fullmatch(r'\s*-?\d+(?:[.,]\d+)?\s*', str(s or '')))


def evaluate(rule, files):
    """Find the actual value for one rule in evidence text and compare it with the expected value.

    rule: {'label','match_text','operator','expected','file_id'}; files: [{'id','name','text','kind'}] in priority order.
    Returns {'check_result': 'Pass'|'Exception'|'Not found', 'check_actual', 'check_source_file_id', 'check_source_line', 'check_note'}.
    """
    needle = _norm(rule.get('match_text') or rule['label']).lower()
    op = rule.get('operator') or '='
    expected = str(rule.get('expected') or '').strip()
    numeric = op in ('>=', '<=') or _is_number(expected)
    candidates = [f for f in files if not rule.get('file_id') or f['id'] == rule['file_id']]
    for f in candidates:
        for line in (f['text'] or '').splitlines():
            flat = _norm(line)
            pos = flat.lower().find(needle)
            if pos < 0:
                continue
            actual, note = _value_after(flat[pos + len(needle):], numeric)
            if actual is None:
                continue
            res = {'check_actual': (f'{actual:g}' if isinstance(actual, float) else actual), 'check_source_file_id': f['id'],
                   'check_source_line': flat[:500], 'check_note': note}
            if actual == 'Not defined':
                res['check_result'] = 'Exception'
                res['check_note'] = 'Setting is not defined on the system.'
            elif numeric:
                if not _is_number(expected):
                    res.update(check_result='Not found', check_note='Expected value must be a number for this operator.')
                    return res
                e = float(expected.replace(',', '.'))
                ok = {'>=': actual >= e, '<=': actual <= e, '=': actual == e, '!=': actual != e}[op]
                res['check_result'] = 'Pass' if ok else 'Exception'
            else:
                same = str(actual).lower() == expected.lower()
                res['check_result'] = 'Pass' if same == (op != '!=') else 'Exception'
            return res
    where = 'the selected file' if rule.get('file_id') else "this test's screenshots and documents"
    return {'check_result': 'Not found', 'check_actual': None, 'check_source_file_id': None, 'check_source_line': None,
            'check_note': f'"{rule.get("match_text") or rule["label"]}" was not found with a readable value in {where}.'}
