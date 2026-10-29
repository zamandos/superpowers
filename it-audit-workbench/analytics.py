"""Audit analytics on evidence extractions: table reading, reproducible sampling, access tests.

Standard library only. Reads CSV/TSV and .xlsx files; parses the date and status formats
that directory and HR extractions typically use.
"""
import csv
import hashlib
import io
import re
import zipfile
from datetime import date, datetime, timedelta, timezone
from xml.etree import ElementTree as ET

MAX_ROWS = 1_000_000


class DataError(ValueError):
    """A problem with the data the auditor supplied; the message is shown to them."""


# ---------- reading tables ----------
def _decode(raw):
    for enc in ('utf-8-sig', 'utf-16') if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else ('utf-8-sig', 'cp1252'):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode('latin-1')


def _read_csv(raw):
    text = _decode(raw)
    sample = text[:20000]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
    except csv.Error:
        dialect = csv.excel
    rows = [r for r in csv.reader(io.StringIO(text), dialect) if any(c.strip() for c in r)]
    if not rows:
        raise DataError('The file has no rows.')
    return rows


_NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
       'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
       'rel': 'http://schemas.openxmlformats.org/package/2006/relationships'}


def _col_index(ref):
    n = 0
    for ch in re.match(r'[A-Z]+', ref).group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1


def xlsx_sheets(z):
    wb = ET.fromstring(z.read('xl/workbook.xml'))
    rels = ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))
    targets = {r.get('Id'): r.get('Target') for r in rels.findall('rel:Relationship', _NS)}
    out = []
    for s in wb.findall('m:sheets/m:sheet', _NS):
        t = targets.get(s.get('{%s}id' % _NS['r']), '')
        t = t.lstrip('/')
        out.append((s.get('name'), t if t.startswith('xl/') else 'xl/' + t))
    return out


_BUILTIN_DATE_FORMATS = set(range(14, 23)) | {45, 46, 47}


def _xlsx_date_styles(z):
    """Indexes of cell styles that display numbers as dates or times."""
    if 'xl/styles.xml' not in z.namelist():
        return set()
    st = ET.fromstring(z.read('xl/styles.xml'))
    custom = {int(f.get('numFmtId')): f.get('formatCode', '') for f in st.findall('m:numFmts/m:numFmt', _NS)}
    is_date = lambda fid: fid in _BUILTIN_DATE_FORMATS or (
        fid in custom and re.search(r'[dmyhs]', re.sub(r'"[^"]*"|\[[^]]*\]|\\.', '', custom[fid]), re.I) is not None)
    xfs = st.findall('m:cellXfs/m:xf', _NS)
    return {i for i, xf in enumerate(xfs) if is_date(int(xf.get('numFmtId', 0)))}


def _serial_text(n):
    d = datetime(1899, 12, 30) + timedelta(days=n)
    return d.strftime('%Y-%m-%d %H:%M:%S') if n % 1 else d.strftime('%Y-%m-%d')


def _read_xlsx(raw, sheet=None):
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
        sheets = xlsx_sheets(z)
    except (zipfile.BadZipFile, KeyError, ET.ParseError):
        raise DataError('This Excel file could not be read. Save it as .xlsx or CSV and attach it again.')
    if not sheets:
        raise DataError('The workbook has no sheets.')
    names = [n for n, _ in sheets]
    path = dict(sheets).get(sheet) if sheet else sheets[0][1]
    if not path:
        raise DataError(f'Sheet "{sheet}" not found.')
    date_styles = _xlsx_date_styles(z)
    shared = []
    if 'xl/sharedStrings.xml' in z.namelist():
        for si in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('m:si', _NS):
            shared.append(''.join(t.text or '' for t in si.iter('{%s}t' % _NS['m'])))
    rows = []
    for row in ET.fromstring(z.read(path)).iter('{%s}row' % _NS['m']):
        cells = {}
        for c in row.findall('m:c', _NS):
            t, v = c.get('t'), c.find('m:v', _NS)
            if t == 'inlineStr':
                val = ''.join(x.text or '' for x in c.iter('{%s}t' % _NS['m']))
            elif v is None:
                val = ''
            elif t == 's':
                val = shared[int(v.text)]
            elif t == 'b':
                val = 'TRUE' if v.text == '1' else 'FALSE'
            else:
                val = v.text or ''
                if c.get('s') and int(c.get('s')) in date_styles and re.fullmatch(r'\d+(\.\d+)?', val):
                    val = _serial_text(float(val))  # a date cell: show it as a date, not a serial number
                elif re.fullmatch(r'-?\d+\.0', val):
                    val = val[:-2]
            cells[_col_index(c.get('r'))] = val
        if cells and any(str(x).strip() for x in cells.values()):
            width = max(cells) + 1
            rows.append([cells.get(i, '') for i in range(width)])
        if len(rows) > MAX_ROWS:
            break
    if not rows:
        raise DataError(f'Sheet "{sheet or names[0]}" is empty.')
    return rows, names


def read_table(raw, name, sheet=None):
    """Return {'headers', 'rows' (list of lists, padded), 'sheets', 'sheet'} from CSV/TSV/XLSX bytes."""
    sheets = None
    if raw[:2] != b'PK' and (b'\x00' in raw[:4096] and raw[:2] not in (b'\xff\xfe', b'\xfe\xff')
                             or raw[:5] == b'%PDF-' or raw[:4] in (b'\x89PNG', b'GIF8') or raw[:3] == b'\xff\xd8\xff'):
        raise DataError('This is not a CSV or Excel file. Attach the extraction as .csv or .xlsx.')
    if raw[:2] == b'PK':
        rows, sheets = _read_xlsx(raw, sheet)
        sheet = sheet or sheets[0]
    elif re.search(r'\.(xls)$', name or '', re.I) or raw[:4] == b'\xd0\xcf\x11\xe0':
        raise DataError('Old .xls workbooks are not supported. Save it as .xlsx or CSV and attach it again.')
    else:
        rows = _read_csv(raw)
    if len(rows) - 1 > MAX_ROWS:
        raise DataError(f'More than {MAX_ROWS:,} rows; split the extraction.')
    headers = [h.strip() or f'Column {i + 1}' for i, h in enumerate(rows[0])]
    seen = {}
    for i, h in enumerate(headers):  # make duplicate headers distinct
        if h in seen:
            seen[h] += 1
            headers[i] = f'{h} ({seen[h]})'
        else:
            seen[h] = 1
    width = max(len(headers), *(len(r) for r in rows)) if rows else len(headers)
    headers += [f'Column {i + 1}' for i in range(len(headers), width)]
    data = [[str(c).strip() for c in r] + [''] * (width - len(r)) for r in rows[1:]]
    return {'headers': headers, 'rows': data, 'sheets': sheets, 'sheet': sheet}


def column(table, name):
    if name not in table['headers']:
        raise DataError(f'Column "{name}" not found.')
    return table['headers'].index(name)


# ---------- reproducible sampling ----------
SAMPLE_METHOD = ('Simple random sample without replacement. Each population row n (1 = first data row) is ranked by '
                 'SHA-256("<seed>:<n>"); the rows with the lowest hashes are selected.')


def draw_sample(population_rows, size, seed):
    """Row numbers (1-based) of a reproducible random sample. Anyone can re-perform it from the method text."""
    if population_rows < 1:
        raise DataError('The population is empty.')
    if size < 1:
        raise DataError('Sample size must be at least 1.')
    if size > population_rows:
        raise DataError(f'Sample size {size} is larger than the population ({population_rows} rows).')
    seed = str(seed)
    ranked = sorted(range(1, population_rows + 1), key=lambda n: hashlib.sha256(f'{seed}:{n}'.encode()).digest())
    return sorted(ranked[:size])


# ---------- parsing values ----------
_MONTHS = {m: i for i, m in enumerate(['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'], 1)}
_NEVER = {'', 'never', 'n/a', 'na', 'null', 'none', '-', '0', '(never)', 'not set'}
DATE_FORMATS = ('auto', 'YYYY-MM-DD', 'DD/MM/YYYY', 'MM/DD/YYYY')


def _num_date(v):
    """Excel serial day or Windows FILETIME (AD lastLogonTimestamp)."""
    n = int(float(v))
    if n > 10 ** 15:  # FILETIME: 100-ns intervals since 1601
        if n >= 9223372036854775807:
            return None
        return datetime.fromtimestamp(n / 1e7 - 11644473600, tz=timezone.utc).date()
    if 1 <= n < 2958466:
        return date(1899, 12, 30) + timedelta(days=n)
    raise ValueError


def parse_date(value, fmt='auto'):
    """Parse one date; returns None for blanks/'never'. Raises ValueError when unreadable."""
    v = str(value).strip()
    if v.lower() in _NEVER:
        return None
    if re.fullmatch(r'(19|20)\d{6}', v):  # YYYYMMDD
        return date(int(v[:4]), int(v[4:6]), int(v[6:]))
    if re.fullmatch(r'\d+(\.\d+)?', v):
        return _num_date(v)
    m = re.match(r'(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})', v)
    if m:
        d = date(int(m[1]), int(m[2]), int(m[3]))
        return None if d.year <= 1601 else d
    m = re.match(r'(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})', v)
    if m:
        a, b, y = int(m[1]), int(m[2]), int(m[3])
        y += 2000 if y < 100 else 0
        if fmt == 'MM/DD/YYYY' or (fmt == 'auto' and a <= 12 < b):
            return date(y, a, b)
        return date(y, b, a)
    m = re.match(r'(\d{1,2})[ -]([A-Za-z]{3,9})[ ,-]*(\d{4})', v) or None
    if m and m[2][:3].lower() in _MONTHS:
        return date(int(m[3]), _MONTHS[m[2][:3].lower()], int(m[1]))
    m = re.match(r'([A-Za-z]{3,9})[ .]+(\d{1,2}),?\s+(\d{4})', v)
    if m and m[1][:3].lower() in _MONTHS:
        return date(int(m[3]), _MONTHS[m[1][:3].lower()], int(m[2]))
    raise ValueError(v)


def detect_date_format(values):
    """Decide day/month order for slash dates in a column. Raises DataError if it can't be told."""
    dmy = mdy = ambiguous = False
    for v in values:
        m = re.match(r'\s*(\d{1,2})[-/.](\d{1,2})[-/.]\d{2,4}', str(v))
        if not m:
            continue
        a, b = int(m[1]), int(m[2])
        if a > 12:
            dmy = True
        elif b > 12:
            mdy = True
        elif a != b:
            ambiguous = True
    if dmy and mdy:
        raise DataError('The column mixes day-first and month-first dates.')
    if dmy:
        return 'DD/MM/YYYY'
    if mdy:
        return 'MM/DD/YYYY'
    if ambiguous:
        return None  # caller must ask the auditor
    return 'auto'


_TRUE = {'true', 'yes', 'y', '1', 'enabled', 'enable', 'active', 'on'}
_FALSE = {'false', 'no', 'n', '0', 'disabled', 'disable', 'inactive', 'off', 'locked', 'suspended', 'terminated'}


def parse_enabled(value, means='enabled'):
    """True if the account is enabled. 'means' says whether the column is an enabled or a disabled flag.
    Numeric AD userAccountControl values (>= 512) use the ACCOUNTDISABLE bit."""
    v = str(value).strip().lower()
    if re.fullmatch(r'\d+', v) and int(v) >= 512:
        return not int(v) & 2
    if v in _TRUE:
        flag = True
    elif v in _FALSE:
        flag = False
    else:
        return None
    return flag if means == 'enabled' else not flag


def norm_account(value):
    """Compare accounts across systems: CORP\\jsmith, jsmith@corp.com and JSmith all become 'jsmith'."""
    v = str(value).strip().lower()
    v = v.rsplit('\\', 1)[-1]
    return v.split('@', 1)[0].strip()


GENERIC = re.compile(r'(^|[._-])(admin|administrator|test|testing|temp|tmp|shared|generic|guest|training|demo|'
                     r'service|svc|support|helpdesk|scanner|kiosk|user\d*|default)([._-]|\d|$)')


# ---------- access test: leavers and dormant accounts ----------
def _dates(table, col, fmt, label, warnings):
    i = column(table, col)
    values = [r[i] for r in table['rows']]
    if fmt == 'auto':
        detected = detect_date_format(values)
        if detected is None:
            raise DataError(f'Dates in "{col}" could be day-first or month-first (e.g. 03/04/2026). '
                            'Choose the date format and run again.')
        fmt = detected
    out, bad = [], 0
    for v in values:
        try:
            out.append(parse_date(v, fmt))
        except (ValueError, OverflowError):
            out.append(None)
            bad += 1
    if bad:
        warnings.append(f'{bad} value(s) in {label} "{col}" could not be read as dates and were treated as blank.')
    return out


def access_test(users, leavers, m, as_at, sla_days=1, dormant_days=90):
    """Compare an account extraction with an HR leavers list.

    m: column mapping with keys user_key, user_enabled, user_last_logon, user_disabled_on, user_name,
       enabled_means, leaver_key, leaver_term_date, date_format (optional ones may be empty).
    Returns {'summary', 'checks', 'exceptions', 'unmatched_leavers', 'warnings', 'counts'}.
    """
    fmt = m.get('date_format') or 'auto'
    warnings = []
    uk = column(users, m['user_key'])
    ue = column(users, m['user_enabled']) if m.get('user_enabled') else None
    un = column(users, m['user_name']) if m.get('user_name') else None
    last = _dates(users, m['user_last_logon'], fmt, 'account list', warnings) if m.get('user_last_logon') else None
    disabled_on = _dates(users, m['user_disabled_on'], fmt, 'account list', warnings) if m.get('user_disabled_on') else None
    lk = column(leavers, m['leaver_key'])
    terms = _dates(leavers, m['leaver_term_date'], fmt, 'leavers list', warnings)

    accounts = {}
    for idx, r in enumerate(users['rows']):
        key = norm_account(r[uk])
        if key:
            accounts.setdefault(key, []).append(idx)
    enabled = []
    unknown_status = 0
    for r in users['rows']:
        e = parse_enabled(r[ue], m.get('enabled_means') or 'enabled') if ue is not None else True
        if e is None:
            unknown_status += 1
        enabled.append(e)
    if unknown_status:
        warnings.append(f'{unknown_status} account(s) have an unrecognised status in "{m["user_enabled"]}" and were not '
                        'treated as enabled or disabled.')

    sla = timedelta(days=int(sla_days))
    exc, unmatched, matched = [], [], 0

    def add(check, idx_u, leaver_term=None, detail=''):
        r = users['rows'][idx_u]
        exc.append({'check': check, 'account': r[uk], 'name': r[un] if un is not None else '',
                    'termination_date': leaver_term.isoformat() if leaver_term else '',
                    'enabled': {True: 'Yes', False: 'No', None: 'Unknown'}[enabled[idx_u]],
                    'last_logon': last[idx_u].isoformat() if last and last[idx_u] else '',
                    'account_row': idx_u + 1, 'detail': detail})

    for li, r in enumerate(leavers['rows']):
        key, term = norm_account(r[lk]), terms[li]
        if not key:
            continue
        if term is None:
            warnings.append(f'Leaver "{r[lk]}" (row {li + 1}) has no readable termination date and was skipped.')
            continue
        if term > as_at:
            continue  # leaves after the extraction date: not yet due
        hits = accounts.get(key)
        if not hits:
            unmatched.append({'leaver': r[lk], 'termination_date': term.isoformat(), 'row': li + 1})
            continue
        matched += 1
        for i in hits:
            days_since = (as_at - term).days
            if enabled[i] and as_at - term > sla:
                add('Leaver account still enabled', i, term, f'Terminated {term.isoformat()}; still enabled on {as_at.isoformat()} '
                    f'({days_since} days after termination, SLA {sla_days} day(s)).')
            if last and last[i] and last[i] > term:
                add('Logon after termination', i, term, f'Last logon {last[i].isoformat()}, {(last[i] - term).days} day(s) after termination.')
            if disabled_on and disabled_on[i] and disabled_on[i] - term > sla:
                add('Disabled late', i, term, f'Disabled {disabled_on[i].isoformat()}, {(disabled_on[i] - term).days} days after '
                    f'termination (SLA {sla_days} day(s)).')

    leaver_keys = {norm_account(r[lk]) for r in leavers['rows']}
    if last is not None:
        cutoff = as_at - timedelta(days=int(dormant_days))
        for i, r in enumerate(users['rows']):
            if enabled[i] and norm_account(r[uk]) not in leaver_keys and (last[i] is None or last[i] < cutoff):
                add('Dormant enabled account', i, None, 'Never logged on.' if last[i] is None else
                    f'Last logon {last[i].isoformat()} ({(as_at - last[i]).days} days before {as_at.isoformat()}; threshold {dormant_days}).')
    for i, r in enumerate(users['rows']):
        if enabled[i] and GENERIC.search(norm_account(r[uk])):
            add('Possible generic or shared account', i, None, 'Account name suggests a generic, test or shared account; confirm '
                'it has a named owner and business justification.')

    checks = ['Leaver account still enabled', 'Logon after termination', 'Disabled late', 'Dormant enabled account',
              'Possible generic or shared account']
    counts = {c: sum(1 for e in exc if e['check'] == c) for c in checks}
    return {'counts': counts, 'exceptions': exc, 'unmatched_leavers': unmatched, 'warnings': warnings,
            'summary': {'accounts': len(users['rows']), 'enabled_accounts': sum(1 for e in enabled if e),
                        'leavers': len(leavers['rows']), 'leavers_due': matched + len(unmatched), 'leavers_matched': matched,
                        'leavers_unmatched': len(unmatched), 'as_at': as_at.isoformat(), 'sla_days': int(sla_days),
                        'dormant_days': int(dormant_days), 'date_format': fmt,
                        'checks_run': [c for c in checks if (c != 'Dormant enabled account' or last is not None)
                                       and (c != 'Logon after termination' or last is not None)
                                       and (c != 'Disabled late' or disabled_on is not None)]}}


def exceptions_csv(result):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['Check', 'Account', 'Name', 'Termination date', 'Enabled', 'Last logon', 'Account list row', 'Detail'])
    for e in result['exceptions']:
        w.writerow([e['check'], e['account'], e['name'], e['termination_date'], e['enabled'], e['last_logon'], e['account_row'], e['detail']])
    for u in result['unmatched_leavers']:
        w.writerow(['Leaver not found in account list (check manually)', u['leaver'], '', u['termination_date'], '', '', '', f"Leavers list row {u['row']}"])
    return out.getvalue().encode('utf-8-sig')


def guess_column(headers, kind):
    """Best-guess column for a role, from common extraction header names."""
    patterns = {
        'user_key': [r'^sam ?account ?name$', r'^(user ?name|username|user ?id|login|logon ?name|account( ?name)?)$', r'principal', r'^e-?mail'],
        'user_enabled': [r'^enabled$', r'^(account ?)?status$', r'useraccountcontrol', r'disabled', r'active'],
        'user_last_logon': [r'last ?logon', r'last ?log ?in', r'last ?sign', r'last ?login', r'lastlogontimestamp'],
        'user_disabled_on': [r'disabled ?(on|date)', r'when ?changed', r'deactivat'],
        'user_name': [r'^(display ?name|full ?name|name)$', r'^name'],
        'leaver_key': [r'^sam ?account ?name$', r'^(user ?name|username|user ?id|login|network ?id|ad ?account|account)$', r'^e-?mail', r'employee'],
        'leaver_term_date': [r'termination', r'term(ination)? ?date', r'leav(e|ing) ?date', r'end ?date', r'last ?(working )?day', r'exit'],
    }[kind]
    for p in patterns:
        for h in headers:
            if re.search(p, h.strip().lower()):
                return h
    return ''
