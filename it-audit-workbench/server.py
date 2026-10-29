#!/usr/bin/env python3
"""Audit Workbench: a self-hosted, multi-user IT audit management server.

Uses only the Python standard library (3.9+). Data lives in a SQLite database
and an evidence folder under --data (default: ./data).

    python3 server.py                     # http://127.0.0.1:8080
    python3 server.py --host 0.0.0.0      # share on the network (put HTTPS in front)
"""
import argparse
import contextlib
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

from ocr import PDF, OcrEngine, kind_of, sniff, sniff_image

ROOT = Path(__file__).resolve().parent
STATIC = {'/': 'index.html', '/app.js': 'app.js', '/app.css': 'app.css'}
CONTENT_TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8'}
MAX_UPLOAD = 50 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
MAX_FIELD = 50_000
SESSION_HOURS = 12
MIN_PASSWORD = 10

ROLES = ('admin', 'manager', 'auditor', 'auditee')
STAFF = ('admin', 'manager', 'auditor')
MGMT = ('admin', 'manager')

# Writable columns per table. Every table also gets id, created_*/updated_* columns.
TABLES = {
    'universe': ['name', 'category', 'owner', 'description', 'likelihood', 'impact', 'frequency', 'last_audited', 'notes'],
    'plan': ['year', 'universe_id', 'title', 'quarter', 'budget_hours', 'lead_id', 'status', 'engagement_id', 'notes'],
    'engagements': ['name', 'universe_id', 'auditee', 'framework', 'status', 'period_start', 'period_end', 'field_start',
                    'field_end', 'lead_id', 'team', 'budget_hours', 'objectives', 'scope', 'out_of_scope'],
    'risks': ['engagement_id', 'area', 'system', 'description', 'likelihood', 'impact', 'response'],
    'workpapers': ['engagement_id', 'risk_id', 'ref', 'title', 'control_desc', 'framework_ref', 'nature', 'frequency',
                   'key_control', 'test_type', 'procedure', 'population', 'sample_size', 'exceptions', 'assigned_to',
                   'due_date', 'status', 'result', 'notes',
                   'prepared_by', 'prepared_at', 'reviewed_by', 'reviewed_at'],
    'evidence': ['engagement_id', 'workpaper_id', 'issue_id', 'title', 'purpose', 'type', 'pbc_status', 'requested_from', 'requested_on',
                 'collected_by', 'collected_on', 'notes'],
    'files': ['evidence_id', 'engagement_id', 'name', 'size', 'content_type', 'sha256',
              'kind', 'pages', 'ocr_status', 'ocr_text', 'ocr_confidence', 'ocr_method', 'ocr_engine', 'ocr_at'],
    'review_notes': ['engagement_id', 'workpaper_id', 'note', 'status', 'response',
                     'responded_by', 'responded_at', 'cleared_by', 'cleared_at'],
    'issues': ['engagement_id', 'workpaper_id', 'title', 'condition', 'criteria', 'cause', 'effect', 'likelihood', 'impact',
               'recommendation', 'owner_id', 'due_date', 'status', 'response', 'validated_by', 'validated_at'],
    'time_entries': ['engagement_id', 'user_id', 'date', 'hours', 'activity', 'notes'],
}
# Set only by server workflows (sign-off, review notes, validation, uploads), never by a plain edit.
SYSTEM = {'prepared_by', 'prepared_at', 'reviewed_by', 'reviewed_at', 'responded_by', 'responded_at',
          'cleared_by', 'cleared_at', 'validated_by', 'validated_at'}
ENGAGEMENT_CHILDREN = ['risks', 'workpapers', 'evidence', 'files', 'review_notes', 'issues', 'time_entries']
# Editing any other workpaper field after sign-off invalidates the sign-offs.
WP_ADMIN_FIELDS = {'assigned_to', 'due_date', 'status'}
AUDITEE_STATUSES = ('Remediation in progress', 'Ready for validation')


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def new_id():
    return uuid.uuid4().hex


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 240_000).hex()
    return f'{salt}${digest}'


def check_password(password, stored):
    salt = stored.split('$', 1)[0]
    return hmac.compare_digest(hash_password(password, salt), stored)


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Workbench:
    """Data access, permissions and audit workflows. HTTP-agnostic so it can be tested directly."""

    def __init__(self, data_dir, ocr=None):
        self.data_dir = Path(data_dir)
        self.file_dir = self.data_dir / 'evidence'
        self.file_dir.mkdir(parents=True, exist_ok=True)
        self.preview_dir = self.data_dir / 'previews'  # rendered PDF pages; safe to delete, rebuilt on demand
        self.preview_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / 'audit.db'
        self.failures = {}
        self.lock = threading.Lock()
        with self.db() as c:
            self._schema(c)
        self.ocr = ocr or OcrEngine()
        self.ocr_queue = queue.Queue()
        threading.Thread(target=self._ocr_worker, daemon=True).start()
        with self.db() as c:  # resume OCR interrupted by a restart
            pending = [r['id'] for r in c.execute("SELECT id FROM files WHERE ocr_status IN ('queued', 'running')")]
        for fid in pending:
            self.ocr_queue.put(fid)

    @contextlib.contextmanager
    def db(self):
        c = sqlite3.connect(self.db_path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA journal_mode=WAL')
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def _schema(self, c):
        meta = 'id TEXT PRIMARY KEY, created_at TEXT, created_by TEXT, updated_at TEXT, updated_by TEXT'
        for t, cols in TABLES.items():
            c.execute(f'CREATE TABLE IF NOT EXISTS {t} ({meta}, {", ".join(col + " TEXT" for col in cols)})')
            have = {r['name'] for r in c.execute(f'PRAGMA table_info({t})')}
            for col in cols:
                if col not in have:
                    c.execute(f'ALTER TABLE {t} ADD COLUMN {col} TEXT')
            if 'engagement_id' in cols:
                c.execute(f'CREATE INDEX IF NOT EXISTS ix_{t}_eng ON {t}(engagement_id)')
        c.execute('''CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, name TEXT,
                     email TEXT, role TEXT, password TEXT, active INTEGER DEFAULT 1, must_change INTEGER DEFAULT 0, created_at TEXT)''')
        c.execute('CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT, expires TEXT)')
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, user_id TEXT,
                     user_name TEXT, action TEXT, table_name TEXT, record_id TEXT, engagement_id TEXT, detail TEXT)''')
        c.execute('CREATE INDEX IF NOT EXISTS ix_log_record ON audit_log(record_id)')

    # ---------- users & sessions ----------
    def bootstrap_admin(self, password=None):
        """Create the first admin account if there are no users. Returns the password, or None."""
        with self.db() as c:
            if c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                return None
            password = password or secrets.token_urlsafe(12)
            c.execute('INSERT INTO users (id, username, name, role, password, must_change, created_at) VALUES (?,?,?,?,?,1,?)',
                      (new_id(), 'admin', 'Administrator', 'admin', hash_password(password), now()))
            return password

    def login(self, username, password):
        key = (username or '').lower()
        count, until = self.failures.get(key, (0, 0))
        if until > time.time():
            raise ApiError(429, 'Too many failed attempts. Try again in a few minutes.')
        with self.db() as c:
            u = c.execute('SELECT * FROM users WHERE username = ?', (username or '',)).fetchone()
            if not u or not u['active'] or not check_password(password or '', u['password']):
                count += 1
                self.failures[key] = (count, time.time() + 300 if count >= 5 else 0)
                raise ApiError(401, 'Invalid username or password.')
            self.failures.pop(key, None)
            token = secrets.token_urlsafe(32)
            expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()
            c.execute('DELETE FROM sessions WHERE expires < ?', (now(),))
            c.execute('INSERT INTO sessions VALUES (?,?,?)', (self._th(token), u['id'], expires))
            self._log(c, dict(u), 'login', 'users', u['id'])
            return token

    @staticmethod
    def _th(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def session_user(self, token):
        if not token:
            return None
        with self.db() as c:
            r = c.execute('''SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                             WHERE s.token_hash = ? AND s.expires > ? AND u.active = 1''', (self._th(token), now())).fetchone()
            return self._public_user(r, full=True) if r else None

    def logout(self, token):
        with self.db() as c:
            c.execute('DELETE FROM sessions WHERE token_hash = ?', (self._th(token or ''),))

    @staticmethod
    def _public_user(r, full=False):
        u = {k: r[k] for k in ('id', 'username', 'name', 'role', 'active')}
        if full:
            u.update(email=r['email'], must_change=bool(r['must_change']))
        return u

    def list_users(self, user):
        with self.db() as c:
            rows = c.execute('SELECT * FROM users ORDER BY name COLLATE NOCASE').fetchall()
        if user['role'] == 'auditee':
            rows = [r for r in rows if r['id'] == user['id']]
        return [self._public_user(r, full=user['role'] == 'admin') for r in rows]

    def save_user(self, user, body, uid=None):
        if user['role'] != 'admin':
            raise ApiError(403, 'Only administrators can manage users.')
        role = body.get('role')
        if role is not None and role not in ROLES:
            raise ApiError(400, 'Invalid role.')
        pw = body.get('password')
        if pw is not None and len(pw) < MIN_PASSWORD:
            raise ApiError(400, f'Password must be at least {MIN_PASSWORD} characters.')
        with self.db() as c:
            if uid is None:
                username = (body.get('username') or '').strip()
                if not re.fullmatch(r'[A-Za-z0-9._@-]{2,64}', username):
                    raise ApiError(400, 'Username must be 2-64 letters, digits or . _ @ -')
                if not pw or not role:
                    raise ApiError(400, 'Role and initial password are required.')
                if c.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
                    raise ApiError(409, 'That username is taken.')
                uid = new_id()
                c.execute('INSERT INTO users (id, username, name, email, role, password, must_change, created_at) VALUES (?,?,?,?,?,?,1,?)',
                          (uid, username, body.get('name') or username, body.get('email'), role, hash_password(pw), now()))
                self._log(c, user, 'create', 'users', uid, detail={'username': username, 'role': role})
            else:
                old = c.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
                if not old:
                    raise ApiError(404, 'User not found.')
                if uid == user['id'] and (role not in (None, 'admin') or body.get('active') in (0, False)):
                    raise ApiError(400, 'You cannot demote or deactivate your own account.')
                sets, vals, detail = [], [], {}
                for k in ('name', 'email', 'role'):
                    if k in body and body[k] != old[k]:
                        sets.append(f'{k} = ?'); vals.append(body[k]); detail[k] = [old[k], body[k]]
                if 'active' in body:
                    active = 1 if body['active'] else 0
                    if active != old['active']:
                        sets.append('active = ?'); vals.append(active); detail['active'] = [old['active'], active]
                if pw:
                    sets += ['password = ?', 'must_change = 1']; vals.append(hash_password(pw)); detail['password'] = 'reset'
                if sets:
                    c.execute(f'UPDATE users SET {", ".join(sets)} WHERE id = ?', (*vals, uid))
                    if 'active' in detail or pw:
                        c.execute('DELETE FROM sessions WHERE user_id = ?', (uid,))
                    self._log(c, user, 'update', 'users', uid, detail=detail)
            return self._public_user(c.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone(), full=True)

    def change_password(self, user, old, new):
        if not new or len(new) < MIN_PASSWORD:
            raise ApiError(400, f'Password must be at least {MIN_PASSWORD} characters.')
        with self.db() as c:
            r = c.execute('SELECT password FROM users WHERE id = ?', (user['id'],)).fetchone()
            if not check_password(old or '', r['password']):
                raise ApiError(400, 'Current password is incorrect.')
            if old == new:
                raise ApiError(400, 'Choose a different password.')
            c.execute('UPDATE users SET password = ?, must_change = 0 WHERE id = ?', (hash_password(new), user['id']))
            self._log(c, user, 'change_password', 'users', user['id'])

    # ---------- audit trail ----------
    def _log(self, c, user, action, table, record_id, engagement_id=None, detail=None):
        c.execute('INSERT INTO audit_log (ts, user_id, user_name, action, table_name, record_id, engagement_id, detail) VALUES (?,?,?,?,?,?,?,?)',
                  (now(), user['id'], user.get('name') or user.get('username'), action, table, record_id, engagement_id,
                   json.dumps(detail) if detail else None))

    def audit_log(self, user, record_id=None, engagement_id=None, limit=500):
        if user['role'] not in MGMT and not (user['role'] in STAFF and record_id):
            raise ApiError(403, 'Not permitted.')
        q, args = 'SELECT * FROM audit_log WHERE 1=1', []
        if record_id:
            q += ' AND record_id = ?'; args.append(record_id)
        if engagement_id:
            q += ' AND engagement_id = ?'; args.append(engagement_id)
        q += ' ORDER BY id DESC LIMIT ?'; args.append(min(int(limit), 2000))
        with self.db() as c:
            return [dict(r) for r in c.execute(q, args)]

    # ---------- generic records ----------
    def _check_table(self, table):
        if table not in TABLES:
            raise ApiError(404, 'Unknown resource.')

    @staticmethod
    def _row(c, table, rid):
        r = c.execute(f'SELECT * FROM {table} WHERE id = ?', (rid,)).fetchone()
        if not r:
            raise ApiError(404, 'Record not found.')
        return dict(r)

    def list(self, user, table, filters):
        self._check_table(table)
        role = user['role']
        q, args = f'SELECT * FROM {table} WHERE 1=1', []
        if role == 'auditee':
            if table == 'issues':
                q += ' AND owner_id = ?'; args.append(user['id'])
            elif table == 'engagements':
                q = 'SELECT id, name, auditee FROM engagements WHERE id IN (SELECT engagement_id FROM issues WHERE owner_id = ?)'
                args.append(user['id'])
            else:
                raise ApiError(403, 'Not permitted.')
        for k, v in filters.items():
            if k in TABLES[table] or k == 'id':
                q += f' AND {k} = ?'; args.append(v)
        q += ' ORDER BY created_at' if role != 'auditee' or table != 'engagements' else ''
        with self.db() as c:
            return [dict(r) for r in c.execute(q, args)]

    def get(self, user, table, rid):
        rows = self.list(user, table, {'id': rid})
        if not rows:
            raise ApiError(404, 'Record not found.')
        return rows[0]

    def _clean(self, table, body):
        out = {}
        for k, v in (body or {}).items():
            if k not in TABLES[table] or k in SYSTEM:
                continue
            if v is not None and not isinstance(v, str):
                v = str(v)
            if v is not None and len(v) > MAX_FIELD:
                raise ApiError(400, f'{k} is too long.')
            out[k] = v if v != '' else None
        return out

    def _can_write(self, user, table, action, row):
        role = user['role']
        if role == 'auditee':
            return table == 'issues' and action == 'update' and row.get('owner_id') == user['id']
        if table in ('universe', 'plan'):
            return role in MGMT
        if table == 'engagements':
            return role in MGMT or (action == 'update' and row.get('lead_id') == user['id'])
        if table == 'files':
            return False
        if table == 'time_entries' and role not in MGMT:
            return row.get('user_id') == user['id']
        if table == 'review_notes' and action == 'delete':
            return role in MGMT or row.get('created_by') == user['id']
        if table == 'workpapers' and action == 'delete' and row.get('reviewed_by'):
            return role in MGMT
        return True

    def _validate_refs(self, c, table, rec):
        if table in ENGAGEMENT_CHILDREN:
            if not rec.get('engagement_id'):
                raise ApiError(400, 'engagement_id is required.')
            self._row(c, 'engagements', rec['engagement_id'])
            for ref, t in (('workpaper_id', 'workpapers'), ('risk_id', 'risks'), ('issue_id', 'issues')):
                if rec.get(ref) and ref in TABLES[table]:
                    other = self._row(c, t, rec[ref])
                    if other['engagement_id'] != rec['engagement_id']:
                        raise ApiError(400, f'{ref} belongs to a different engagement.')

    def create(self, user, table, body):
        self._check_table(table)
        data = self._clean(table, body)
        if table == 'time_entries' and (user['role'] not in MGMT or not data.get('user_id')):
            data['user_id'] = user['id']
        if not self._can_write(user, table, 'create', data):
            raise ApiError(403, 'You do not have permission to create this record.')
        defaults = {'workpapers': {'status': 'Not started', 'result': 'Not concluded'}, 'review_notes': {'status': 'Open'},
                    'issues': {'status': 'Open'}, 'engagements': {'status': 'Planning'}, 'plan': {'status': 'Planned'}}
        for k, v in defaults.get(table, {}).items():
            data.setdefault(k, v)
        if table == 'workpapers' and data.get('status') in ('Ready for review', 'Complete'):
            data['status'] = 'Not started'
        if table == 'review_notes' and not data.get('workpaper_id'):
            raise ApiError(400, 'A review note must be attached to a workpaper.')
        ts = now()
        rec = {'id': new_id(), 'created_at': ts, 'created_by': user['id'], 'updated_at': ts, 'updated_by': user['id'], **data}
        with self.db() as c:
            self._validate_refs(c, table, rec)
            cols = list(rec)
            c.execute(f'INSERT INTO {table} ({", ".join(cols)}) VALUES ({", ".join("?" * len(cols))})', [rec[k] for k in cols])
            self._log(c, user, 'create', table, rec['id'], rec.get('engagement_id') or (rec['id'] if table == 'engagements' else None),
                      {k: v for k, v in data.items() if v})
            return self._row(c, table, rec['id'])

    def update(self, user, table, rid, body):
        self._check_table(table)
        with self.db() as c:
            row = self._row(c, table, rid)
            if not self._can_write(user, table, 'update', row):
                raise ApiError(403, 'You do not have permission to edit this record.')
            version = (body or {}).get('_version')
            if version and version != row['updated_at']:
                raise ApiError(409, 'Someone else changed this record since you opened it. Reload and try again.')
            data = self._clean(table, body)
            if user['role'] == 'auditee':
                data = {k: v for k, v in data.items() if k in ('response', 'status')}
                if 'status' in data and data['status'] not in AUDITEE_STATUSES:
                    raise ApiError(400, 'You can set status to: ' + ', '.join(AUDITEE_STATUSES))
            if table == 'time_entries' and user['role'] not in MGMT:
                data.pop('user_id', None)
            if table == 'engagements' and user['role'] not in MGMT:
                data.pop('lead_id', None)
            if table in ENGAGEMENT_CHILDREN:
                data.pop('engagement_id', None)  # records never move between engagements
            changes = {k: v for k, v in data.items() if (row.get(k) or None) != v}
            if not changes:
                return row
            if table == 'workpapers':
                if changes.get('status') in ('Ready for review', 'Complete'):
                    raise ApiError(400, 'Use preparer/reviewer sign-off to move a workpaper to review or complete.')
                signed = row['prepared_by'] or row['reviewed_by']
                if signed and 'status' in changes and not set(changes) - WP_ADMIN_FIELDS:
                    raise ApiError(400, 'Remove the sign-off before changing the status.')
                if signed and set(changes) - WP_ADMIN_FIELDS:
                    changes.update(prepared_by=None, prepared_at=None, reviewed_by=None, reviewed_at=None)
                    changes.setdefault('status', 'In progress')
            if table == 'issues' and 'status' in changes:
                closed = changes['status'] == 'Closed'
                changes.update(validated_by=user['id'] if closed else None, validated_at=now() if closed else None)
            rec = {**row, **changes}
            self._validate_refs(c, table, rec)
            changes.update(updated_at=now(), updated_by=user['id'])
            c.execute(f'UPDATE {table} SET {", ".join(k + " = ?" for k in changes)} WHERE id = ?', (*changes.values(), rid))
            detail = {k: [row.get(k), v] for k, v in changes.items() if k not in ('updated_at', 'updated_by')}
            self._log(c, user, 'update', table, rid, row.get('engagement_id') or (rid if table == 'engagements' else None), detail)
            return self._row(c, table, rid)

    def delete(self, user, table, rid):
        self._check_table(table)
        with self.db() as c:
            row = self._row(c, table, rid)
            if not self._can_write(user, table, 'delete', row):
                raise ApiError(403, 'You do not have permission to delete this record.')
            eng = row.get('engagement_id') or (rid if table == 'engagements' else None)
            file_ids = []
            if table == 'engagements':
                file_ids = [r['id'] for r in c.execute('SELECT id FROM files WHERE engagement_id = ?', (rid,))]
                for t in ENGAGEMENT_CHILDREN:
                    c.execute(f'DELETE FROM {t} WHERE engagement_id = ?', (rid,))
                c.execute('UPDATE plan SET engagement_id = NULL WHERE engagement_id = ?', (rid,))
            elif table == 'evidence':
                file_ids = [r['id'] for r in c.execute('SELECT id FROM files WHERE evidence_id = ?', (rid,))]
                c.execute('DELETE FROM files WHERE evidence_id = ?', (rid,))
                if file_ids and row.get('workpaper_id'):
                    self._invalidate_signoffs(c, user, row['workpaper_id'], f"evidence removed: {row.get('title')}")
            elif table == 'workpapers':
                c.execute('DELETE FROM review_notes WHERE workpaper_id = ?', (rid,))
                c.execute('UPDATE evidence SET workpaper_id = NULL WHERE workpaper_id = ?', (rid,))
                c.execute('UPDATE issues SET workpaper_id = NULL WHERE workpaper_id = ?', (rid,))
            elif table == 'risks':
                c.execute('UPDATE workpapers SET risk_id = NULL WHERE risk_id = ?', (rid,))
            elif table == 'issues':
                c.execute('UPDATE evidence SET issue_id = NULL WHERE issue_id = ?', (rid,))
            elif table == 'universe':
                c.execute('UPDATE plan SET universe_id = NULL WHERE universe_id = ?', (rid,))
                c.execute('UPDATE engagements SET universe_id = NULL WHERE universe_id = ?', (rid,))
            c.execute(f'DELETE FROM {table} WHERE id = ?', (rid,))
            label = row.get('name') or row.get('title') or row.get('ref') or row.get('area')
            self._log(c, user, 'delete', table, rid, eng, {'deleted': label} if label else None)
        for fid in file_ids:
            self._remove_stored(fid)

    def _remove_stored(self, fid):
        (self.file_dir / fid).unlink(missing_ok=True)
        for p in self.preview_dir.glob(fid + '-*.png'):
            p.unlink(missing_ok=True)

    # ---------- workflows ----------
    def sign_off(self, user, wp_id, kind):
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            wp = self._row(c, 'workpapers', wp_id)
            ts = now()
            if kind == 'prepare':
                if wp['reviewed_by']:
                    raise ApiError(400, 'Already reviewed.')
                if (wp['result'] or 'Not concluded') == 'Not concluded':
                    raise ApiError(400, 'Record a conclusion before signing off as preparer.')
                changes = {'prepared_by': user['id'], 'prepared_at': ts, 'status': 'Ready for review'}
            elif kind == 'review':
                if user['role'] not in MGMT:
                    raise ApiError(403, 'Only managers can sign off as reviewer.')
                if not wp['prepared_by']:
                    raise ApiError(400, 'The preparer has not signed off yet.')
                if wp['prepared_by'] == user['id']:
                    raise ApiError(400, 'Segregation of duties: the preparer cannot also review.')
                n = c.execute("SELECT COUNT(*) FROM review_notes WHERE workpaper_id = ? AND status != 'Cleared'", (wp_id,)).fetchone()[0]
                if n:
                    raise ApiError(400, f'{n} review note(s) are still open. Clear them before review sign-off.')
                changes = {'reviewed_by': user['id'], 'reviewed_at': ts, 'status': 'Complete'}
            elif kind == 'remove':
                if not (wp['prepared_by'] == user['id'] and not wp['reviewed_by']) and user['role'] not in MGMT:
                    raise ApiError(403, 'Only the preparer (before review) or a manager can remove sign-offs.')
                changes = {'prepared_by': None, 'prepared_at': None, 'reviewed_by': None, 'reviewed_at': None, 'status': 'In progress'}
            else:
                raise ApiError(400, 'Unknown sign-off type.')
            changes.update(updated_at=ts, updated_by=user['id'])
            c.execute(f'UPDATE workpapers SET {", ".join(k + " = ?" for k in changes)} WHERE id = ?', (*changes.values(), wp_id))
            self._log(c, user, 'signoff_' + kind, 'workpapers', wp_id, wp['engagement_id'])
            return self._row(c, 'workpapers', wp_id)

    def review_note_action(self, user, note_id, action, body):
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            n = self._row(c, 'review_notes', note_id)
            ts = now()
            if action == 'respond':
                if not (body.get('response') or '').strip():
                    raise ApiError(400, 'Enter a response.')
                changes = {'response': body['response'][:MAX_FIELD], 'responded_by': user['id'], 'responded_at': ts, 'status': 'Responded'}
            elif action == 'clear':
                if user['role'] not in MGMT and n['created_by'] != user['id']:
                    raise ApiError(403, 'Only the reviewer who raised the note or a manager can clear it.')
                changes = {'status': 'Cleared', 'cleared_by': user['id'], 'cleared_at': ts}
            elif action == 'reopen':
                if user['role'] not in MGMT and n['created_by'] != user['id']:
                    raise ApiError(403, 'Only the reviewer who raised the note or a manager can reopen it.')
                changes = {'status': 'Open', 'cleared_by': None, 'cleared_at': None}
            else:
                raise ApiError(400, 'Unknown action.')
            changes.update(updated_at=ts, updated_by=user['id'])
            c.execute(f'UPDATE review_notes SET {", ".join(k + " = ?" for k in changes)} WHERE id = ?', (*changes.values(), note_id))
            self._log(c, user, 'review_note_' + action, 'review_notes', note_id, n['engagement_id'],
                      {'response': changes['response']} if action == 'respond' else None)
            return self._row(c, 'review_notes', note_id)

    # ---------- evidence files ----------
    def _receive(self, user, name, stream, length):
        """Stream an upload to disk, hashing as it goes. Returns (file_id, clean_name, sha256)."""
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        if length <= 0:
            raise ApiError(400, 'The file is empty.')
        if length > MAX_UPLOAD:
            raise ApiError(413, f'Files are limited to {MAX_UPLOAD // (1024 * 1024)} MB.')
        name = re.sub(r'[\x00-\x1f/\\]', '_', name or 'file').strip()[:200] or 'file'
        fid, h, remaining = new_id(), hashlib.sha256(), length
        tmp = self.file_dir / (fid + '.part')
        with open(tmp, 'wb') as f:
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    break
                f.write(chunk); h.update(chunk); remaining -= len(chunk)
        if remaining:
            tmp.unlink(missing_ok=True)
            raise ApiError(400, 'Upload was incomplete.')
        tmp.rename(self.file_dir / fid)
        return fid, name, h.hexdigest()

    def _insert_file(self, c, user, fid, ev, name, content_type, length, sha):
        ts = now()
        mime = sniff(self.file_dir / fid)
        rec = {'id': fid, 'evidence_id': ev['id'], 'engagement_id': ev['engagement_id'], 'name': name, 'size': str(length),
               'content_type': (content_type or 'application/octet-stream')[:100], 'sha256': sha,
               'kind': kind_of(mime), 'ocr_status': ('queued' if self.ocr.can_read(mime) else 'unavailable') if mime else None,
               'created_at': ts, 'created_by': user['id'], 'updated_at': ts, 'updated_by': user['id']}
        c.execute(f'INSERT INTO files ({", ".join(rec)}) VALUES ({", ".join("?" * len(rec))})', list(rec.values()))
        self._log(c, user, 'upload', 'files', fid, ev['engagement_id'], {'name': name, 'sha256': sha, 'evidence_id': ev['id']})
        if ev.get('workpaper_id'):
            self._invalidate_signoffs(c, user, ev['workpaper_id'], f'evidence added: {name}')
        return rec

    def _invalidate_signoffs(self, c, user, wp_id, reason):
        """Changing the evidence behind a signed-off workpaper means it must be signed off again."""
        wp = c.execute('SELECT * FROM workpapers WHERE id = ?', (wp_id,)).fetchone()
        if not wp or not (wp['prepared_by'] or wp['reviewed_by']):
            return
        c.execute("""UPDATE workpapers SET prepared_by = NULL, prepared_at = NULL, reviewed_by = NULL, reviewed_at = NULL,
                     status = 'In progress', updated_at = ?, updated_by = ? WHERE id = ?""", (now(), user['id'], wp_id))
        self._log(c, user, 'signoffs_removed', 'workpapers', wp_id, wp['engagement_id'], {'reason': reason})

    def save_file(self, user, evidence_id, name, content_type, stream, length):
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            ev = self._row(c, 'evidence', evidence_id)
        fid, name, sha = self._receive(user, name, stream, length)
        try:
            with self.db() as c:
                rec = self._insert_file(c, user, fid, ev, name, content_type, length, sha)
        except BaseException:
            (self.file_dir / fid).unlink(missing_ok=True)
            raise
        self._queue_ocr(rec)
        return rec

    def attach_to_workpaper(self, user, wp_id, name, content_type, stream, length, purpose=None, description=None):
        """One-step upload next to a test: creates the evidence record and stores the file together."""
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            wp = self._row(c, 'workpapers', wp_id)
        fid, name, sha = self._receive(user, name, stream, length)
        ts = now()
        ev = {'id': new_id(), 'engagement_id': wp['engagement_id'], 'workpaper_id': wp_id, 'title': (description or '').strip()[:500] or name,
              'purpose': (purpose or '').strip()[:100] or None, 'pbc_status': 'Received', 'collected_by': user.get('name'),
              'collected_on': ts[:10], 'created_at': ts, 'created_by': user['id'], 'updated_at': ts, 'updated_by': user['id']}
        try:
            with self.db() as c:
                c.execute(f'INSERT INTO evidence ({", ".join(ev)}) VALUES ({", ".join("?" * len(ev))})', list(ev.values()))
                self._log(c, user, 'create', 'evidence', ev['id'], wp['engagement_id'],
                          {k: ev[k] for k in ('title', 'purpose', 'workpaper_id') if ev[k]})
                f = self._insert_file(c, user, fid, ev, name, content_type, length, sha)
        except BaseException:
            (self.file_dir / fid).unlink(missing_ok=True)
            raise
        self._queue_ocr(f)
        return {'evidence': ev, 'file': f}

    # ---------- OCR ----------
    SYSTEM_USER = {'id': 'system', 'name': 'OCR service'}

    def _queue_ocr(self, rec):
        if rec.get('ocr_status') == 'queued':
            self.ocr_queue.put(rec['id'])

    def request_ocr(self, user, fid):
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            rec = self._row(c, 'files', fid)
            mime = sniff(self.file_dir / fid)
            if not mime:
                raise ApiError(400, 'Text can be read from PDFs and images (PNG, JPEG, GIF, BMP, TIFF, WebP).')
            if not self.ocr.can_read(mime):
                tool = 'PDF tools (Poppler)' if mime == PDF else 'OCR (Tesseract)'
                raise ApiError(503, f'{tool} is not installed on the server. Ask your administrator to install it.')
            if rec['ocr_status'] in ('queued', 'running'):
                return rec
            c.execute("UPDATE files SET ocr_status = 'queued' WHERE id = ?", (fid,))
            self._log(c, user, 'ocr_requested', 'files', fid, rec['engagement_id'], {'name': rec['name']})
        self.ocr_queue.put(fid)
        with self.db() as c:
            return self._row(c, 'files', fid)

    def _ocr_worker(self):
        while True:
            fid = self.ocr_queue.get()
            try:
                self.run_ocr(fid)
            except Exception as e:  # never let one bad file stop the worker
                sys.stderr.write(f'OCR worker error for {fid}: {e!r}\n')

    def run_ocr(self, fid):
        with self.db() as c:
            rec = c.execute('SELECT * FROM files WHERE id = ?', (fid,)).fetchone()
            if not rec:
                return
            c.execute("UPDATE files SET ocr_status = 'running' WHERE id = ?", (fid,))
        try:
            r = self.ocr.read(self.file_dir / fid)
            conf = r['confidence']
            fields = {'ocr_status': 'done', 'ocr_text': r['text'], 'ocr_confidence': None if conf is None else str(conf),
                      'ocr_method': r['method'], 'pages': None if r['pages'] is None else str(r['pages'])}
            detail = {'name': rec['name'], 'method': r['method'], 'confidence': conf, 'characters': len(r['text'])}
        except Exception as e:
            fields = {'ocr_status': 'failed', 'ocr_text': f'Text extraction failed: {e}'[:1000], 'ocr_confidence': None, 'ocr_method': None}
            detail = {'name': rec['name'], 'error': str(e)[:300]}
        fields.update(ocr_engine=self.ocr.version, ocr_at=now())
        with self.db() as c:
            c.execute(f'UPDATE files SET {", ".join(k + " = ?" for k in fields)} WHERE id = ?', (*fields.values(), fid))
            self._log(c, self.SYSTEM_USER, 'ocr_' + fields['ocr_status'], 'files', fid, rec['engagement_id'], detail)

    def view_image(self, user, fid):
        """Inline image for the OCR viewer. The type comes from the file's content, never from the uploader."""
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            rec = self._row(c, 'files', fid)
            mime = sniff_image(self.file_dir / fid)
            if not mime:
                raise ApiError(415, 'Only images can be previewed.')
            self._log(c, user, 'view', 'files', fid, rec['engagement_id'], {'name': rec['name']})
        return mime, self.file_dir / fid

    def view_page(self, user, fid, page):
        """A PDF page rendered as PNG for the viewer (cached). Rendering avoids running PDF content in the browser."""
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            rec = self._row(c, 'files', fid)
        if sniff(self.file_dir / fid) != PDF:
            raise ApiError(415, 'Not a PDF.')
        if not self.ocr.pdf_available:
            raise ApiError(503, 'PDF preview needs the PDF tools (Poppler) on the server.')
        try:
            page = int(page)
        except ValueError:
            raise ApiError(400, 'Invalid page.')
        pages = int(rec['pages']) if rec['pages'] else self.ocr.pdf_pages(self.file_dir / fid)
        if not 1 <= page <= pages:
            raise ApiError(404, 'No such page.')
        out = self.preview_dir / f'{fid}-{page}.png'
        if not out.exists():
            try:
                self.ocr.render_page(self.file_dir / fid, page, out)
            except RuntimeError as e:
                raise ApiError(422, str(e))
        if page == 1:
            with self.db() as c:
                self._log(c, user, 'view', 'files', fid, rec['engagement_id'], {'name': rec['name']})
        return out

    def open_file(self, user, fid):
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            rec = self._row(c, 'files', fid)
            self._log(c, user, 'download', 'files', fid, rec['engagement_id'], {'name': rec['name']})
        return rec, self.file_dir / fid

    def delete_file(self, user, fid):
        if user['role'] not in STAFF:
            raise ApiError(403, 'Not permitted.')
        with self.db() as c:
            rec = self._row(c, 'files', fid)
            if user['role'] not in MGMT and rec['created_by'] != user['id']:
                raise ApiError(403, 'Only the uploader or a manager can remove a file.')
            c.execute('DELETE FROM files WHERE id = ?', (fid,))
            self._log(c, user, 'delete', 'files', fid, rec['engagement_id'], {'name': rec['name'], 'sha256': rec['sha256']})
            ev = c.execute('SELECT workpaper_id FROM evidence WHERE id = ?', (rec['evidence_id'],)).fetchone()
            if ev and ev['workpaper_id']:
                self._invalidate_signoffs(c, user, ev['workpaper_id'], f"evidence removed: {rec['name']}")
        self._remove_stored(fid)


class Handler(BaseHTTPRequestHandler):
    server_version = 'AuditWorkbench'
    app: Workbench = None
    secure_cookie = False

    def log_message(self, fmt, *args):
        if os.environ.get('AUDIT_QUIET') != '1':
            sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))

    def do_GET(self): self._dispatch('GET')
    def do_POST(self): self._dispatch('POST')
    def do_PUT(self): self._dispatch('PUT')
    def do_DELETE(self): self._dispatch('DELETE')

    def _headers(self, status, ctype, length=None, extra=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        if length is not None:
            self.send_header('Content-Length', str(length))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                                    "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, status, obj, extra=None):
        body = json.dumps(obj).encode()
        self._headers(status, 'application/json', len(body), extra)
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_JSON:
            raise ApiError(413, 'Request too large.')
        try:
            return json.loads(self.rfile.read(n) or b'{}')
        except ValueError:
            raise ApiError(400, 'Invalid JSON.')

    def _token(self):
        c = cookies.SimpleCookie(self.headers.get('Cookie') or '')
        return c['aw_session'].value if 'aw_session' in c else None

    def _cookie(self, value, max_age):
        flags = '; Secure' if self.secure_cookie else ''
        return {'Set-Cookie': f'aw_session={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{flags}'}

    def _static(self, path):
        name = STATIC.get(path)
        if not name:
            return self._json(404, {'error': 'Not found'})
        data = (ROOT / 'static' / name).read_bytes()
        self._headers(200, CONTENT_TYPES[Path(name).suffix], len(data))
        self.wfile.write(data)

    def _dispatch(self, method):
        url = urlparse(self.path)
        try:
            if not url.path.startswith('/api/'):
                if method != 'GET':
                    raise ApiError(405, 'Method not allowed.')
                return self._static(url.path)
            if method != 'GET' and self.headers.get('X-Requested-With') != 'fetch':
                raise ApiError(403, 'Missing request header.')
            self._api(method, [unquote(p) for p in url.path[5:].strip('/').split('/')], parse_qs(url.query))
        except ApiError as e:
            self._json(e.status, {'error': str(e)})
        except Exception as e:  # keep the server alive; details go to the console only
            sys.stderr.write(f'ERROR {method} {url.path}: {e!r}\n')
            self._json(500, {'error': 'Internal error.'})

    def _api(self, method, parts, query):
        app = self.app
        if parts == ['login'] and method == 'POST':
            b = self._body()
            token = app.login(b.get('username'), b.get('password'))
            return self._json(200, {'ok': True}, self._cookie(token, SESSION_HOURS * 3600))
        if parts == ['logout'] and method == 'POST':
            app.logout(self._token())
            return self._json(200, {'ok': True}, self._cookie('', 0))
        user = app.session_user(self._token())
        if not user:
            raise ApiError(401, 'Please sign in.')
        q = {k: v[0] for k, v in query.items()}
        head, rest = parts[0], parts[1:]

        if head == 'me':
            if method == 'GET' and not rest:
                return self._json(200, user)
            if method == 'POST' and rest == ['password']:
                b = self._body()
                app.change_password(user, b.get('old'), b.get('new'))
                return self._json(200, {'ok': True})
        elif head == 'users':
            if method == 'GET' and not rest:
                return self._json(200, app.list_users(user))
            if method == 'POST' and not rest:
                return self._json(201, app.save_user(user, self._body()))
            if method == 'PUT' and len(rest) == 1:
                return self._json(200, app.save_user(user, self._body(), rest[0]))
        elif head == 'audit_log' and method == 'GET':
            return self._json(200, app.audit_log(user, q.get('record_id'), q.get('engagement_id'), q.get('limit', 500)))
        elif head == 'workpapers' and len(rest) == 2 and rest[1] == 'signoff' and method == 'POST':
            return self._json(200, app.sign_off(user, rest[0], self._body().get('kind')))
        elif head == 'review_notes' and len(rest) == 2 and method == 'POST':
            return self._json(200, app.review_note_action(user, rest[0], rest[1], self._body()))
        elif head == 'evidence' and len(rest) == 2 and rest[1] == 'files' and method == 'POST':
            length = int(self.headers.get('Content-Length') or 0)
            name = unquote(self.headers.get('X-Filename') or 'file')
            return self._json(201, app.save_file(user, rest[0], name, self.headers.get('Content-Type'), self.rfile, length))
        elif head == 'workpapers' and len(rest) == 2 and rest[1] == 'attach' and method == 'POST':
            h = self.headers
            return self._json(201, app.attach_to_workpaper(user, rest[0], unquote(h.get('X-Filename') or 'file'), h.get('Content-Type'),
                                                           self.rfile, int(h.get('Content-Length') or 0),
                                                           unquote(h.get('X-Purpose') or ''), unquote(h.get('X-Description') or '')))
        elif head == 'ocr' and not rest and method == 'GET':
            return self._json(200, self.app.ocr.describe())
        elif head == 'files' and len(rest) == 2 and rest[1] == 'ocr' and method == 'POST':
            return self._json(200, app.request_ocr(user, rest[0]))
        elif head == 'files' and len(rest) == 3 and rest[1] == 'page' and method == 'GET':
            data = app.view_page(user, rest[0], rest[2]).read_bytes()
            self._headers(200, 'image/png', len(data), {'Content-Disposition': 'inline'})
            return self.wfile.write(data)
        elif head == 'files' and len(rest) == 2 and rest[1] == 'view' and method == 'GET':
            mime, path = app.view_image(user, rest[0])
            data = path.read_bytes()
            self._headers(200, mime, len(data), {'Content-Disposition': 'inline'})
            return self.wfile.write(data)
        elif head == 'files' and len(rest) == 1 and method == 'GET':
            rec, path = app.open_file(user, rest[0])
            data = path.read_bytes()
            safe = re.sub(r'[^A-Za-z0-9._ -]', '_', rec['name'])
            self._headers(200, 'application/octet-stream', len(data), {
                'Content-Disposition': f'attachment; filename="{safe}"; filename*=UTF-8\'\'{quote(rec["name"], safe="")}'})
            return self.wfile.write(data)
        elif head == 'files' and len(rest) == 1 and method == 'DELETE':
            app.delete_file(user, rest[0])
            return self._json(200, {'ok': True})
        elif head in TABLES:
            if method == 'GET' and not rest:
                return self._json(200, app.list(user, head, q))
            if method == 'GET' and len(rest) == 1:
                return self._json(200, app.get(user, head, rest[0]))
            if method == 'POST' and not rest:
                return self._json(201, app.create(user, head, self._body()))
            if method == 'PUT' and len(rest) == 1:
                return self._json(200, app.update(user, head, rest[0], self._body()))
            if method == 'DELETE' and len(rest) == 1:
                app.delete(user, head, rest[0])
                return self._json(200, {'ok': True})
        raise ApiError(404, 'Not found.')


def make_server(data_dir, host='127.0.0.1', port=8080, secure_cookie=False, ocr=None):
    app = Workbench(data_dir, ocr)
    handler = type('BoundHandler', (Handler,), {'app': app, 'secure_cookie': secure_cookie})
    return ThreadingHTTPServer((host, port), handler), app


def main():
    p = argparse.ArgumentParser(description='Audit Workbench server')
    p.add_argument('--host', default=os.environ.get('AUDIT_HOST', '127.0.0.1'))
    p.add_argument('--port', type=int, default=int(os.environ.get('AUDIT_PORT', 8080)))
    p.add_argument('--data', default=os.environ.get('AUDIT_DATA', str(ROOT / 'data')))
    p.add_argument('--secure-cookie', action='store_true', help='mark the session cookie Secure (use behind HTTPS)')
    a = p.parse_args()
    srv, app = make_server(a.data, a.host, a.port, a.secure_cookie)
    pw = app.bootstrap_admin(os.environ.get('AUDIT_ADMIN_PASSWORD'))
    if pw:
        print(f'\nCreated first administrator account.\n  username: admin\n  password: {pw}\n'
              'You will be asked to change it at first sign-in.\n', flush=True)
    o = app.ocr.describe()
    print(f"PDF text extraction: {'available' if o['pdf'] else 'not available - install Poppler (poppler-utils) to read PDFs'}", flush=True)
    print(f"OCR: {o['engine'] + (' with image enhancement' if o['enhanced'] else ' (install Pillow for better accuracy)') if o['available'] else 'not available - install Tesseract to read screenshots'}", flush=True)
    print(f'Audit Workbench running at http://{a.host}:{a.port}  (data: {a.data})', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
