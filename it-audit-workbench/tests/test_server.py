"""End-to-end API tests: run with  python3 -m unittest discover -s tests"""
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ['AUDIT_QUIET'] = '1'
import server  # noqa: E402


class Client:
    def __init__(self, port):
        self.port, self.cookie = port, None

    def req(self, method, path, body=None, raw=None, headers=None, csrf=True):
        c = http.client.HTTPConnection('127.0.0.1', self.port)
        h = dict(headers or {})
        if csrf:
            h['X-Requested-With'] = 'fetch'
        if self.cookie:
            h['Cookie'] = self.cookie
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if body is not None:
            h['Content-Type'] = 'application/json'
        c.request(method, '/api/' + path, data, h)
        r = c.getresponse()
        payload = r.read()
        sc = r.getheader('Set-Cookie')
        if sc:
            self.cookie = sc.split(';')[0]
        c.close()
        try:
            return r.status, json.loads(payload)
        except ValueError:
            return r.status, payload

    def ok(self, method, path, body=None, **kw):
        status, data = self.req(method, path, body, **kw)
        assert status < 300, (status, data)
        return data


class WorkbenchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.srv, cls.app = server.make_server(cls.tmp.name, port=0)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.app.bootstrap_admin('admin-password-1')
        cls.admin = cls.login('admin', 'admin-password-1')
        users = {}
        for name, role in [('mgr', 'manager'), ('mgr2', 'manager'), ('aud', 'auditor'), ('owner', 'auditee'), ('owner2', 'auditee')]:
            users[name] = cls.admin.ok('POST', 'users', {'username': name, 'name': name.title(), 'role': role, 'password': name + '-password-1'})
        cls.uid = {k: v['id'] for k, v in users.items()}
        cls.mgr, cls.mgr2, cls.aud = (cls.login(n, n + '-password-1') for n in ('mgr', 'mgr2', 'aud'))
        cls.owner, cls.owner2 = cls.login('owner', 'owner-password-1'), cls.login('owner2', 'owner2-password-1')

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    @classmethod
    def login(cls, u, p):
        c = Client(cls.port)
        c.ok('POST', 'login', {'username': u, 'password': p})
        return c

    def engagement(self):
        e = self.mgr.ok('POST', 'engagements', {'name': 'ERP ITGC', 'lead_id': self.uid['mgr']})
        wp = self.aud.ok('POST', 'workpapers', {'engagement_id': e['id'], 'ref': 'AC-01', 'title': 'Provisioning'})
        return e, wp

    def test_requires_login_and_csrf_header(self):
        self.assertEqual(Client(self.port).req('GET', 'engagements')[0], 401)
        self.assertEqual(self.mgr.req('POST', 'engagements', {'name': 'x'}, csrf=False)[0], 403)

    def test_bad_password_and_lockout(self):
        c = Client(self.port)
        for _ in range(5):
            self.assertEqual(c.req('POST', 'login', {'username': 'mgr2', 'password': 'nope'})[0], 401)
        self.assertEqual(c.req('POST', 'login', {'username': 'mgr2', 'password': 'mgr2-password-1'})[0], 429)
        self.app.failures.clear()

    def test_new_users_must_change_password(self):
        me = self.aud.ok('GET', 'me')
        self.assertTrue(me['must_change'])
        self.assertEqual(self.aud.req('POST', 'me/password', {'old': 'wrong', 'new': 'x' * 12})[0], 400)
        self.assertEqual(self.aud.req('POST', 'me/password', {'old': 'aud-password-1', 'new': 'short'})[0], 400)

    def test_role_permissions(self):
        self.assertEqual(self.aud.req('POST', 'engagements', {'name': 'x'})[0], 403)
        self.assertEqual(self.aud.req('POST', 'universe', {'name': 'x'})[0], 403)
        self.assertEqual(self.mgr.req('POST', 'users', {'username': 'zz', 'role': 'admin', 'password': 'x' * 12})[0], 403)
        self.assertEqual(self.owner.req('GET', 'workpapers')[0], 403)
        self.assertEqual(self.aud.req('GET', 'audit_log')[0], 403)

    def test_signoff_workflow_and_segregation_of_duties(self):
        e, wp = self.engagement()
        path = f"workpapers/{wp['id']}/signoff"
        self.assertEqual(self.aud.req('POST', path, {'kind': 'prepare'})[0], 400)  # no conclusion yet
        wp = self.aud.ok('PUT', 'workpapers/' + wp['id'], {'result': 'Effective', '_version': wp['updated_at']})
        self.assertEqual(self.aud.req('POST', path, {'kind': 'review'})[0], 403)  # auditors cannot review
        self.assertEqual(self.mgr.req('POST', path, {'kind': 'review'})[0], 400)  # not prepared yet
        wp = self.aud.ok('POST', path, {'kind': 'prepare'})
        self.assertEqual(wp['status'], 'Ready for review')

        note = self.mgr.ok('POST', 'review_notes', {'engagement_id': e['id'], 'workpaper_id': wp['id'], 'note': 'Sample 3 lacks approval'})
        status, err = self.mgr.req('POST', path, {'kind': 'review'})
        self.assertEqual(status, 400)
        self.assertIn('review note', err['error'])
        self.aud.ok('POST', f"review_notes/{note['id']}/respond", {'response': 'Added approval email'})
        self.assertEqual(self.aud.req('POST', f"review_notes/{note['id']}/clear", {})[0], 403)  # only raiser/manager
        self.mgr.ok('POST', f"review_notes/{note['id']}/clear", {})

        wp = self.mgr.ok('POST', path, {'kind': 'review'})
        self.assertEqual((wp['status'], wp['reviewed_by']), ('Complete', self.uid['mgr']))

        # A manager who prepared cannot review their own work.
        wp2 = self.mgr.ok('POST', 'workpapers', {'engagement_id': e['id'], 'ref': 'AC-02', 'title': 'Leavers', 'result': 'Effective'})
        self.mgr.ok('POST', f"workpapers/{wp2['id']}/signoff", {'kind': 'prepare'})
        status, err = self.mgr.req('POST', f"workpapers/{wp2['id']}/signoff", {'kind': 'review'})
        self.assertEqual(status, 400)
        self.assertIn('Segregation', err['error'])

    def test_editing_signed_workpaper_removes_signoffs(self):
        e, wp = self.engagement()
        wp = self.aud.ok('PUT', 'workpapers/' + wp['id'], {'result': 'Effective'})
        self.aud.ok('POST', f"workpapers/{wp['id']}/signoff", {'kind': 'prepare'})
        wp = self.mgr.ok('POST', f"workpapers/{wp['id']}/signoff", {'kind': 'review'})
        # Admin field: sign-offs stay.
        wp = self.aud.ok('PUT', 'workpapers/' + wp['id'], {'due_date': '2026-12-31', 'status': wp['status']})
        self.assertEqual(wp['reviewed_by'], self.uid['mgr'])
        # Substantive change: sign-offs removed.
        wp = self.aud.ok('PUT', 'workpapers/' + wp['id'], {'exceptions': '2'})
        self.assertIsNone(wp['prepared_by'])
        self.assertIsNone(wp['reviewed_by'])
        self.assertEqual(wp['status'], 'In progress')
        # Status can't be pushed to Complete by editing.
        self.assertEqual(self.aud.req('PUT', 'workpapers/' + wp['id'], {'status': 'Complete'})[0], 400)
        log = self.mgr.ok('GET', 'audit_log?record_id=' + wp['id'])
        self.assertIn('signoff_review', [r['action'] for r in log])

    def test_optimistic_locking(self):
        e, wp = self.engagement()
        self.aud.ok('PUT', 'workpapers/' + wp['id'], {'notes': 'first', '_version': wp['updated_at']})
        status, err = self.mgr.req('PUT', 'workpapers/' + wp['id'], {'notes': 'stale', '_version': '2000-01-01T00:00:00+00:00'})
        self.assertEqual(status, 409)

    def test_evidence_upload_hash_and_download(self):
        e, wp = self.engagement()
        ev = self.aud.ok('POST', 'evidence', {'engagement_id': e['id'], 'workpaper_id': wp['id'], 'title': 'AD export'})
        content = b'user,enabled\nalice,1\n'
        f = self.aud.ok('POST', f"evidence/{ev['id']}/files", raw=content,
                        headers={'X-Filename': 'ad%20users.csv', 'Content-Type': 'text/csv'})
        self.assertEqual(f['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(f['name'], 'ad users.csv')
        status, body = self.mgr.req('GET', 'files/' + f['id'])
        self.assertEqual((status, body), (200, content))
        self.assertEqual(self.owner.req('GET', 'files/' + f['id'])[0], 403)
        actions = [r['action'] for r in self.mgr.ok('GET', 'audit_log?record_id=' + f['id'])]
        self.assertEqual(sorted(actions), ['download', 'upload'])
        self.mgr.ok('DELETE', 'evidence/' + ev['id'])
        self.assertFalse((Path(self.tmp.name) / 'evidence' / f['id']).exists())

    def test_auditee_sees_and_answers_only_own_issues(self):
        e, wp = self.engagement()
        mine = self.aud.ok('POST', 'issues', {'engagement_id': e['id'], 'title': 'Leavers not removed', 'owner_id': self.uid['owner'],
                                              'likelihood': '4', 'impact': '5'})
        self.aud.ok('POST', 'issues', {'engagement_id': e['id'], 'title': 'Other', 'owner_id': self.uid['owner2']})
        self.assertEqual([i['title'] for i in self.owner.ok('GET', 'issues')], ['Leavers not removed'])
        engs = self.owner.ok('GET', 'engagements')
        self.assertEqual(set(engs[0]), {'id', 'name', 'auditee'})
        upd = self.owner.ok('PUT', 'issues/' + mine['id'], {'response': 'Will automate', 'status': 'Remediation in progress', 'title': 'hacked'})
        self.assertEqual((upd['response'], upd['title']), ('Will automate', 'Leavers not removed'))
        self.assertEqual(self.owner.req('PUT', 'issues/' + mine['id'], {'status': 'Closed'})[0], 400)
        self.assertEqual(self.owner2.req('PUT', 'issues/' + mine['id'], {'response': 'x'})[0], 403)
        closed = self.aud.ok('PUT', 'issues/' + mine['id'], {'status': 'Closed'})
        self.assertEqual(closed['validated_by'], self.uid['aud'])

    def test_references_must_belong_to_same_engagement(self):
        e1, wp1 = self.engagement()
        e2, _ = self.engagement()
        status, _ = self.aud.req('POST', 'issues', {'engagement_id': e2['id'], 'workpaper_id': wp1['id'], 'title': 'x'})
        self.assertEqual(status, 400)

    def test_time_entries_belong_to_their_author(self):
        e, _ = self.engagement()
        t = self.aud.ok('POST', 'time_entries', {'engagement_id': e['id'], 'date': '2026-10-01', 'hours': '3', 'user_id': self.uid['mgr']})
        self.assertEqual(t['user_id'], self.uid['aud'])
        self.assertEqual(self.mgr2.req('PUT', 'time_entries/' + t['id'], {'hours': '4'})[0], 200)  # managers may correct
        mine = self.mgr.ok('POST', 'time_entries', {'engagement_id': e['id'], 'date': '2026-10-01', 'hours': '1'})
        self.assertEqual(self.aud.req('PUT', 'time_entries/' + mine['id'], {'hours': '9'})[0], 403)

    def test_delete_engagement_cascades_and_is_logged(self):
        e, wp = self.engagement()
        self.assertEqual(self.aud.req('DELETE', 'engagements/' + e['id'])[0], 403)
        self.mgr.ok('DELETE', 'engagements/' + e['id'])
        self.assertEqual(self.mgr.req('GET', 'workpapers/' + wp['id'])[0], 404)
        log = self.mgr.ok('GET', 'audit_log?engagement_id=' + e['id'])
        self.assertEqual(log[0]['action'], 'delete')

    def test_disabled_user_is_signed_out(self):
        u = self.admin.ok('POST', 'users', {'username': 'temp', 'name': 'Temp', 'role': 'auditor', 'password': 'temp-password-1'})
        c = self.login('temp', 'temp-password-1')
        self.admin.ok('PUT', 'users/' + u['id'], {'active': False})
        self.assertEqual(c.req('GET', 'me')[0], 401)
        self.assertEqual(self.admin.req('PUT', 'users/' + self.admin.ok('GET', 'me')['id'], {'role': 'auditor'})[0], 400)

    def test_static_files_and_security_headers(self):
        c = http.client.HTTPConnection('127.0.0.1', self.port)
        c.request('GET', '/')
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertIn("default-src 'self'", r.getheader('Content-Security-Policy'))
        r.read()
        c.request('GET', '/../server.py')
        self.assertEqual(c.getresponse().status, 404)


if __name__ == '__main__':
    unittest.main()
