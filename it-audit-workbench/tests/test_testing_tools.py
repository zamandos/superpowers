"""Sampling, access analytics and policy-vs-setting checks, end to end through the API."""
import csv
import io
import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_server import Client, server  # noqa: E402  (also puts the app on sys.path)
import analytics  # noqa: E402
import policycheck  # noqa: E402
from ocr import OcrEngine  # noqa: E402

FIX = Path(__file__).resolve().parent / 'fixtures'


class FakeOcr:
    """Lets tests attach 'screenshots' whose text they control (text is the file content after a PNG header)."""
    available, pdf_available, enhanced, version, lang = True, True, False, 'fake', 'eng'

    def can_read(self, mime):
        return True

    def describe(self):
        return {'available': True, 'engine': 'fake', 'enhanced': False, 'lang': 'eng', 'pdf': True}

    def read(self, path, mime=None):
        raw = Path(path).read_bytes()
        text = raw.split(b'\n', 1)[1].decode()
        kind = 'pdf' if raw.startswith(b'%PDF') else 'image'
        return {'text': text, 'confidence': 95.0, 'method': 'PDF text' if kind == 'pdf' else 'Image OCR', 'pages': 1 if kind == 'pdf' else None}


class Base(unittest.TestCase):
    engine = FakeOcr()

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.srv, cls.app = server.make_server(cls.tmp.name, port=0, ocr=cls.engine)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.app.bootstrap_admin('admin-password-1')
        cls.c = Client(cls.srv.server_address[1])
        cls.c.ok('POST', 'login', {'username': 'admin', 'password': 'admin-password-1'})
        cls.c.ok('POST', 'users', {'username': 'mgr', 'name': 'Manager', 'role': 'manager', 'password': 'mgr-password-1'})
        cls.mgr = Client(cls.srv.server_address[1])
        cls.mgr.ok('POST', 'login', {'username': 'mgr', 'password': 'mgr-password-1'})

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.eng = self.c.ok('POST', 'engagements', {'name': 'Tools'})
        self.wp = self.c.ok('POST', 'workpapers', {'engagement_id': self.eng['id'], 'ref': 'AC-02', 'title': 'Leavers'})

    def attach(self, data, name, wp=None):
        return self.c.ok('POST', f"workpapers/{(wp or self.wp)['id']}/attach", raw=data, headers={'X-Filename': name})['file']

    def wait_ocr(self, fid):
        for _ in range(300):
            f = self.c.ok('GET', 'files?id=' + fid)[0]
            if f['ocr_status'] not in ('queued', 'running'):
                return f
            time.sleep(0.05)
        self.fail('text extraction did not finish')


class SamplingTest(Base):
    def test_draw_is_reproducible_and_documented(self):
        pop = self.attach((FIX / 'ad_users.csv').read_bytes(), 'ad_users.csv')
        s = self.c.ok('POST', f"workpapers/{self.wp['id']}/sample", {'file_id': pop['id'], 'size': 10, 'seed': '48213977'})
        rows = json.loads(s['selected_rows'])
        self.assertEqual(rows, analytics.draw_sample(54, 10, '48213977'))
        self.assertEqual((s['population_rows'], s['population_sha256']), ('54', pop['sha256']))
        # The sample file is attached to the test as "Sample selection" and holds the right population rows.
        ev = [e for e in self.c.ok('GET', 'evidence?workpaper_id=' + self.wp['id']) if e['purpose'] == 'Sample selection'][0]
        self.assertIn('Seed: 48213977', ev['notes'])
        self.assertIn(pop['sha256'], ev['notes'])
        status, body = self.c.req('GET', 'files/' + s['sample_file_id'])
        got = list(csv.reader(io.StringIO(body.decode('utf-8-sig'))))
        population = list(csv.reader(io.StringIO((FIX / 'ad_users.csv').read_text(encoding='utf-8'))))
        self.assertEqual(got[0], ['Sample #', 'Population row #'] + population[0])
        for i, line in enumerate(got[1:], 1):
            self.assertEqual(line[0], str(i))
            self.assertEqual(line[2:], population[int(line[1])])
        wp = self.c.ok('GET', 'workpapers/' + self.wp['id'])
        self.assertEqual((wp['sample_size'], wp['population']), ('10', 'ad_users.csv (54 rows)'))
        self.assertIn('sample_drawn', [r['action'] for r in self.c.ok('GET', 'audit_log?record_id=' + s['id'])])

    def test_seed_is_generated_when_blank(self):
        pop = self.attach(b'id\n1\n2\n3\n4\n5\n', 'pop.csv')
        s = self.c.ok('POST', f"workpapers/{self.wp['id']}/sample", {'file_id': pop['id'], 'size': 2})
        self.assertRegex(s['seed'], r'^\d{8}$')

    def test_verify_detects_tampering(self):
        pop = self.attach((FIX / 'ad_users.csv').read_bytes(), 'ad_users.csv')
        s = self.c.ok('POST', f"workpapers/{self.wp['id']}/sample", {'file_id': pop['id'], 'size': 5, 'seed': 'abc'})
        v = self.mgr.ok('POST', f"samples/{s['id']}/verify", {})
        self.assertEqual(v['verify_result'], 'Verified')
        self.assertTrue(all(ch[1] for ch in v['checks']))
        stored = Path(self.tmp.name) / 'evidence' / pop['id']
        stored.write_bytes(stored.read_bytes().replace(b'bwong', b'xwong'))
        v = self.mgr.ok('POST', f"samples/{s['id']}/verify", {})
        self.assertTrue(v['verify_result'].startswith('Failed: Population file unchanged'))

    def test_rejections_and_immutability(self):
        pop = self.attach(b'id\n1\n2\n', 'pop.csv')
        url = f"workpapers/{self.wp['id']}/sample"
        self.assertEqual(self.c.req('POST', url, {'file_id': pop['id'], 'size': 3})[0], 400)
        self.assertEqual(self.c.req('POST', url, {'file_id': pop['id'], 'size': 1, 'seed': 'bad seed!'})[0], 400)
        self.assertEqual(self.c.req('POST', url, {'file_id': self.attach(b'\x89PNG\r\n\x1a\n\nx', 'a.png')['id'], 'size': 1})[0], 400)
        other = self.c.ok('POST', 'engagements', {'name': 'Other'})
        owp = self.c.ok('POST', 'workpapers', {'engagement_id': other['id'], 'ref': 'X', 'title': 'X'})
        self.assertEqual(self.c.req('POST', f"workpapers/{owp['id']}/sample", {'file_id': pop['id'], 'size': 1})[0], 400)
        s = self.c.ok('POST', url, {'file_id': pop['id'], 'size': 1})
        self.assertEqual(self.c.req('PUT', 'samples/' + s['id'], {'seed': '1'})[0], 403)
        self.assertEqual(self.c.req('DELETE', 'samples/' + s['id'])[0], 403)
        self.assertEqual(self.c.req('POST', 'samples', {'engagement_id': self.eng['id']})[0], 403)


class AccessTestTest(Base):
    def run_test(self, **over):
        u = self.attach((FIX / 'ad_users.csv').read_bytes(), 'ad_users.csv')
        lv = self.attach((FIX / 'hr_leavers.xlsx').read_bytes(), 'hr_leavers.xlsx')
        pu, pl = self.c.ok('GET', f"files/{u['id']}/table"), self.c.ok('GET', f"files/{lv['id']}/table")
        mapping = {**{k: v for k, v in pu['guess'].items() if k.startswith('user') and v},
                   **{k: v for k, v in pl['guess'].items() if k.startswith('leaver') and v}}
        body = {'users': {'file_id': u['id']}, 'leavers': {'file_id': lv['id'], 'sheet': 'Leavers'}, 'mapping': mapping,
                'as_at': '2026-09-30', 'sla_days': 1, 'dormant_days': 90, **over}
        return pu, pl, self.c.req('POST', f"workpapers/{self.wp['id']}/access_test", body)

    def test_finds_every_planted_case(self):
        pu, pl, (status, a) = self.run_test()
        self.assertEqual(pl['sheets'], ['Leavers', 'Notes'])
        self.assertEqual(pl['rows'][0][4], '2026-02-01')  # Excel date cells are shown as dates, not serial numbers
        self.assertEqual(pu['row_count'], 54)
        self.assertEqual(status, 201, a)
        self.assertEqual(json.loads(a['counts']), {'Leaver account still enabled': 2, 'Logon after termination': 1, 'Disabled late': 1,
                                                    'Dormant enabled account': 3, 'Possible generic or shared account': 3})
        found = {(e['check'], e['account']) for e in json.loads(a['exceptions'])}
        self.assertEqual(found, {('Leaver account still enabled', 'bwong'), ('Leaver account still enabled', 'kpatel'),
                                 ('Logon after termination', 'kpatel'), ('Disabled late', 'tnguyen'),
                                 ('Dormant enabled account', 'rlee'), ('Dormant enabled account', 'pmartin'),
                                 ('Dormant enabled account', 'anew'), ('Possible generic or shared account', 'svc-backup'),
                                 ('Possible generic or shared account', 'admin.test'), ('Possible generic or shared account', 'scanner01')})
        self.assertEqual([u['leaver'] for u in json.loads(a['unmatched'])], ['CORP\\ojones'])
        inputs = json.loads(a['inputs'])
        self.assertEqual([i['rows'] for i in inputs], [54, 8])
        # Exceptions file attached to the test for the workpaper.
        status, body = self.c.req('GET', 'files/' + a['result_file_id'])
        self.assertEqual(body.decode('utf-8-sig').count('\n'), 1 + 10 + 1)
        self.assertEqual(self.c.req('PUT', 'analyses/' + a['id'], {'type': 'x'})[0], 403)

    def test_ambiguous_dates_need_a_format(self):
        u = self.attach(b'user,enabled\nbob,True\n', 'u.csv')
        lv = self.attach(b'user,left\nbob,03/04/2026\n', 'l.csv')
        body = {'users': {'file_id': u['id']}, 'leavers': {'file_id': lv['id']}, 'as_at': '2026-09-30',
                'mapping': {'user_key': 'user', 'user_enabled': 'enabled', 'leaver_key': 'user', 'leaver_term_date': 'left'}}
        status, err = self.c.req('POST', f"workpapers/{self.wp['id']}/access_test", body)
        self.assertEqual(status, 400)
        self.assertIn('Choose the date format', err['error'])
        body['mapping']['date_format'] = 'DD/MM/YYYY'
        a = self.c.ok('POST', f"workpapers/{self.wp['id']}/access_test", body)
        self.assertIn('Terminated 2026-04-03', json.loads(a['exceptions'])[0]['detail'])

    def test_validation(self):
        _, _, (status, err) = self.run_test(as_at='')
        self.assertEqual(status, 400)
        _, _, (status, err) = self.run_test(mapping={'user_key': 'Nope', 'leaver_key': 'Network ID', 'leaver_term_date': 'Termination Date'})
        self.assertEqual(status, 400)
        self.assertIn('Nope', err['error'])


class SettingChecksTest(Base):
    POLICY = (b'%PDF-1.4\n--- Page 2 ---\n3. Passwords\n\n3.1 Passwords must be a minimum of 12 characters and meet complexity '
              b'requirements.\n\n3.2 Accounts must lock after 5 invalid logon attempts.\n')
    GPO = (b'\x89PNG\r\n\x1a\n\nPassword Policy\nMinimum password length    8 characters\nPassword must meet complexity requirements    Enabled\n'
           b'Account lockout threshold    5 invalid logon attempts\nMinimum password age    I days\n')

    def test_suggest_run_and_trace(self):
        pol = self.wait_ocr(self.attach(self.POLICY, 'IS-04.pdf')['id'])
        shot = self.wait_ocr(self.attach(self.GPO, 'gpo.png')['id'])
        props = self.c.ok('POST', f"workpapers/{self.wp['id']}/setting_checks/suggest", {})
        self.assertEqual([(p['label'], p['operator'], p['expected']) for p in props],
                         [('Minimum password length', '>=', '12'), ('Account lockout threshold', '<=', '5'),
                          ('Password must meet complexity requirements', '=', 'Enabled')])
        self.assertIn('IS-04.pdf, page 2: "3.1 Passwords must be a minimum of 12 characters', props[0]['policy_ref'])
        self.assertTrue(all(p['policy_ref'].startswith('IS-04.pdf') for p in props))
        for p in props:
            self.c.ok('POST', 'setting_checks', {**p, 'engagement_id': self.eng['id'], 'workpaper_id': self.wp['id']})
        self.c.ok('POST', 'setting_checks', {'engagement_id': self.eng['id'], 'workpaper_id': self.wp['id'],
                                             'label': 'Minimum password age', 'operator': '>=', 'expected': '1'})
        self.c.ok('POST', 'setting_checks', {'engagement_id': self.eng['id'], 'workpaper_id': self.wp['id'],
                                             'label': 'Maximum password age', 'operator': '<=', 'expected': '90'})
        # Already-added checks are not suggested again.
        self.assertEqual(self.c.ok('POST', f"workpapers/{self.wp['id']}/setting_checks/suggest", {}), [])
        res = {r['label']: r for r in self.c.ok('POST', f"workpapers/{self.wp['id']}/setting_checks/run", {})}
        length = res['Minimum password length']
        self.assertEqual((length['check_result'], length['check_actual'], length['check_source_file_id']), ('Exception', '8', shot['id']))
        self.assertEqual(length['check_source_line'], 'Minimum password length 8 characters')
        self.assertEqual(res['Account lockout threshold']['check_result'], 'Pass')
        self.assertEqual(res['Password must meet complexity requirements']['check_result'], 'Pass')
        age = res['Minimum password age']
        self.assertEqual((age['check_result'], age['check_actual']), ('Pass', '1'))
        self.assertIn('verify against the image', age['check_note'])
        self.assertEqual(res['Maximum password age']['check_result'], 'Not found')
        # Policy text itself is never used as the "actual" value.
        self.assertTrue(all(r['check_source_file_id'] in (None, shot['id']) for r in res.values()))
        self.assertNotEqual(pol['id'], length['check_source_file_id'])

    def test_editing_a_rule_clears_its_result_and_runs_reset_signoffs(self):
        self.wait_ocr(self.attach(self.GPO, 'gpo.png')['id'])
        rule = self.c.ok('POST', 'setting_checks', {'engagement_id': self.eng['id'], 'workpaper_id': self.wp['id'],
                                                    'label': 'Minimum password length', 'operator': '>=', 'expected': '8'})
        self.c.ok('PUT', 'workpapers/' + self.wp['id'], {'result': 'Effective'})
        self.c.ok('POST', f"workpapers/{self.wp['id']}/signoff", {'kind': 'prepare'})
        self.c.ok('POST', f"workpapers/{self.wp['id']}/setting_checks/run", {})
        self.assertIsNone(self.c.ok('GET', 'workpapers/' + self.wp['id'])['prepared_by'])
        rule = self.c.ok('GET', 'setting_checks/' + rule['id'])
        self.assertEqual(rule['check_result'], 'Pass')
        rule = self.c.ok('PUT', 'setting_checks/' + rule['id'], {'expected': '14'})
        self.assertIsNone(rule['check_result'])
        self.assertEqual(self.c.req('PUT', 'setting_checks/' + rule['id'], {'operator': 'like'})[0], 400)
        self.assertEqual(self.c.req('POST', 'setting_checks', {'engagement_id': self.eng['id'], 'workpaper_id': self.wp['id'],
                                                              'label': 'x', 'operator': '~'})[0], 400)
        self.assertEqual(self.c.req('POST', f"workpapers/{self.wp['id']}/setting_checks/run", {})[0], 200)

    def test_workpaper_delete_removes_tool_records(self):
        pop = self.attach(b'id\n1\n2\n', 'pop.csv')
        self.c.ok('POST', f"workpapers/{self.wp['id']}/sample", {'file_id': pop['id'], 'size': 1})
        self.c.ok('POST', 'setting_checks', {'engagement_id': self.eng['id'], 'workpaper_id': self.wp['id'], 'label': 'x', 'expected': '1'})
        self.c.ok('DELETE', 'workpapers/' + self.wp['id'])
        self.assertEqual(self.c.ok('GET', 'samples?workpaper_id=' + self.wp['id']), [])
        self.assertEqual(self.c.ok('GET', 'setting_checks?workpaper_id=' + self.wp['id']), [])


class PolicyUnitTest(unittest.TestCase):
    def test_screenshot_text_is_not_mistaken_for_policy(self):
        gpo = 'Minimum password length    8 characters\nPassword must meet complexity requirements    Enabled'
        self.assertEqual(policycheck.suggest([{'id': 'g', 'name': 'gpo.png', 'kind': 'image', 'text': gpo}]), [])
        # The same lines in a PDF settings report (e.g. gpresult) aren't policy wording either.
        self.assertEqual(policycheck.suggest([{'id': 'r', 'name': 'gpresult.pdf', 'kind': 'pdf', 'text': gpo}]), [])
        policy = 'Passwords must meet complexity requirements as defined by the CISO.'
        self.assertEqual([p['label'] for p in policycheck.suggest([{'id': 'p', 'name': 'p.pdf', 'kind': 'pdf', 'text': policy}])],
                         ['Password must meet complexity requirements'])

    def test_operators_and_not_defined(self):
        files = [{'id': 'f', 'name': 'x', 'kind': 'image', 'text': 'Account lockout threshold    Not Defined\nMaximum password age 120 days'}]
        r = policycheck.evaluate({'label': 'Account lockout threshold', 'operator': '<=', 'expected': '5'}, files)
        self.assertEqual((r['check_result'], r['check_actual']), ('Exception', 'Not defined'))
        r = policycheck.evaluate({'label': 'Maximum password age', 'operator': '<=', 'expected': '90'}, files)
        self.assertEqual((r['check_result'], r['check_actual']), ('Exception', '120'))
        r = policycheck.evaluate({'label': 'Maximum password age', 'operator': '!=', 'expected': '0'}, files)
        self.assertEqual(r['check_result'], 'Pass')


@unittest.skipUnless(shutil.which('tesseract') and shutil.which('pdftotext'), 'Tesseract and Poppler are needed')
class RealEvidenceTest(Base):
    """The real policy PDF and GPO screenshot fixtures, read by the real engines."""
    engine = OcrEngine()

    def test_policy_pdf_vs_gpo_screenshot(self):
        self.wait_ocr(self.attach((FIX / 'policy_mixed.pdf').read_bytes(), 'IS-04 Access Control Policy.pdf')['id'])
        self.wait_ocr(self.attach((FIX / 'gpo_password_policy.png').read_bytes(), 'gpo.png')['id'])
        for p in self.c.ok('POST', f"workpapers/{self.wp['id']}/setting_checks/suggest", {}):
            self.c.ok('POST', 'setting_checks', {**p, 'engagement_id': self.eng['id'], 'workpaper_id': self.wp['id']})
        res = {r['label']: (r['check_result'], r['check_actual']) for r in
               self.c.ok('POST', f"workpapers/{self.wp['id']}/setting_checks/run", {})}
        self.assertEqual(res, {'Minimum password length': ('Exception', '8'), 'Account lockout threshold': ('Pass', '5'),
                               'Password must meet complexity requirements': ('Pass', 'Enabled')})


if __name__ == '__main__':
    unittest.main()
