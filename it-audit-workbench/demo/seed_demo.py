"""Load a realistic demo (fictional Harbor & Pine Logistics) into a fresh Audit Workbench.

    AUDIT_ADMIN_PASSWORD=admin-password-1 python3 server.py --port 8050 --data demo-data
    python3 demo/seed_demo.py --port 8050

Run against an empty data folder: it signs in with the first admin password above.
Demo sign-ins afterwards: admin / admin-password-2, maria / maria-password-2 (manager),
sam / sam-password-22 and priya / priya-password-2 (auditors), jo / jo-password-22 (auditee).
"""
import argparse
import json
import sys
import time
from pathlib import Path

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP / 'tests'))
from test_server import Client  # noqa: E402

_p = argparse.ArgumentParser(description='Load the Audit Workbench demo data.')
_p.add_argument('--port', type=int, default=8050)
PORT = _p.parse_args().port
FIX = APP / 'tests' / 'fixtures'


def login(u, p, new=None):
    c = Client(PORT)
    c.ok('POST', 'login', {'username': u, 'password': p})
    if new:
        c.ok('POST', 'me/password', {'old': p, 'new': new})
    return c


admin = login('admin', 'admin-password-1', 'admin-password-2')
U = {}
for un, name, role in [('maria', 'Maria Lopez', 'manager'), ('sam', 'Sam Patel', 'auditor'), ('priya', 'Priya Shah', 'auditor'),
                       ('jo', 'Jo Kim (IT Operations)', 'auditee'), ('omar', 'Omar Haddad (Engineering)', 'auditee')]:
    U[un] = admin.ok('POST', 'users', {'username': un, 'name': name, 'role': role, 'password': un + '-initial-pw',
                                       'email': f'{un}@harborpine.example'})['id']
maria = login('maria', 'maria-initial-pw', 'maria-password-2')
sam = login('sam', 'sam-initial-pw', 'sam-password-22')
priya = login('priya', 'priya-initial-pw', 'priya-password-2')
jo = login('jo', 'jo-initial-pw', 'jo-password-22')

# ---- universe & plan
uni = {}
for name, cat, owner, freq, l, i, last in [
        ('SAP S/4HANA (ERP)', 'Application', 'Finance IT', 'Annual', '4', '5', '2025-03-31'),
        ('Active Directory & Entra ID', 'Infrastructure', 'IT Operations', 'Annual', '4', '5', '2025-06-30'),
        ('AWS production accounts', 'Infrastructure', 'Cloud Platform', 'Annual', '4', '4', '2024-11-15'),
        ('Change management (ServiceNow)', 'Process', 'IT Service Management', 'Every 2 years', '3', '4', '2025-09-30'),
        ('Third-party remote access', 'Vendor', 'Procurement & Security', 'Every 2 years', '3', '3', '2025-02-28'),
        ('Backup & disaster recovery', 'Process', 'IT Operations', 'Every 3 years', '2', '5', '2023-10-31'),
        ('Warehouse management system', 'Application', 'Logistics Ops', 'Every 3 years', '2', '3', '2024-05-31')]:
    uni[name] = maria.ok('POST', 'universe', {'name': name, 'category': cat, 'owner': owner, 'frequency': freq,
                                              'likelihood': l, 'impact': i, 'last_audited': last})['id']

eng = maria.ok('POST', 'engagements', {
    'name': 'FY26 ITGC: Active Directory & ERP', 'universe_id': uni['Active Directory & Entra ID'], 'auditee': 'IT Operations / Finance IT',
    'framework': 'SOX ITGC', 'status': 'Fieldwork', 'lead_id': U['maria'], 'team': 'Sam Patel, Priya Shah', 'budget_hours': '160',
    'period_start': '2026-01-01', 'period_end': '2026-09-30', 'field_start': '2026-10-05', 'field_end': '2026-11-13',
    'objectives': 'Assess whether IT general controls over Active Directory and SAP S/4HANA were designed and operated effectively '
                  'throughout the audit period, to support reliance for the FY26 financial statement audit.',
    'scope': 'Active Directory (CORP domain) and Entra ID; SAP S/4HANA production client 100.\nLogical access (provisioning, leavers, '
             'reviews, privileged access, authentication), change management, backup.',
    'out_of_scope': 'Warehouse management system (audited 2024). Application controls within SAP.'})
E = eng['id']
cloud = maria.ok('POST', 'engagements', {'name': 'Cloud security review: AWS', 'universe_id': uni['AWS production accounts'],
                                         'auditee': 'Cloud Platform', 'framework': 'NIST CSF 2.0', 'status': 'Planning',
                                         'lead_id': U['priya'], 'budget_hours': '120', 'field_start': '2026-11-16', 'field_end': '2026-12-11'})
vendor = maria.ok('POST', 'engagements', {'name': 'Third-party remote access 2026', 'universe_id': uni['Third-party remote access'],
                                          'auditee': 'Procurement & Security', 'framework': 'ISO/IEC 27001:2022', 'status': 'Reporting',
                                          'lead_id': U['maria'], 'budget_hours': '80', 'field_start': '2026-08-03', 'field_end': '2026-08-28'})
for title, u, q, lead, hrs, status, e in [
        ('FY26 ITGC: SAP S/4HANA', 'SAP S/4HANA (ERP)', 'Q1', 'maria', '140', 'Completed', None),
        ('Third-party remote access 2026', 'Third-party remote access', 'Q3', 'maria', '80', 'In progress', vendor['id']),
        ('FY26 ITGC: Active Directory & ERP', 'Active Directory & Entra ID', 'Q4', 'maria', '160', 'In progress', E),
        ('Cloud security review: AWS', 'AWS production accounts', 'Q4', 'priya', '120', 'In progress', cloud['id']),
        ('Change management deep dive', 'Change management (ServiceNow)', 'Q4', 'maria', '90', 'Deferred', None)]:
    maria.ok('POST', 'plan', {'title': title, 'universe_id': uni[u], 'year': '2026', 'quarter': q, 'lead_id': U[lead],
                              'budget_hours': hrs, 'status': status, 'engagement_id': e,
                              'notes': 'Deferred to Q1 2027: ServiceNow upgrade in flight.' if status == 'Deferred' else None})

# ---- risks & workpapers
risk = {}
for area, sysn, l, i, resp in [
        ('Logical access', 'AD, Entra ID, SAP', '4', '5', 'Test provisioning, leavers, access reviews; data analytics over full leaver population.'),
        ('Privileged access', 'AD Domain Admins, SAP_ALL', '4', '5', 'Inspect privileged group membership and approvals.'),
        ('Change management', 'SAP transports, ServiceNow', '3', '4', 'Sample production changes; test SoD in transport tool.'),
        ('Backup & recovery', 'Veeam, SAP HANA backups', '2', '5', 'Inspect backup logs and last restore test.')]:
    risk[area] = maria.ok('POST', 'risks', {'engagement_id': E, 'area': area, 'system': sysn, 'likelihood': l, 'impact': i,
                                            'response': resp})['id']
WP = {}
for ref, title, area, desc, freq, proc, who, due in [
        ('AC-01', 'User access provisioning', 'Logical access', 'New access is requested in ServiceNow and approved by the line manager and system owner before it is granted.',
         'As needed', 'Obtain AD accounts created in the period; sample; inspect approved request predates creation and matches access granted.', 'sam', '2026-10-16'),
        ('AC-02', 'Timely removal of terminated users', 'Logical access', 'Leavers are disabled within 1 business day of the termination date in Workday.',
         'As needed', 'Compare the HR leavers report with the AD account extraction as at period end; investigate exceptions; sample leavers for SLA.', 'sam', '2026-10-23'),
        ('AC-03', 'Quarterly user access review', 'Logical access', 'System owners review SAP access quarterly and remove inappropriate access within 10 business days.',
         'Quarterly', 'Inspect Q1-Q3 review evidence: completeness of listing, sign-off, removals actioned.', 'priya', '2026-10-23'),
        ('AC-04', 'Privileged access restriction', 'Privileged access', 'Domain Admin and SAP_ALL access is limited to approved named administrators.',
         'Quarterly', 'Obtain privileged group membership; validate each to job role and approval; check for shared accounts.', 'priya', '2026-10-30'),
        ('AC-05', 'Password & authentication settings', 'Logical access', 'Domain password and lockout settings meet IS-04 Access Control Policy.',
         'Automated', 'Inspect Default Domain Policy settings against IS-04 section 3. Test of one (automated control).', 'sam', '2026-10-20'),
        ('CM-01', 'Change authorisation & testing', 'Change management', 'SAP transports to production are tested and approved in ServiceNow before import.',
         'As needed', 'Sample production transports; inspect test evidence and CAB approval before import date.', 'priya', '2026-10-27'),
        ('OP-02', 'Backup completion & restore testing', 'Backup & recovery', 'Daily backups complete successfully; restores are tested at least annually.',
         'Daily', 'Sample 25 days of backup job logs; inspect the latest restore test report.', 'priya', '2026-11-06')]:
    WP[ref] = sam.ok('POST', 'workpapers', {'engagement_id': E, 'ref': ref, 'title': title, 'risk_id': risk[area], 'control_desc': desc,
                                            'frequency': freq, 'key_control': 'Yes', 'nature': 'Automated' if freq == 'Automated' else 'IT-dependent manual',
                                            'test_type': 'Inspection', 'procedure': proc, 'assigned_to': U[who], 'due_date': due,
                                            'framework_ref': {'AC': 'ISO A.5.15 / A.5.18', 'CM': 'ISO A.8.32', 'OP': 'ISO A.8.13'}[ref[:2]]})


def attach(c, wp, path, name, purpose, desc):
    data = Path(path).read_bytes() if isinstance(path, (str, Path)) else path
    from urllib.parse import quote
    return c.ok('POST', f"workpapers/{WP[wp]['id']}/attach", raw=data, headers={
        'X-Filename': quote(name), 'X-Purpose': quote(purpose), 'X-Description': quote(desc)})['file']


def wait(c, fid):
    for _ in range(600):
        f = c.ok('GET', 'files?id=' + fid)[0]
        if f['ocr_status'] not in ('queued', 'running'):
            return f
        time.sleep(0.1)


# AC-02: extraction, leavers, sample, access test
pop = attach(sam, 'AC-02', FIX / 'ad_users.csv', 'AD_users_CORP_2026-09-30.csv', 'Population (e.g. user extraction)',
             'Get-ADUser export of all CORP accounts as at 30 Sep 2026, run by auditor')
lv = attach(sam, 'AC-02', FIX / 'hr_leavers.xlsx', 'Workday_leavers_Jan-Oct_2026.xlsx', 'Supporting documentation',
            'Workday terminations report, 1 Jan to 15 Oct 2026')
sample = sam.ok('POST', f"workpapers/{WP['AC-02']['id']}/sample", {'file_id': pop['id'], 'size': 25, 'seed': '20261030'})
maria.ok('POST', f"samples/{sample['id']}/verify", {})
pu, pl = sam.ok('GET', f"files/{pop['id']}/table"), sam.ok('GET', f"files/{lv['id']}/table")
mapping = {**{k: v for k, v in pu['guess'].items() if k.startswith('user') and v}, **{k: v for k, v in pl['guess'].items() if k.startswith('leaver') and v}}
analysis = sam.ok('POST', f"workpapers/{WP['AC-02']['id']}/access_test", {'users': {'file_id': pop['id']}, 'leavers': {'file_id': lv['id'], 'sheet': 'Leavers'},
                                                                         'mapping': mapping, 'as_at': '2026-09-30', 'sla_days': 1, 'dormant_days': 90})
sam.ok('PUT', 'workpapers/' + WP['AC-02']['id'], {'status': 'In progress', 'result': 'Ineffective', 'exceptions': '4',
                                                  'notes': 'Full-population analytics: 2 leavers still enabled (bwong, kpatel), kpatel logged on 17 days after '
                                                           'termination, tnguyen disabled 16 days late. 3 dormant and 3 generic accounts referred to AC-04.'})

# AC-05: policy + GPO screenshot + checks
pol = attach(sam, 'AC-05', FIX / 'policy_mixed.pdf', 'IS-04_Access_Control_Policy_v3.2.pdf', 'Supporting documentation',
             'IS-04 Access Control Policy v3.2 with signed approval record')
gpo = attach(sam, 'AC-05', FIX / 'gpo_password_policy.png', 'Default_Domain_Policy_password_settings.png', 'Testing performed / tick-marked results',
             'Screenshot of Default Domain Policy password settings, taken in walkthrough with IT Ops on 6 Oct 2026')
wait(sam, pol['id'])
wait(sam, gpo['id'])
for p in sam.ok('POST', f"workpapers/{WP['AC-05']['id']}/setting_checks/suggest", {}):
    sam.ok('POST', 'setting_checks', {**p, 'engagement_id': E, 'workpaper_id': WP['AC-05']['id']})
sam.ok('POST', 'setting_checks', {'engagement_id': E, 'workpaper_id': WP['AC-05']['id'], 'label': 'Store passwords using reversible encryption',
                                  'operator': '=', 'expected': 'Disabled', 'policy_ref': 'Microsoft security baseline'})
sam.ok('POST', f"workpapers/{WP['AC-05']['id']}/setting_checks/run", {})
sam.ok('PUT', 'workpapers/' + WP['AC-05']['id'], {'status': 'In progress', 'result': 'Ineffective', 'exceptions': '1', 'population': 'Default Domain Policy (test of one)',
                                                  'sample_size': '1', 'notes': 'Minimum password length is 8 characters; IS-04 3.1 requires 12. Other settings comply.'})

# AC-01 & CM-01: prepared and reviewed; AC-03 prepared awaiting review; AC-04 open note
for ref, who in (('AC-01', sam), ('CM-01', priya)):
    attach(who, ref, b'change,approved_by,approved_on,imported_on\nCHG0041,J. Alvarez,2026-03-02,2026-03-04\n', f'{ref}_sample_testing.csv',
           'Testing performed / tick-marked results', 'Tick-marked sample testing, 25 items, no exceptions')
    who.ok('PUT', 'workpapers/' + WP[ref]['id'], {'status': 'In progress', 'result': 'Effective', 'exceptions': '0', 'sample_size': '25',
                                                  'population': 'ServiceNow extract, 412 items' if ref == 'CM-01' else 'AD accounts created in period, 186'})
    who.ok('POST', f"workpapers/{WP[ref]['id']}/signoff", {'kind': 'prepare'})
n = maria.ok('POST', 'review_notes', {'engagement_id': E, 'workpaper_id': WP['CM-01']['id'],
                                      'note': 'Confirm the population was complete: reconcile the ServiceNow extract to the SAP transport log (STMS).'})
priya.ok('POST', f"review_notes/{n['id']}/respond", {'response': 'Reconciled 412 transports in STMS to the extract; no differences. Reconciliation attached.'})
maria.ok('POST', f"review_notes/{n['id']}/clear", {})
for ref in ('AC-01', 'CM-01'):
    maria.ok('POST', f"workpapers/{WP[ref]['id']}/signoff", {'kind': 'review'})
priya.ok('PUT', 'workpapers/' + WP['AC-03']['id'], {'status': 'In progress', 'result': 'Effective', 'exceptions': '0', 'sample_size': '2',
                                                    'population': 'Quarterly reviews Q1-Q3'})
priya.ok('POST', f"workpapers/{WP['AC-03']['id']}/signoff", {'kind': 'prepare'})
priya.ok('PUT', 'workpapers/' + WP['AC-04']['id'], {'status': 'In progress'})
maria.ok('POST', 'review_notes', {'engagement_id': E, 'workpaper_id': WP['AC-02']['id'],
                                  'note': 'For kpatel: obtain sign-in logs for 2 Jul to confirm what was accessed after termination, and whether HR was notified.'})

# issues
i1 = sam.ok('POST', 'issues', {'engagement_id': E, 'workpaper_id': WP['AC-02']['id'], 'title': 'Leavers retain active network access',
    'condition': 'Of 7 leavers due by 30 Sep 2026, 2 accounts were still enabled (241 and 107 days after termination). One leaver signed in 17 days after leaving. One account was disabled 16 days late.',
    'criteria': 'IS-04 4.1: access for leavers must be disabled within 1 business day of the termination date recorded in Workday.',
    'cause': 'Disabling relies on a manual ticket raised by line managers; there is no automated feed from Workday to AD.',
    'effect': 'Former employees could access company systems and data after leaving.',
    'likelihood': '4', 'impact': '5', 'owner_id': U['jo'], 'due_date': '2026-12-31',
    'recommendation': 'Automate account disablement from the Workday termination feed, and run a weekly reconciliation of leavers to enabled accounts.'})
i2 = sam.ok('POST', 'issues', {'engagement_id': E, 'workpaper_id': WP['AC-05']['id'], 'title': 'Domain password length below policy',
    'condition': 'Default Domain Policy sets the minimum password length to 8 characters.', 'criteria': 'IS-04 3.1: passwords must be a minimum of 12 characters.',
    'cause': 'Policy was updated in February 2026; the GPO was not changed to match.', 'effect': 'Weaker passwords are easier to guess or crack.',
    'likelihood': '3', 'impact': '4', 'owner_id': U['jo'], 'due_date': '2026-11-30',
    'recommendation': 'Raise the GPO minimum to 12 characters and enforce MFA for all interactive sign-ins.'})
sam.ok('POST', 'issues', {'engagement_id': E, 'title': 'Dormant and generic accounts without owners',
    'condition': '3 enabled accounts had no sign-in for over 90 days; 3 generic accounts (svc-backup, admin.test, scanner01) have no recorded owner.',
    'criteria': 'IS-04 5.1 quarterly access review; service accounts must have a named owner.', 'likelihood': '3', 'impact': '3',
    'owner_id': U['jo'], 'due_date': '2027-01-31', 'recommendation': 'Disable dormant accounts and assign owners to service accounts.'})
maria.ok('POST', 'issues', {'engagement_id': vendor['id'], 'title': 'Vendor VPN accounts not time-limited',
    'condition': '9 of 14 vendor VPN accounts have no expiry date.', 'likelihood': '3', 'impact': '4', 'owner_id': U['omar'],
    'due_date': '2026-10-15', 'status': 'Open', 'recommendation': 'Set 90-day expiry on all vendor accounts.'})
maria.ok('POST', 'issues', {'engagement_id': vendor['id'], 'title': 'Vendor access not reviewed quarterly', 'likelihood': '2', 'impact': '3',
                            'owner_id': U['omar'], 'due_date': '2026-12-15', 'status': 'Remediation in progress'})
jo.ok('PUT', 'issues/' + i2['id'], {'status': 'Remediation in progress',
                                    'response': 'Agreed. GPO change CHG0052 scheduled for 18 Nov 2026 after pilot on IT devices.'})

# time
for who, c, entries in (('sam', sam, [('2026-10-05', 6, 'Planning'), ('2026-10-06', 7.5, 'Fieldwork'), ('2026-10-07', 8, 'Fieldwork'), ('2026-10-08', 7, 'Fieldwork')]),
                        ('priya', priya, [('2026-10-06', 7, 'Fieldwork'), ('2026-10-07', 6.5, 'Fieldwork'), ('2026-10-09', 7.5, 'Fieldwork')]),
                        ('maria', maria, [('2026-10-02', 5, 'Planning'), ('2026-10-09', 4, 'Review'), ('2026-10-16', 3.5, 'Review')])):
    for d, h, act in entries:
        c.ok('POST', 'time_entries', {'engagement_id': E, 'date': d, 'hours': str(h), 'activity': act})
maria.ok('POST', 'time_entries', {'engagement_id': vendor['id'], 'date': '2026-08-10', 'hours': '62', 'activity': 'Fieldwork'})
print(json.dumps({'engagement': E, 'wp': {k: v['id'] for k, v in WP.items()}, 'gpo': gpo['id'], 'policy': pol['id'], 'analysis': analysis['id'],
                  'sample': sample['id'], 'vendor': vendor['id']}))
