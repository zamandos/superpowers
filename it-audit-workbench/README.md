# Audit Workbench

Audit Workbench is a self-hosted, multi-user audit management application for IT audit teams. It covers the full cycle from the risk-based audit universe to issue follow-up, with reviewer sign-off and a complete audit trail.

It needs only **Python 3.9+**. Screenshot OCR additionally uses Tesseract if it's installed (see below). There are no packages to install and no internet access is required. Data stays on your own server in a SQLite database and an evidence folder.

## Quick start

```bash
python3 server.py                       # http://127.0.0.1:8080, data in ./data
```

On first start, the console prints a one-time `admin` password, which must be changed at first sign-in. You can also set it yourself with `AUDIT_ADMIN_PASSWORD=...`. Sign in as admin and add your team under **Admin → Users**.

To let the team use it over the network:

```bash
python3 server.py --host 0.0.0.0 --port 8080 --data /srv/audit-data --secure-cookie
```

Put it behind your HTTPS reverse proxy (nginx, IIS, Caddy) and use `--secure-cookie` there. Back up the `--data` folder, which holds `audit.db` and `evidence/`, with your normal server backups.

## Roles

| Role | Can do |
|---|---|
| **Administrator** | Everything, including managing user accounts. |
| **Audit manager** | Manage the audit universe, annual plan and engagements. Sign off as **reviewer**. Clear review notes. View the full audit trail. |
| **Auditor** | Prepare workpapers, collect evidence, raise issues, log time, respond to review notes, and sign off as **preparer**. An auditor who is an engagement's lead can also edit that engagement. |
| **Auditee** | Sees **only the issues they own**. Can record a management response and move the issue to "Remediation in progress" or "Ready for validation". |

## Features

**Audit universe and annual plan.** Rate each auditable entity (system, process, vendor) by likelihood × impact and set an audit cycle. The next-due date is calculated from the last audit. Add entities to a yearly plan with quarter, lead and budget hours, then start an engagement from a plan item in one click.

**Engagements.** Each engagement records objectives, scope, out-of-scope items, framework (SOX ITGC, ISO 27001, NIST, COBIT, PCI, SOC 2), audit period, fieldwork dates, team and budget. Planning includes a risk assessment that ranks areas so testing goes to the highest-risk ones.

**Workpapers.** One workpaper per control test: control description, framework reference, nature, frequency and key-control flag, test method, procedure, population, sample size and exceptions. Choosing the control frequency fills in a suggested sample size. **Add from ITGC library** loads 12 standard controls covering access, change, operations, backup, network and incident management.

**Sign-off and review**, which follow the usual audit-file controls:
- The preparer signs off once a conclusion is recorded.
- Only a manager can sign off as reviewer, and **never on their own work** (segregation of duties).
- Reviewers raise **review notes**. The preparer responds, and the reviewer clears the note. Any open note blocks review sign-off.
- **Editing the content of a signed-off workpaper removes its sign-offs**, so it must be re-reviewed. Changes to administrative fields such as due date or assignee keep the sign-offs.

**Attaching evidence to a test.** Every workpaper has a **Test evidence** panel directly below the test procedure. To attach a file:
1. Pick what the file is: population (e.g. a user extraction), sample selection, testing performed, supporting documentation, or exception follow-up.
2. Optionally describe it, e.g. "AD user extraction as at 30 Sep, 1,204 accounts".
3. Drag the file onto the panel or click **Choose files**.

Several files can go up at once, with a progress bar. The workpapers list also has an **Attach** link on every row, and it shows how many files each test has. Attaching or removing evidence on a signed-off test removes its sign-offs, so the reviewer sees the change.

**Reading screenshots (OCR).** When an auditor attaches a screenshot (PNG, JPEG, GIF, BMP, TIFF or WebP), the server reads the text in the background. Uploads stay instant, and the file shows *Reading text…* until it's done. Then **View image & text** opens the screenshot beside the extracted text, with:
- **Find in text**, which highlights matches, e.g. "password length".
- **Copy text.**
- **Add to test results**, which appends the text, clearly labelled as OCR output, to the test's results notes.
- **Read again**, which re-runs OCR.

Each result carries a confidence score, and results below 75% are flagged for checking. The **Evidence & PBC** tab can search across file names, descriptions and all text read from screenshots, e.g. find every screenshot that mentions "lockout".

A few rules keep OCR honest as evidence:
- OCR runs **on your server** with Tesseract, so screenshots never leave your network.
- The original image stays the evidence. The text is a reading aid, kept separate and never edited.
- Whether a file is an image is decided from its content, not its name.
- Viewing an image, and each OCR run with its engine version and confidence, is recorded in the audit trail.

**Evidence and PBC requests.** Track each request as requested, received, accepted, or rejected and to be resubmitted. Attach files of up to 50 MB each. Each file is stored with a **SHA-256 fingerprint**, and every upload, download and removal is logged.

**Issues.** Findings are written as condition, criteria, cause, effect and recommendation, with a management owner, due date, status and response. **Criticality = likelihood × impact**:

| Score | Rating |
|---|---|
| 20–25 | Critical |
| 12–19 | High |
| 6–11 | Medium |
| 1–5 | Low |

You can raise an issue straight from a failed workpaper. The **Issue tracker** covers every engagement, with filters and CSV export. Closing an issue records who validated it.

**Time.** Log hours by activity. Budget vs actual is shown per engagement, per person and across the plan.

**Dashboards and reports.**
- **Home** shows *My tasks*: workpapers to complete, notes to answer, workpapers to review, and responses to clear. It also has the engagement portfolio, a criticality heat map and overdue issues.
- **Report** produces a draft report that you can print or save as PDF, plus CSV exports.

**Audit trail.** Every create, edit (with old → new values), delete, sign-off, upload, download and sign-in is logged. Managers can view it per workpaper, per engagement, or for everything.

## Enabling OCR (optional)

OCR needs the free Tesseract engine on the server. Without it, everything else works and screenshots show "OCR not installed". **Admin** shows whether OCR is active.

| Server | Install |
|---|---|
| Ubuntu / Debian | `sudo apt install tesseract-ocr` |
| Red Hat / Fedora | `sudo dnf install tesseract` |
| macOS | `brew install tesseract` |
| Windows | UB Mannheim Tesseract installer; add it to PATH or set `AUDIT_TESSERACT=C:\Program Files\Tesseract-OCR\tesseract.exe` |

For best accuracy on small screenshot text, also install Pillow (`pip install pillow`). Images are then converted to greyscale and enlarged before reading.

For other languages, install the Tesseract language pack and set `AUDIT_OCR_LANG`, e.g. `eng+fra`. Restart the server after installing.

## Working as a team

- Two people editing the same record is handled safely: the second save is refused with "someone else changed this record". The record is never silently overwritten.
- The page reloads the latest data when you return to the browser tab, or when you press **Refresh**.

## Security notes

- Passwords are hashed with PBKDF2-SHA256 (240k iterations) and must be at least 10 characters. New and reset accounts must change their password at next sign-in.
- After 5 failed sign-in attempts, the account is locked for 5 minutes.
- Sessions use HttpOnly, SameSite=Strict cookies, and writes require a custom request header. A strict Content-Security-Policy and anti-framing headers are sent.
- Disabling a user or resetting their password ends their sessions.
- **Not included:** SSO/LDAP and e-mail notifications. Use HTTPS in front of the server for any network use.

## Customising

- **Rating bands:** `criticality()` in `static/app.js`.
- **Sample sizes:** `SAMPLE_GUIDE` in `static/app.js`.
- **Control library:** `LIBRARY` in `static/app.js`.
- **Field lists** (frameworks, statuses, evidence types): `SCHEMAS` in `static/app.js`.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests cover permissions, segregation of duties, sign-off invalidation, review-note blocking, auditee isolation, evidence hashing, optimistic locking, cascade deletes and the audit trail.
