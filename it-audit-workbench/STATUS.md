# Project status

Last updated: 2026-10-29. Work happens on branch `ccr-f38b2f08-675gm1` of `zamandos/superpowers`, in the `it-audit-workbench/` folder.

## Built so far

- **Multi-user audit management.** Python standard library plus SQLite. Roles: admin, manager, auditor, auditee. Includes:
  - audit universe and annual plan
  - engagements and workpapers
  - preparer/reviewer sign-off with segregation of duties
  - review notes
  - issues with likelihood × impact criticality, and an auditee response portal
  - time against budget, dashboards and reports
  - full audit trail
- **Evidence attached to each test.** Drag-and-drop, with a purpose and description per file, a SHA-256 fingerprint, and logged downloads.
- **Reading evidence.** OCR of screenshots (Tesseract, with Pillow enhancement). Text extraction from PDFs with OCR of scanned pages (Poppler). Viewer with search, copy, and "add to test results". Search across all evidence.
- **Testing tools on each test:**
  1. Reproducible random sampling with re-performance.
  2. Access test: leavers and dormant accounts, comparing an account extraction with the HR leavers report.
  3. Policy vs actual settings: requirements suggested from policy PDFs, checked against screenshots.

See `README.md` for setup and full feature details.

## How to run

```bash
python3 server.py                          # http://127.0.0.1:8080, prints the first admin password
python3 -m unittest discover -s tests      # 41 tests
```

Optional tools: `tesseract-ocr` and `poppler-utils` (system packages), and `pillow` (pip).

## Known limitations

- No single sign-on / LDAP and no email notifications.
- Word (.docx) and Excel evidence text are not read yet. Old .xls workbooks are not supported.
- Policy suggestions recognise the built-in password and lockout settings only. Other settings can be checked manually.
- "Disabled late" depends on the date column chosen. AD `whenChanged` reflects any change to the account, not only disabling.
- The app lives inside the `superpowers` plugin repository. It should move to its own repository before wider use.

## Candidate next features

From the earlier shortlist:

- Report reliability checks (IPE): how each report was produced, reconciled row counts, population → sample → tested-item lineage.
- Tamper-evident audit trail (hash-chained log) and trusted timestamps on evidence.
- Direct evidence connectors: Entra ID/AD, AWS, Azure, ServiceNow, GitHub, Jira.
- Optional AI assistant: draft findings, pre-review consistency checks, policy summaries.
- One test mapped to many frameworks (ISO 27001, NIST, SOX, PCI, SOC 2).
- Auditee portal for document requests, with uploads, reminders and escalation.
- Repeat-finding and root-cause analytics.
- Personal-data detection and redaction in evidence.
- Continuous control monitoring.
- Reading text from .docx and .xlsx evidence.
