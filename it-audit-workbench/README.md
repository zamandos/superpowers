# IT Audit Workbench

A single-file, offline tool for IT auditors to plan engagements, run control tests, collect evidence, and rate issues by criticality.

## Run it

Open `index.html` in Chrome, Edge, or Firefox. You don't need to install anything, and it never makes a network call.
Your data is saved in the browser's local storage (IndexedDB) on your machine.

## What it does

| Tab | Purpose |
|---|---|
| **Dashboard** | Testing progress, conclusions, open issues by criticality, a 5x5 risk heat map, and overdue tests or issues. |
| **Planning** | Engagement details (framework, audit period, fieldwork dates, team, objectives, scope, out of scope) and an inherent-risk assessment of auditable areas, ranked by score. |
| **Audit tests** | Control tests: control ID and description, framework reference, nature, frequency, key-control flag, test method, procedure, population, sample size, exceptions, tester and reviewer, due date, status, and conclusion. **Add from ITGC library** adds standard access, change, operations, backup, network, and incident controls. |
| **Evidence** | PBC request tracking (requested, received, accepted, rejected) with file attachments. Each file is stored with a **SHA-256 fingerprint**, which shows it hasn't changed since collection. |
| **Issues** | Findings in condition / criteria / cause / effect / recommendation form, with management owner, due date, status, and response. You can raise an issue straight from an ineffective or partially effective test. |
| **Report** | Draft report: executive summary, scope, detailed findings ordered by criticality, and the controls tested. You can print it or save it as PDF. Issues and tests also export to CSV. |

### Criticality rating

Score = Likelihood (1-5) x Impact (1-5)

| Score | Criticality |
|---|---|
| 20-25 | Critical |
| 12-19 | High |
| 6-11 | Medium |
| 1-5 | Low |

### Suggested sample sizes

When you pick a control frequency, a sample size is suggested. The lower bound applies to non-key controls and the upper bound to key controls.

| Frequency | Sample size |
|---|---|
| Annual | 1 |
| Quarterly | 2 |
| Monthly | 2-5 |
| Weekly | 5-15 |
| Daily | 20-40 |
| Multiple times per day | 25-60 |
| Automated | 1 (test of one plus change controls) |
| As needed | 10-25 |

Change these to match your firm's methodology in `SAMPLE_GUIDE` inside `index.html`. Edit `criticality()` the same way to change the rating bands.

## Backups and sharing

Data stays only in the browser where you entered it. To keep a copy or move it to another machine, use **Backup**: it saves one JSON file with all records and evidence files. **Restore** merges a backup back in.
Evidence may be sensitive, so store backup files under your organisation's data-handling rules.
