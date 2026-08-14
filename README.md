# GRC Automation Portfolio

A collection of Python scripts automating SOC 2 control tests and access reviews, built as a
hands-on learning project. What started
as file-based control tests has grown into live audits against real cloud and SaaS environments
AWS, Google Cloud, and 1Password including near-real-time detection via event streaming,
not just point-in-time snapshots. One script runs on an automated daily schedule via GitHub
Actions. A control catalog (control_catalog.yaml) ties every script back to a documented risk
hypothesis, owner, and framework mapping, so the collection reads as a program rather than a set
of one-off checks. Each project still follows the same core pattern underneath: pull data,
apply a compliance rule, and report findings in text, CSV, and PDF formats with a dated evidence
trail.

## Project structure

Each project lives in its own folder. To run a script, `cd` into its folder first, since scripts read and write files relative to the current directory:

- project-01-access-review/ — SOC 2 CC6 access review (MFA + stale login checks)
- project-02-vendor-risk-scorer/ — TPRM vendor risk scoring with dated evidence trail
- project-03-github-api/ — Public and authenticated API calls against GitHub
- project-04-iam-auditor/ — Live AWS IAM audit (MFA + password freshness) via boto3
- project-04-s3-checker/ — Live AWS S3 bucket audit (encryption + public access)
- project-04-unused-access-finder/ — Live AWS IAM access key usage audit
- project-05-cross-system-review/ — AWS IAM cross-referenced against a synthetic HR roster
- project-06-gcp-access-review/ — Live GCP IAM audit, flagging Owner/Editor access via a service account
- project-07-1password-vault-audit/ — 1Password vault access review, flagging placement risk and access sprawl

## A note on data and scope

Every account, credential, and dataset in this repository was created specifically for this
portfolio, on personal hardware, using personal email addresses and personal cloud/SaaS trial
accounts (AWS, GCP, GitHub, 1Password). No company data, private data, or personally identifiable
information appears anywhere in this repo. No employer, current or former, is named or
identifiable anywhere in this repository or its history. Any resemblance between a synthetic
finding here and a real-world scenario is a reflection of common, well-documented failure modes
in access management not a description of any specific organization's environment.

## Control catalog

control_catalog.yaml, at the repo root, is the judgment layer behind every script in this
portfolio. Each entry maps one control to its risk hypothesis, proportionality reasoning, owner,
severity, escalation path, and framework references (SOC 2, and PCI DSS where relevant)
independent of which script implements it. The scripts enforce what this file specifies; the
catalog is what makes them defensible as a program rather than a collection of one-off checks.

iso_ref is intentionally left empty across every entry. Extending this repo to a new compliance
framework means populating that column with real mappings, not writing new code the
architecture is designed so evidence collection and framework mapping are separate concerns.
---

# Access Review Automation

A Python script that automates a SOC 2 CC6 (Logical Access) control test by reviewing user access data and flagging control failures.

## What it does

Reads a list of user accounts and evaluates each one against two access control checks:

- MFA enforcement — flags any account without multi-factor authentication enabled.
- Stale access — flags any account that hasn't logged in within 90 days.

Every user receives an explicit PASS or FAIL on both checks, providing evidence that all accounts were evaluated (not just the failures) — which is what auditors look for during a control test.

## Output formats

Running the script generates the same findings in three formats:

- access_review_report.txt — plain-text summary
- access_review_report.csv — spreadsheet-friendly format
- access_review_report.pdf — formatted report with a title, timestamp, and bordered table

## How to run it

1. From the repo root, move into this project's folder and set up a virtual environment:

cd project-01-access-review
python3 -m venv venv
source venv/bin/activate
pip install fpdf2

2. Run the script:

python access_review.py

3. Check the generated report files in this folder.

## Input data

users.csv contains sample user records with columns: name, department, last_login, mfa_enabled.

## SOC 2 relevance

This maps to CC6 — Logical and Physical Access Controls, specifically the requirements that access is authenticated (MFA) and periodically reviewed for accounts that are no longer active (stale access).

---

# Vendor Risk Scorer

A Python script that automates a Third-Party Risk Management (TPRM) control test by reviewing vendor risk data and flagging overdue assessments and missing SOC 2 reports.

## What it does

Reads a list of vendors and evaluates each one against two checks:

- SOC 2 on file — flags any vendor without a SOC 2 report on record, regardless of risk tier.
- Assessment currency — flags any vendor whose last risk assessment is overdue, based on a tiered cadence:
  - critical / high risk: reassess annually
  - medium / low risk: reassess every 2 years

Every vendor receives an explicit PASS or FAIL on both checks.

## Output formats

Each run generates a dated set of reports, so nothing is ever overwritten and a full history is preserved:

- vendor_risk_YYYY-MM-DD.txt — plain-text summary
- vendor_risk_YYYY-MM-DD.csv — spreadsheet-friendly format
- vendor_risk_YYYY-MM-DD.pdf — formatted report with a title, timestamp, and bordered table

Keeping a dated file per run builds an evidence trail — an auditor asking "show me the vendor review from Q1" can be answered by pulling the exact file from that date.

## How to run it

1. From the repo root, move into this project's folder, activate a virtual environment, and make sure fpdf2 is installed:

cd project-02-vendor-risk-scorer
python3 -m venv venv
source venv/bin/activate
pip install fpdf2

2. Run the script:

python vendor_risk.py

3. Check the generated dated report files in this folder.

## Input data

vendors.csv contains sample vendor records with columns: name, data_access_level, last_assessment_date, soc2_on_file.

## SOC 2 / TPRM relevance

This reflects a Third-Party Risk Management control test, verifying that vendors with access to company data are appropriately vetted (SOC 2 report on file) and periodically reassessed based on the risk they pose (tiered by data access level).

---

# GitHub API Scripts

Two small scripts demonstrating real API integration patterns: calling a public, unauthenticated endpoint, and calling an authenticated endpoint using a personal access token stored as an environment variable.

## What they do

github_api_test.py calls GitHub's public API (no credentials required) to pull user and repository data, and demonstrates working with both single JSON objects and lists of objects.

github_auth_test.py calls an authenticated GitHub endpoint using a personal access token read from an environment variable (GITHUB_TOKEN), demonstrating credential handling via headers rather than hardcoded secrets.

## How to run it

1. From the repo root, move into this project's folder:

cd project-03-github-api
pip install requests

2. For the authenticated script, set your token as an environment variable first:

export GITHUB_TOKEN="your_personal_access_token"

3. Run either script:

python github_api_test.py
python github_auth_test.py

## Relevance

Demonstrates the foundational pattern behind every real API integration used later in this repo: a URL, optional headers carrying a token for authentication, and a GET request to retrieve data as JSON.

---

# IAM Auditor

A Python script that uses boto3 to pull live IAM user data directly from AWS and run a SOC 2 CC6 control test against it, rather than reading from a static file.

## What it does

Connects to AWS using the IAM API and evaluates every IAM user in the account against two checks:

- MFA enforcement — flags any user without a registered MFA device.
- Access freshness — flags any user whose console password hasn't been used within 90 days.

Every user receives an explicit PASS or FAIL on both checks.

## Output formats

Each run generates a dated set of reports, matching the format of the other projects in this repo:

- iam_audit_YYYY-MM-DD.txt — plain-text summary
- iam_audit_YYYY-MM-DD.csv — spreadsheet-friendly format
- iam_audit_YYYY-MM-DD.pdf — formatted report with a title, timestamp, and bordered table

Same evidence-trail approach as the Vendor Risk Scorer — nothing is overwritten, so a history of audits builds up over time.

## How to run it

1. From the repo root, move into this project's folder and create an IAM user with an access key (not the AWS root account), then set the following as environment variables:

cd project-04-iam-auditor
export AWS_ACCESS_KEY_ID="your_access_key_id"
export AWS_SECRET_ACCESS_KEY="your_secret_access_key"
export AWS_DEFAULT_REGION="your_region"

2. Install boto3 and fpdf2:

pip install boto3 fpdf2

3. Run the script:

python iam_auditor.py

4. Check the generated dated report files in this folder.

## SOC 2 relevance

This maps to CC6 — Logical and Physical Access Controls, applied directly against a live AWS account instead of sample data: verifying MFA is enforced and that IAM users are actively and recently used, flagging stale or unused accounts.

## A note on credentials

This script authenticates using environment variables, never hardcoded keys. AWS access keys and secrets should never be committed to source control — this repo's .gitignore is configured to keep credential files and dated report output out of version control.

---

# S3 Bucket Checker

A Python script that uses boto3 to pull live S3 bucket configuration from AWS and check two data protection controls: encryption at rest and public access blocking.

## What it does

Connects to AWS via the S3 API and evaluates every bucket in the account against two checks:

- Encryption — flags any bucket without server-side encryption configured.
- Public access blocked — flags any bucket that doesn't have public access blocking fully enabled, or has no public access block configuration at all.

Every bucket receives an explicit PASS or FAIL on both checks.

## Output formats

Each run generates a dated set of reports:

- s3_audit_YYYY-MM-DD.txt — plain-text summary
- s3_audit_YYYY-MM-DD.csv — spreadsheet-friendly format
- s3_audit_YYYY-MM-DD.pdf — formatted report with a title, timestamp, and bordered table

## How to run it

1. From the repo root, move into this project's folder. Set AWS credentials as environment variables (see IAM Auditor setup above).

cd project-04-s3-checker

2. Install boto3 and fpdf2 if not already installed:

pip install boto3 fpdf2

3. Run the script:

python s3_checker.py

4. Check the generated dated report files in this folder.

## SOC 2 relevance

This reflects a data protection control test, verifying that storage resources enforce encryption at rest and are not inadvertently exposed to the public internet — both common SOC 2 and general security findings when misconfigured.

---

# Unused Access Key Finder

A Python script that uses boto3 to check every IAM access key in the account and flag ones that haven't been used in the last 90 days — a common finding in access reviews, since unused live credentials carry risk without providing business value.

## What it does

Loops through every IAM user and every access key belonging to that user, checking each key's last-used timestamp (as reported by AWS itself) against a 90-day cutoff. Keys that have never been used at all are also flagged, since a key with zero usage history is exactly the kind of unnecessary standing access an audit should catch.

Every key receives an explicit PASS or FAIL, along with its current status (Active/Inactive).

## Output formats

Each run generates a dated set of reports:

- unused_access_YYYY-MM-DD.txt — plain-text summary
- unused_access_YYYY-MM-DD.csv — spreadsheet-friendly format
- unused_access_YYYY-MM-DD.pdf — formatted report with a title, timestamp, and bordered table

## How to run it

1. From the repo root, move into this project's folder. Set AWS credentials as environment variables (see IAM Auditor setup above).

cd project-04-unused-access-finder

2. Install boto3 and fpdf2 if not already installed:

pip install boto3 fpdf2

3. Run the script:

python unused_access_finder.py

4. Check the generated dated report files in this folder.

## SOC 2 relevance

This maps to CC6 — Logical and Physical Access Controls, specifically the principle of least privilege and periodic access review: credentials that exist but are never used represent unnecessary risk and should be identified, reviewed, and deactivated or removed.

---

# Cross-System Access Review

A Python script that cross-references live AWS IAM users against a company HR roster to catch a common and high-risk finding: employees who have left the company but still have active access to a system.

## What it does

Pulls the real, live list of IAM users from AWS via boto3, and reads a simulated HR roster (150 employees, representing a realistic company headcount) from a CSV. For each AWS account, it checks whether that account belongs to a currently active employee, a terminated employee (an orphaned account), or an account with no matching HR record at all.

Known service and admin accounts (accounts that don't map 1:1 to an individual employee, such as an AWS admin account) are maintained in an explicit, documented exception list rather than being treated as false positives — a standard real-world audit practice.

## Output formats

Each run generates a dated set of reports:

- cross_system_review_YYYY-MM-DD.txt — plain-text summary
- cross_system_review_YYYY-MM-DD.csv — spreadsheet-friendly format
- cross_system_review_YYYY-MM-DD.pdf — formatted report with a title, timestamp, and bordered table

## How to run it

1. From the repo root, move into this project's folder. Set AWS credentials as environment variables (see IAM Auditor setup above).

cd project-05-cross-system-review

2. Install boto3 and fpdf2 if not already installed:

pip install boto3 fpdf2

3. Ensure hr_roster.csv is present in this folder (columns: name, department, status).
4. Run the script:

python cross_system_review.py

5. Check the generated dated report files in this folder.

## SOC 2 relevance

This directly reflects a core offboarding/deprovisioning control under CC6 — Logical and Physical Access Controls: verifying that access is promptly revoked when an employee's status changes, and that every system account can be tied back to a known, currently active identity or a documented exception.

## A note on the data

The HR roster (hr_roster.csv) is synthetic data generated for this project and does not represent any real company or individuals. The AWS side of this comparison is live, real data pulled from a personal AWS lab account.


---

# GCP Access Review

A Python script that authenticates with a GCP service account key and pulls the live IAM policy for a Google Cloud project via the Cloud Resource Manager API, flagging any identity with Owner or Editor access — the GCP equivalent of admin-level privilege.

## What it does

Connects to a GCP project using a dedicated service account (itself scoped to read-only Viewer access) and evaluates every IAM role binding in the project:

- Owner / Editor roles — flagged as high-privilege, since these grant broad write access (Owner also controls IAM itself).
- All other roles (e.g., Viewer) — pass, since they carry no meaningful write or admin capability.

Every binding — user or service account — receives an explicit PASS or FAIL, so the report shows the full access picture, not just the flagged findings.

## Output formats

Each run generates a dated set of reports, matching the format of the other live-API projects in this repo:

- gcp_access_review_YYYY-MM-DD.txt — plain-text summary
- gcp_access_review_YYYY-MM-DD.csv — spreadsheet-friendly format
- gcp_access_review_YYYY-MM-DD.pdf — formatted report with a title, timestamp, and bordered table

## How to run it

1. From the repo root, move into this project's folder and activate the shared virtual environment:

cd project-06-gcp-access-review
source ../venv/bin/activate

2. Install dependencies:

pip install google-api-python-client google-auth fpdf2

3. Place a GCP service account key (JSON, scoped to Viewer on the target project) at ../secrets/gcp-service-account-key.json. This path is covered by .gitignore and is never committed.
4. Run the script:

python gcp_access_review.py

5. Check the generated dated report files in this folder.

## SOC 2 relevance

This maps to CC6 — Logical and Physical Access Controls, applied to a second live cloud environment alongside the AWS projects in this repo. It demonstrates that the same access-review pattern — authenticate, pull live identity data, flag admin-equivalent privilege — generalizes across cloud providers rather than being AWS-specific.

## A note on scope

The service account used to run this script holds only the Viewer role — it can read IAM policy but cannot modify anything, including its own permissions. This mirrors the least-privilege principle the script itself is checking for.


---

# 1Password Vault Access Review

A Python script that audits a 1Password Business account via the `op` CLI, looking for two
patterns that a simple "who has access to what" list doesn't surface on its own: credentials
placed in overly broad vaults, and individual access grants sitting outside a team's normal
access path.

## What it does

Connects to 1Password using an already-authenticated CLI session and evaluates every vault
against two checks:

- Vault placement risk — flags service/system-looking credentials (titles matching keywords like
  "test," "admin," "service," or a known SaaS name) sitting in a vault with broad, company-wide
  access (the default "Team Members" group). A credential that looks like infrastructure shouldn't
  be reachable by the whole company by default.
- Access sprawl — flags individuals with direct, individual access to a vault that a
  team-specific group already covers, excluding admin-level and default-group access. A
  standing grant sitting alongside the "official" access path is the kind of thing that gets
  forgotten and never reviewed.

This project is modeled on a real access-review gap: a test credential saved into a
broadly-shared vault, visible to far more people than intended, undetected for an extended
period until discovered by chance. The two checks above are aimed directly at catching that
pattern automatically instead of by accident.

## Output formats

Each run generates a dated set of reports:

- vault_access_review_YYYY-MM-DD.txt — plain-text summary
- vault_access_review_YYYY-MM-DD.csv — spreadsheet-friendly format
- vault_access_review_YYYY-MM-DD.pdf — formatted report with a title, timestamp, and bordered table

## How to run it

1. Install the 1Password CLI and authenticate:

brew install --cask 1password-cli
op account add
eval $(op signin)

2. From the repo root, move into this project's folder and activate the shared virtual environment:

cd project-07-1password-vault-audit
source ../venv/bin/activate

3. Install dependencies:

pip install fpdf2

4. Run the script:

python vault_access_review.py

5. Check the generated dated report files in this folder.

## SOC 2 relevance

This maps to CC6 — Logical and Physical Access Controls, extended to a credential vault rather
than a cloud IAM system. Vault-level access review is a common but often-overlooked SOC 2 finding
area: identity and access management controls tend to focus on cloud/SaaS systems, leaving the
system that stores the credentials to those systems itself unreviewed.

## A note on scope

This script only reads data the authenticated `op` CLI session already has access to. It never
stores, logs, or transmits the account password, Secret Key, or any vault item contents.

## Stretch goal: item usage monitor

A second script, `itemusage_monitor.py`, polls the 1Password Events API directly (not the CLI)
for item usage and creation events, cross-referenced against the same broad-vault definition as
the access review. It flags `server-create` events landing in a broad-access vault -- the exact
moment a credential is created somewhere far more people can see it than intended, which is the
root event this whole project is modeled on, not just a downstream symptom of it.

### How to run it

1. In the 1Password Business admin console, go to Integrations -> Events Reporting -> Other, and
   create an Events Reporting integration with a bearer token scoped to at least `itemusages`.
2. Export the token as an environment variable -- never hardcode it, never commit it:

export OP_EVENTS_TOKEN="your_token_here"

3. Install the additional dependency:

pip install requests

4. Run the script:

python itemusage_monitor.py

The script saves its position (a cursor) to `.itemusage_cursor.json` after each run, so
subsequent runs only pick up new events instead of re-fetching or missing anything in between 
the same pattern a real scheduled job would need.

---

# Automated Scheduling (GitHub Actions)

The IAM Auditor runs automatically on a daily schedule using GitHub Actions, with no manual steps required. This turns a script you'd otherwise run by hand into a real, unattended compliance check.

## What it does

A workflow defined in .github/workflows/iam-audit.yml triggers automatically once a day (cron schedule) and can also be triggered manually from the Actions tab in GitHub. Each run: checks out the repository, installs Python dependencies, runs project-04-iam-auditor/iam_auditor.py using AWS credentials stored as encrypted GitHub Actions secrets, and uploads the generated TXT/CSV/PDF reports as a downloadable artifact.

## Why this matters

This is the same pattern used in real compliance automation: a control test that used to require someone to remember to run it manually now runs itself, every day, and produces evidence automatically. AWS credentials are never stored in the code or committed to the repo — they live only in GitHub's encrypted secrets store and are injected into the workflow at runtime.

## How to view a run

1. Go to the repository's "Actions" tab on GitHub.
2. Click "IAM Audit" to see the run history.
3. Click any individual run to see step-by-step logs, or download the generated report from the "Artifacts" section of that run's summary page.
4. Use the "Run workflow" button to trigger a run manually at any time, without waiting for the daily schedule.
   
