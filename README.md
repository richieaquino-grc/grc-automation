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

1. Clone this repo and set up a virtual environment:

python3 -m venv venv
source venv/bin/activate
pip install fpdf2

2. Run the script:

python access_review.py

3. Check the generated report files in the project folder.

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

1. Activate the virtual environment (see setup above) and make sure fpdf2 is installed.
2. Run the script:

python vendor_risk.py

3. Check the generated dated report files in the project folder.

## Input data

vendors.csv contains sample vendor records with columns: name, data_access_level, last_assessment_date, soc2_on_file.

## SOC 2 / TPRM relevance

This reflects a Third-Party Risk Management control test, verifying that vendors with access to company data are appropriately vetted (SOC 2 report on file) and periodically reassessed based on the risk they pose (tiered by data access level).

---

# IAM Auditor

A Python script that uses boto3 to pull live IAM user data directly from AWS and run a SOC 2 CC6 control test against it, rather than reading from a static file.

## What it does

Connects to AWS using the IAM API and evaluates every IAM user in the account against two checks:

- MFA enforcement — flags any user without a registered MFA device.
- Access freshness — flags any user whose console password hasn't been used within 90 days.

Every user receives an explicit PASS or FAIL on both checks.

## Output format

Each run generates a dated CSV report:

- iam_audit_YYYY-MM-DD.csv

Same evidence-trail approach as the Vendor Risk Scorer — nothing is overwritten, so a history of audits builds up over time.

## How to run it

1. Create an IAM user with an access key (not the AWS root account) and set the following as environment variables:

export AWS_ACCESS_KEY_ID="your_access_key_id"
export AWS_SECRET_ACCESS_KEY="your_secret_access_key"
export AWS_DEFAULT_REGION="your_region"

2. Install boto3:

pip install boto3

3. Run the script:

python iam_auditor.py

4. Check the generated dated report file in the project folder.

## SOC 2 relevance

This maps to CC6 — Logical and Physical Access Controls, applied directly against a live AWS account instead of sample data: verifying MFA is enforced and that IAM users are actively and recently used, flagging stale or unused accounts.

## A note on credentials

This script authenticates using environment variables, never hardcoded keys. AWS access keys and secrets should never be committed to source control — this repo's .gitignore is configured to keep credential files and dated report output out of version control.