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