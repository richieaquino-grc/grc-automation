import csv
import boto3
from datetime import datetime, timedelta, timezone

iam = boto3.client("iam")

response = iam.list_users()
users = response["Users"]

cutoff = datetime.now(timezone.utc) - timedelta(days=90)

all_findings = []

for user in users:
    username = user["UserName"]

    mfa_response = iam.list_mfa_devices(UserName=username)
    mfa_devices = mfa_response["MFADevices"]
    mfa_status = "PASS" if len(mfa_devices) > 0 else "FAIL"

    last_used = user.get("PasswordLastUsed")
    if last_used is not None and last_used > cutoff:
        freshness_status = "PASS"
    else:
        freshness_status = "FAIL"

    all_findings.append({
        "username": username,
        "mfa_status": mfa_status,
        "freshness_status": freshness_status
    })

today_str = datetime.now().strftime("%Y-%m-%d")

csv_filename = "iam_audit_" + today_str + ".csv"
csv_fields = ["username", "mfa_status", "freshness_status"]

with open(csv_filename, "w", newline="") as csv_report:
    writer = csv.DictWriter(csv_report, fieldnames=csv_fields)
    writer.writeheader()
    for finding in all_findings:
        writer.writerow(finding)

print("Report written to " + csv_filename)