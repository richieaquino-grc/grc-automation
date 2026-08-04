import csv
import boto3
from datetime import datetime, timedelta, timezone
from fpdf import FPDF

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
txt_filename = "iam_audit_" + today_str + ".txt"

with open(txt_filename, "w") as txt_report:
    txt_report.write("IAM Audit Report\n")
    txt_report.write("Generated: " + today_str + "\n\n")

    for finding in all_findings:
        txt_report.write(finding["username"] + "\n")
        txt_report.write("  MFA: " + finding["mfa_status"] + "\n")
        txt_report.write("  Freshness: " + finding["freshness_status"] + "\n\n")

print("Report written to " + txt_filename)
pdf_filename = "iam_audit_" + today_str + ".pdf"

pdf = FPDF()
pdf.add_page()

pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "IAM Audit Report", new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 8, "Generated: " + today_str, new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

pdf.set_font("Helvetica", "B", 10)
pdf.cell(70, 8, "Username", border=1)
pdf.cell(50, 8, "MFA", border=1)
pdf.cell(50, 8, "Freshness", border=1, new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
for finding in all_findings:
    pdf.cell(70, 8, finding["username"], border=1)
    pdf.cell(50, 8, finding["mfa_status"], border=1)
    pdf.cell(50, 8, finding["freshness_status"], border=1, new_x="LMARGIN", new_y="NEXT")

pdf.output(pdf_filename)
print("Report written to " + pdf_filename)