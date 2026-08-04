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

    keys_response = iam.list_access_keys(UserName=username)
    access_keys = keys_response["AccessKeyMetadata"]

    for key in access_keys:
        key_id = key["AccessKeyId"]
        status = key["Status"]

        last_used_response = iam.get_access_key_last_used(AccessKeyId=key_id)
        last_used_info = last_used_response["AccessKeyLastUsed"]
        last_used_date = last_used_info.get("LastUsedDate")

        if last_used_date is not None and last_used_date > cutoff:
            usage_status = "PASS"
        else:
            usage_status = "FAIL"

        all_findings.append({
            "username": username,
            "access_key_id": key_id,
            "key_status": status,
            "usage_status": usage_status
        })

today_str = datetime.now().strftime("%Y-%m-%d")

csv_filename = "unused_access_" + today_str + ".csv"
csv_fields = ["username", "access_key_id", "key_status", "usage_status"]

with open(csv_filename, "w", newline="") as csv_report:
    writer = csv.DictWriter(csv_report, fieldnames=csv_fields)
    writer.writeheader()
    for finding in all_findings:
        writer.writerow(finding)

print("Report written to " + csv_filename)

txt_filename = "unused_access_" + today_str + ".txt"

with open(txt_filename, "w") as txt_report:
    txt_report.write("Unused Access Key Report\n")
    txt_report.write("Generated: " + today_str + "\n\n")

    for finding in all_findings:
        txt_report.write(finding["username"] + " - " + finding["access_key_id"] + "\n")
        txt_report.write("  Key Status: " + finding["key_status"] + "\n")
        txt_report.write("  Used within 90 days: " + finding["usage_status"] + "\n\n")

print("Report written to " + txt_filename)

pdf_filename = "unused_access_" + today_str + ".pdf"

pdf = FPDF()
pdf.add_page()

pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "Unused Access Key Report", new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 8, "Generated: " + today_str, new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

pdf.set_font("Helvetica", "B", 10)
pdf.cell(45, 8, "Username", border=1)
pdf.cell(65, 8, "Access Key ID", border=1)
pdf.cell(35, 8, "Key Status", border=1)
pdf.cell(45, 8, "Used < 90 Days", border=1, new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
for finding in all_findings:
    pdf.cell(45, 8, finding["username"], border=1)
    pdf.cell(65, 8, finding["access_key_id"], border=1)
    pdf.cell(35, 8, finding["key_status"], border=1)
    pdf.cell(45, 8, finding["usage_status"], border=1, new_x="LMARGIN", new_y="NEXT")

pdf.output(pdf_filename)
print("Report written to " + pdf_filename)