import csv
import boto3
from datetime import datetime
from fpdf import FPDF

iam = boto3.client("iam")

response = iam.list_users()
aws_users = response["Users"]

with open("hr_roster.csv", "r") as file:
    reader = csv.DictReader(file)
    hr_roster = list(reader)

known_service_accounts = ["richie-admin"]

all_findings = []

for user in aws_users:
    username = user["UserName"]

    if username in known_service_accounts:
        finding_status = "PASS - known service/admin account"
    else:
        normalized_name = username.replace("-", " ").title()

        match = None
        for employee in hr_roster:
            if employee["name"] == normalized_name:
                match = employee
                break

        if match is None:
            finding_status = "FAIL - not found in HR roster"
        elif match["status"] == "terminated":
            finding_status = "FAIL - terminated employee still has AWS access"
        else:
            finding_status = "PASS"

    all_findings.append({
        "aws_username": username,
        "finding_status": finding_status
    })

today_str = datetime.now().strftime("%Y-%m-%d")

csv_filename = "cross_system_review_" + today_str + ".csv"
csv_fields = ["aws_username", "finding_status"]

with open(csv_filename, "w", newline="") as csv_report:
    writer = csv.DictWriter(csv_report, fieldnames=csv_fields)
    writer.writeheader()
    for finding in all_findings:
        writer.writerow(finding)

print("Report written to " + csv_filename)

txt_filename = "cross_system_review_" + today_str + ".txt"

with open(txt_filename, "w") as txt_report:
    txt_report.write("Cross-System Access Review: AWS IAM vs HR Roster\n")
    txt_report.write("Generated: " + today_str + "\n\n")

    for finding in all_findings:
        txt_report.write(finding["aws_username"] + "\n")
        txt_report.write("  " + finding["finding_status"] + "\n\n")

print("Report written to " + txt_filename)

pdf_filename = "cross_system_review_" + today_str + ".pdf"

pdf = FPDF()
pdf.add_page()

pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "Cross-System Access Review", new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 8, "AWS IAM vs HR Roster - Generated: " + today_str, new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

pdf.set_font("Helvetica", "B", 10)
pdf.cell(60, 8, "AWS Username", border=1)
pdf.cell(120, 8, "Finding", border=1, new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 9)
for finding in all_findings:
    pdf.cell(60, 8, finding["aws_username"], border=1)
    pdf.cell(120, 8, finding["finding_status"], border=1, new_x="LMARGIN", new_y="NEXT")

pdf.output(pdf_filename)
print("Report written to " + pdf_filename)