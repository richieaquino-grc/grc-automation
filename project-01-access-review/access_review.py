import csv
from datetime import datetime, timedelta

today = datetime.now()
cutoff = today - timedelta(days=90)

all_findings = []

with open("users.csv", "r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        mfa_status = "PASS" if row["mfa_enabled"] == "yes" else "FAIL"

        last_login_date = datetime.strptime(row["last_login"], "%Y-%m-%d")
        login_status = "PASS" if last_login_date > cutoff else "FAIL"

        all_findings.append({
            "name": row["name"],
            "department": row["department"],
            "mfa_status": mfa_status,
            "login_status": login_status
        })

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

with open("access_review_report.txt", "w") as report:
    report.write("Access Review Report\n")
    report.write("Generated: " + timestamp + "\n\n")

    for finding in all_findings:
        report.write(finding["name"] + " (" + finding["department"] + ")\n")
        report.write("  MFA: " + finding["mfa_status"] + "\n")
        report.write("  Last Login: " + finding["login_status"] + "\n\n")

print("Report written to access_review_report.txt")

csv_fields = ["name", "department", "mfa_status", "login_status"]

with open("access_review_report.csv", "w", newline="") as csv_report:
    writer = csv.DictWriter(csv_report, fieldnames=csv_fields)
    writer.writeheader()
    for finding in all_findings:
        writer.writerow(finding)

print("Report written to access_review_report.csv")
from fpdf import FPDF

pdf = FPDF()
pdf.add_page()

pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "Access Review Report", new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 8, "Generated: " + timestamp, new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

pdf.set_font("Helvetica", "B", 10)
pdf.cell(50, 8, "Name", border=1)
pdf.cell(40, 8, "Department", border=1)
pdf.cell(30, 8, "MFA", border=1)
pdf.cell(35, 8, "Last Login", border=1, new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
for finding in all_findings:
    pdf.cell(50, 8, finding["name"], border=1)
    pdf.cell(40, 8, finding["department"], border=1)
    pdf.cell(30, 8, finding["mfa_status"], border=1)
    pdf.cell(35, 8, finding["login_status"], border=1, new_x="LMARGIN", new_y="NEXT")

pdf.output("access_review_report.pdf")
print("Report written to access_review_report.pdf")