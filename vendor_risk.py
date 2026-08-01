import csv
from datetime import datetime, timedelta
from fpdf import FPDF

today = datetime.now()

all_findings = []

with open("vendors.csv", "r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        soc2_status = "PASS" if row["soc2_on_file"] == "yes" else "FAIL"

        if row["data_access_level"] in ("critical", "high"):
            cutoff = today - timedelta(days=365)
        else:
            cutoff = today - timedelta(days=730)

        assessment_date = datetime.strptime(row["last_assessment_date"], "%Y-%m-%d")
        assessment_status = "PASS" if assessment_date > cutoff else "FAIL"

        all_findings.append({
            "name": row["name"],
            "data_access_level": row["data_access_level"],
            "soc2_status": soc2_status,
            "assessment_status": assessment_status
        })

today_str = today.strftime("%Y-%m-%d")

csv_filename = "vendor_risk_" + today_str + ".csv"
csv_fields = ["name", "data_access_level", "soc2_status", "assessment_status"]

with open(csv_filename, "w", newline="") as csv_report:
    writer = csv.DictWriter(csv_report, fieldnames=csv_fields)
    writer.writeheader()
    for finding in all_findings:
        writer.writerow(finding)

print("Report written to " + csv_filename)

txt_filename = "vendor_risk_" + today_str + ".txt"

with open(txt_filename, "w") as txt_report:
    txt_report.write("Vendor Risk Report\n")
    txt_report.write("Generated: " + today_str + "\n\n")

    for finding in all_findings:
        txt_report.write(finding["name"] + " (" + finding["data_access_level"] + ")\n")
        txt_report.write("  SOC 2 on file: " + finding["soc2_status"] + "\n")
        txt_report.write("  Assessment current: " + finding["assessment_status"] + "\n\n")

print("Report written to " + txt_filename)

pdf_filename = "vendor_risk_" + today_str + ".pdf"

pdf = FPDF()
pdf.add_page()

pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "Vendor Risk Report", new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 8, "Generated: " + today_str, new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

pdf.set_font("Helvetica", "B", 10)
pdf.cell(60, 8, "Vendor", border=1)
pdf.cell(35, 8, "Risk Level", border=1)
pdf.cell(45, 8, "SOC 2 on File", border=1)
pdf.cell(40, 8, "Assessment", border=1, new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
for finding in all_findings:
    pdf.cell(60, 8, finding["name"], border=1)
    pdf.cell(35, 8, finding["data_access_level"], border=1)
    pdf.cell(45, 8, finding["soc2_status"], border=1)
    pdf.cell(40, 8, finding["assessment_status"], border=1, new_x="LMARGIN", new_y="NEXT")

pdf.output(pdf_filename)
print("Report written to " + pdf_filename)