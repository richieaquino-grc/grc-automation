import csv
import boto3
from datetime import datetime
from fpdf import FPDF

s3 = boto3.client("s3")

response = s3.list_buckets()
buckets = response["Buckets"]

all_findings = []

for bucket in buckets:
    name = bucket["Name"]

    try:
        s3.get_bucket_encryption(Bucket=name)
        encryption_status = "PASS"
    except:
        encryption_status = "FAIL"

    try:
        pab_response = s3.get_public_access_block(Bucket=name)
        pab_config = pab_response["PublicAccessBlockConfiguration"]

        if pab_config["BlockPublicAcls"] and pab_config["BlockPublicPolicy"]:
            public_access_status = "PASS"
        else:
            public_access_status = "FAIL"
    except:
        public_access_status = "FAIL"

    all_findings.append({
        "bucket_name": name,
        "encryption_status": encryption_status,
        "public_access_status": public_access_status
    })

today_str = datetime.now().strftime("%Y-%m-%d")

csv_filename = "s3_audit_" + today_str + ".csv"
csv_fields = ["bucket_name", "encryption_status", "public_access_status"]

with open(csv_filename, "w", newline="") as csv_report:
    writer = csv.DictWriter(csv_report, fieldnames=csv_fields)
    writer.writeheader()
    for finding in all_findings:
        writer.writerow(finding)

print("Report written to " + csv_filename)

txt_filename = "s3_audit_" + today_str + ".txt"

with open(txt_filename, "w") as txt_report:
    txt_report.write("S3 Bucket Audit Report\n")
    txt_report.write("Generated: " + today_str + "\n\n")

    for finding in all_findings:
        txt_report.write(finding["bucket_name"] + "\n")
        txt_report.write("  Encryption: " + finding["encryption_status"] + "\n")
        txt_report.write("  Public Access Blocked: " + finding["public_access_status"] + "\n\n")

print("Report written to " + txt_filename)

pdf_filename = "s3_audit_" + today_str + ".pdf"

pdf = FPDF()
pdf.add_page()

pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "S3 Bucket Audit Report", new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
pdf.cell(0, 8, "Generated: " + today_str, new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

pdf.set_font("Helvetica", "B", 10)
pdf.cell(70, 8, "Bucket Name", border=1)
pdf.cell(55, 8, "Encryption", border=1)
pdf.cell(55, 8, "Public Access Blocked", border=1, new_x="LMARGIN", new_y="NEXT")

pdf.set_font("Helvetica", "", 10)
for finding in all_findings:
    pdf.cell(70, 8, finding["bucket_name"], border=1)
    pdf.cell(55, 8, finding["encryption_status"], border=1)
    pdf.cell(55, 8, finding["public_access_status"], border=1, new_x="LMARGIN", new_y="NEXT")

pdf.output(pdf_filename)
print("Report written to " + pdf_filename)