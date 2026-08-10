"""
gcp_access_review.py

Pulls the IAM policy for a GCP project and reports who holds which role.
Mirrors project-04-iam-auditor (AWS) but for Google Cloud.

Flags high-privilege bindings (Owner, Editor) the same way the AWS auditor
flags admin-equivalent policies -- these are the roles that matter most in
a SOC 2 access review.

Auth: service account key file (never committed -- see ../secrets/).
"""

import csv
import sys
from datetime import date, datetime, timezone

from fpdf import FPDF
from google.oauth2 import service_account
from googleapiclient.discovery import build

# ---- config ---------------------------------------------------------------

PROJECT_ID = "richie-grc-lab"
KEY_PATH = "../secrets/gcp-service-account-key.json"

# Roles considered high-privilege for flagging purposes.
# roles/owner and roles/editor grant broad write access across the project.
HIGH_PRIVILEGE_ROLES = {
    "roles/owner": "Owner -- full project control, including IAM changes",
    "roles/editor": "Editor -- can modify most resources, cannot manage IAM",
}


def get_iam_policy(project_id: str, key_path: str) -> dict:
    """Authenticate with the service account key and fetch the project's IAM policy."""
    credentials = service_account.Credentials.from_service_account_file(
        key_path,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    service = build("cloudresourcemanager", "v1", credentials=credentials)
    policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
    return policy


def flatten_bindings(policy: dict) -> list[dict]:
    """Turn {role: [members]} bindings into one row per (role, member) pair."""
    rows = []
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        for member in binding.get("members", []):
            member_type, _, identity = member.partition(":")
            status = "FAIL" if role in HIGH_PRIVILEGE_ROLES else "PASS"
            rows.append(
                {
                    "role": role,
                    "member_type": member_type,
                    "identity": identity or member,
                    "status": status,
                    "note": HIGH_PRIVILEGE_ROLES.get(role, "Standard role, not flagged"),
                }
            )
    return rows


def write_txt(rows: list[dict], project_id: str, run_date: str) -> str:
    filename = f"gcp_access_review_{run_date}.txt"
    flagged = [r for r in rows if r["status"] == "FAIL"]

    with open(filename, "w") as f:
        f.write(f"GCP Access Review -- project: {project_id}\n")
        f.write(f"Run date: {run_date}\n")
        f.write(f"Total role bindings: {len(rows)}\n")
        f.write(f"Flagged (high-privilege): {len(flagged)}\n\n")
        for r in rows:
            f.write(f"[{r['status']}] {r['role']} -- {r['member_type']}:{r['identity']}\n")
            f.write(f"    {r['note']}\n")

    return filename


def write_csv(rows: list[dict], run_date: str) -> str:
    filename = f"gcp_access_review_{run_date}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["role", "member_type", "identity", "status", "note"]
        )
        writer.writeheader()
        writer.writerows(rows)

    return filename


def write_pdf(rows: list[dict], project_id: str, run_date: str) -> str:
    filename = f"gcp_access_review_{run_date}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "GCP Access Review", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Project: {project_id}", ln=True)
    pdf.cell(0, 8, f"Run date: {run_date}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 9)
    col_widths = [40, 25, 70, 15, 40]
    headers = ["Role", "Type", "Identity", "Status", "Note"]
    for w, h in zip(col_widths, headers):
        pdf.cell(w, 8, h, border=1)
    pdf.ln()

    pdf.set_font("Helvetica", "", 8)
    for r in rows:
        pdf.cell(col_widths[0], 8, r["role"], border=1)
        pdf.cell(col_widths[1], 8, r["member_type"], border=1)
        pdf.cell(col_widths[2], 8, r["identity"][:38], border=1)
        pdf.cell(col_widths[3], 8, r["status"], border=1)
        pdf.cell(col_widths[4], 8, r["note"][:24], border=1)
        pdf.ln()

    pdf.output(filename)
    return filename


def print_summary(rows: list[dict], project_id: str) -> None:
    flagged = [r for r in rows if r["status"] == "FAIL"]
    print(f"\nGCP Access Review -- project: {project_id}")
    print(f"Pulled at: {datetime.now(timezone.utc).isoformat()}")
    print(f"Total role bindings: {len(rows)}\n")

    if flagged:
        print(f"HIGH-PRIVILEGE FINDINGS ({len(flagged)}):")
        for r in flagged:
            print(f"  [{r['role']}] {r['member_type']}:{r['identity']}")
            print(f"    -> {r['note']}")
    else:
        print("No Owner/Editor role bindings found.")

    print("\nAll bindings:")
    for r in rows:
        marker = "!!" if r["status"] == "FAIL" else "  "
        print(f"  {marker} {r['role']:<20} {r['member_type']:<15} {r['identity']}")


def main():
    try:
        policy = get_iam_policy(PROJECT_ID, KEY_PATH)
    except FileNotFoundError:
        print(f"ERROR: key file not found at {KEY_PATH}")
        print("Check that gcp-service-account-key.json is in ../secrets/")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: could not fetch IAM policy: {e}")
        sys.exit(1)

    rows = flatten_bindings(policy)

    if not rows:
        print("No bindings returned -- check that the service account has Viewer access.")
        sys.exit(1)

    run_date = date.today().isoformat()
    txt_file = write_txt(rows, PROJECT_ID, run_date)
    csv_file = write_csv(rows, run_date)
    pdf_file = write_pdf(rows, PROJECT_ID, run_date)

    print_summary(rows, PROJECT_ID)
    print(f"\nReports written: {txt_file}, {csv_file}, {pdf_file}")


if __name__ == "__main__":
    main()