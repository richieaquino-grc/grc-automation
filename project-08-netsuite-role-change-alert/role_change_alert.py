"""
role_change_alert.py

Flags employee role changes, department moves, departures, and leave (including leave of
absence and maternity leave) that haven't had an access review yet, using a scheduled export
of HR system-of-record change-request data (modeled on NetSuite/SuitePeople's change request
record) instead of a live API connection.

The problem this targets: a position or status change is usually entered into the HR system
well before it takes effect, but IT often only finds out the day before or the day of,
sometimes from a coworker instead of HR. That's not a gap in the HR data -- the change
request record already exists with a proposed effective date, often weeks out. It's a gap in
what gets looked at. This script reads the same kind of record and flags any request that
doesn't yet have an access review, ranked by how close the effective date is. A daily or
every-other-day run is enough here; these changes don't need to be caught within the hour,
just within a day or two.

Auth: none. Reads a scheduled CSV export (role_change_requests.csv) -- the same file a real
version would receive from a scheduled saved-search export, not a live credential. Only
ordinary fields are read: name, department, role, change type, and two dates. No pay,
birth date, home address, or free-text justification fields are read or stored.
"""

from __future__ import annotations

import csv
from datetime import date, datetime

from fpdf import FPDF

# ---- config -----------------------------------------------------------------

INPUT_FILE = "role_change_requests.csv"

# A request within this many days of its effective date, with no access review yet,
# is urgent enough to fail outright rather than just be an early warning.
URGENT_WINDOW_DAYS = 7


def parse_date(value: str) -> date:
    return datetime.strptime(value.strip(), "%Y-%m-%d").date()


def load_requests(filename: str) -> list[dict]:
    with open(filename, newline="") as f:
        return list(csv.DictReader(f))


def evaluate_request(row: dict, run_date: date) -> dict:
    """Score one change request: how much lead time it gave us, and whether it's been
    reviewed in time."""
    entered = parse_date(row["request_entered_date"])
    effective = parse_date(row["effective_date"])
    reviewed = row["access_reviewed"].strip().lower() == "yes"

    lead_time_days = (effective - entered).days
    days_until_effective = (effective - run_date).days

    if reviewed:
        status = "PASS"
        detail = f"Access reviewed. Lead time was {lead_time_days} days."
    elif days_until_effective <= URGENT_WINDOW_DAYS:
        status = "FAIL"
        detail = (
            f"No access review on file and the change takes effect in "
            f"{days_until_effective} day(s). This needed review days ago."
        )
    else:
        status = "FLAG"
        detail = (
            f"No access review yet, but {days_until_effective} day(s) of lead time remain "
            f"before it takes effect. Early warning, not yet urgent."
        )

    return {
        "employee": row["employee_name"],
        "department": row["department"],
        "change_type": row["change_type"],
        "current_role": row["current_role"],
        "proposed_role": row["proposed_role"],
        "request_entered_date": row["request_entered_date"],
        "effective_date": row["effective_date"],
        "lead_time_days": lead_time_days,
        "days_until_effective": days_until_effective,
        "status": status,
        "detail": detail,
    }


def median(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 0:
        return (ordered[mid - 1] + ordered[mid]) / 2
    return float(ordered[mid])


def write_txt(findings: list[dict], run_date: str, median_lead: float) -> str:
    filename = f"role_change_alert_{run_date}.txt"
    fails = [f for f in findings if f["status"] == "FAIL"]
    flags = [f for f in findings if f["status"] == "FLAG"]

    with open(filename, "w") as f:
        f.write("NetSuite Role-Change Early Warning\n")
        f.write(f"Run date: {run_date}\n")
        f.write(f"Total requests reviewed: {len(findings)}\n")
        f.write(f"Unreviewed and urgent (FAIL): {len(fails)}\n")
        f.write(f"Unreviewed, early warning (FLAG): {len(flags)}\n")
        f.write(f"Median lead time across all requests: {median_lead:.1f} days\n\n")
        for finding in findings:
            f.write(
                f"[{finding['status']}] {finding['employee']} ({finding['department']}) -- "
                f"{finding['change_type']}\n"
            )
            f.write(
                f"    {finding['current_role']} -> {finding['proposed_role']} | "
                f"entered {finding['request_entered_date']}, effective {finding['effective_date']} "
                f"(lead time {finding['lead_time_days']}d)\n"
            )
            f.write(f"    {finding['detail']}\n")

    return filename


def write_csv(findings: list[dict], run_date: str) -> str:
    filename = f"role_change_alert_{run_date}.csv"
    fieldnames = [
        "employee", "department", "change_type", "current_role", "proposed_role",
        "request_entered_date", "effective_date", "lead_time_days",
        "days_until_effective", "status", "detail",
    ]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
    return filename


def write_pdf(findings: list[dict], run_date: str, median_lead: float) -> str:
    filename = f"role_change_alert_{run_date}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "NetSuite Role-Change Early Warning")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Run date: {run_date}")
    pdf.ln(8)
    pdf.cell(0, 8, f"Median lead time across all requests: {median_lead:.1f} days")
    pdf.ln(12)

    pdf.set_font("Helvetica", "B", 8)
    col_widths = [30, 22, 25, 40, 22, 22, 20, 15]
    headers = [
        "Employee", "Department", "Change type", "Role change", "Entered",
        "Effective", "Lead (d)", "Status",
    ]
    for w, h in zip(col_widths, headers):
        pdf.cell(w, 8, h, border=1)
    pdf.ln()

    pdf.set_font("Helvetica", "", 7)
    for finding in findings:
        role_change = f"{finding['current_role'][:14]} -> {finding['proposed_role'][:14]}"
        pdf.cell(col_widths[0], 8, finding["employee"][:18], border=1)
        pdf.cell(col_widths[1], 8, finding["department"][:14], border=1)
        pdf.cell(col_widths[2], 8, finding["change_type"][:16], border=1)
        pdf.cell(col_widths[3], 8, role_change[:30], border=1)
        pdf.cell(col_widths[4], 8, finding["request_entered_date"], border=1)
        pdf.cell(col_widths[5], 8, finding["effective_date"], border=1)
        pdf.cell(col_widths[6], 8, str(finding["lead_time_days"]), border=1)
        pdf.cell(col_widths[7], 8, finding["status"], border=1)
        pdf.ln()

    pdf.output(filename)
    return filename


def print_summary(findings: list[dict], median_lead: float) -> None:
    fails = [f for f in findings if f["status"] == "FAIL"]
    flags = [f for f in findings if f["status"] == "FLAG"]
    passes = [f for f in findings if f["status"] == "PASS"]

    print("\nNetSuite Role-Change Early Warning")
    print(f"Total requests reviewed: {len(findings)}")
    print(f"Reviewed on time (PASS): {len(passes)}")
    print(f"Early warning, still time to act (FLAG): {len(flags)}")
    print(f"Unreviewed and urgent (FAIL): {len(fails)}")
    print(f"Median lead time across all requests: {median_lead:.1f} days\n")

    if fails:
        print("URGENT, NO ACCESS REVIEW ON FILE:")
        for f in fails:
            print(f"  !! {f['employee']} ({f['department']}) -- {f['detail']}")

    if flags:
        print("\nEARLY WARNING:")
        for f in flags:
            print(f"  -  {f['employee']} ({f['department']}) -- {f['detail']}")


def main():
    rows = load_requests(INPUT_FILE)
    run_date = date.today()

    findings = [evaluate_request(row, run_date) for row in rows]
    median_lead = median([f["lead_time_days"] for f in findings])

    run_date_str = run_date.isoformat()
    txt_file = write_txt(findings, run_date_str, median_lead)
    csv_file = write_csv(findings, run_date_str)
    pdf_file = write_pdf(findings, run_date_str, median_lead)

    print_summary(findings, median_lead)
    print(f"\nReports written: {txt_file}, {csv_file}, {pdf_file}")


if __name__ == "__main__":
    main()
