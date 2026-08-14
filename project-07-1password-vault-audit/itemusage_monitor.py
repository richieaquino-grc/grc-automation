"""
itemusage_monitor.py

Polls the 1Password Events API for item usage events (item accessed, filled, revealed,
exported, etc.) and cross-references each event's vault against which vaults have broad,
company-wide access (the "Team Members" default group -- same definition used in
vault_access_review.py).

An access event on an item sitting in a broad-access vault is the near-real-time version of
the incident this whole project is modeled on: not "this credential sits somewhere risky"
(caught by the point-in-time vault review), but "someone just touched it, right now."

Auth: reads a bearer token from the OP_EVENTS_TOKEN environment variable. Never hardcoded,
never logged, never written to disk.

Cursor handling: the Events API is a continuous stream. This script saves its position
(cursor) to a local file after each run, so the next run picks up exactly where the last one
left off instead of re-fetching from scratch or missing events in between -- the same pattern
a real scheduled job (cron, GitHub Actions) would need.
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone

import requests
from fpdf import FPDF

# ---- config -----------------------------------------------------------------

EVENTS_BASE_URL = "https://events.1password.com"
CURSOR_FILE = ".itemusage_cursor.json"

# Same broad-access definition as vault_access_review.py.
BROAD_ACCESS_GROUPS = {"Team Members"}

# Actions that represent someone actually touching the credential, not just background sync.
NOTABLE_ACTIONS = {"fill", "reveal", "secure-copy", "export", "share", "server-create"}


def get_token() -> str:
    token = os.environ.get("OP_EVENTS_TOKEN")
    if not token:
        print("ERROR: OP_EVENTS_TOKEN environment variable is not set.")
        print("Run: export OP_EVENTS_TOKEN=\"your_token\"")
        sys.exit(1)
    return token


def load_cursor() -> str | None:
    if os.path.exists(CURSOR_FILE):
        with open(CURSOR_FILE) as f:
            return json.load(f).get("cursor")
    return None


def save_cursor(cursor: str) -> None:
    with open(CURSOR_FILE, "w") as f:
        json.dump({"cursor": cursor, "saved_at": datetime.now(timezone.utc).isoformat()}, f)


def fetch_item_usages(token: str, cursor: str | None) -> dict:
    url = f"{EVENTS_BASE_URL}/api/v2/itemusages"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    if cursor:
        body = {"cursor": cursor}
    else:
        # First run -- no saved cursor yet. Look back 30 days to catch anything already
        # sitting in the demo account.
        start_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        body = {"limit": 100, "start_time": start_time}

    response = requests.post(url, headers=headers, json=body, timeout=15)
    if response.status_code != 200:
        raise RuntimeError(f"Events API returned {response.status_code}: {response.text}")
    return response.json()


def get_broad_vault_ids() -> dict:
    """Return {vault_id: vault_name} for every vault that has a broad-access group."""
    result = subprocess.run(
        ["op", "vault", "list", "--format=json"], capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"WARNING: could not list vaults via op CLI: {result.stderr.strip()}")
        return {}

    vaults = json.loads(result.stdout)
    broad = {}
    for vault in vaults:
        group_result = subprocess.run(
            ["op", "vault", "group", "list", vault["name"], "--format=json"],
            capture_output=True,
            text=True,
        )
        if group_result.returncode != 0:
            continue
        groups = json.loads(group_result.stdout)
        group_names = {g.get("name", "") for g in groups}
        if group_names & BROAD_ACCESS_GROUPS:
            broad[vault["id"]] = vault["name"]
    return broad


def analyze_events(items: list[dict], broad_vaults: dict) -> list[dict]:
    findings = []
    for event in items:
        vault_uuid = event.get("vault_uuid", "")
        action = event.get("action", "")
        user = event.get("user", {})

        in_broad_vault = vault_uuid in broad_vaults
        is_notable = action in NOTABLE_ACTIONS

        findings.append(
            {
                "status": "FLAG" if (in_broad_vault and is_notable) else "INFO",
                "timestamp": event.get("timestamp", ""),
                "action": action,
                "user": user.get("name", user.get("email", "unknown")),
                "vault": broad_vaults.get(vault_uuid, vault_uuid),
                "item_uuid": event.get("item_uuid", ""),
                "ip_address": event.get("client", {}).get("ip_address", ""),
            }
        )
    return findings


def write_txt(findings: list[dict], run_date: str) -> str:
    filename = f"itemusage_monitor_{run_date}.txt"
    flags = [f for f in findings if f["status"] == "FLAG"]

    with open(filename, "w") as f:
        f.write("1Password Item Usage Monitor\n")
        f.write(f"Run date: {run_date}\n")
        f.write(f"Total events: {len(findings)}\n")
        f.write(f"Flagged (notable action on broad-access vault): {len(flags)}\n\n")
        for finding in findings:
            f.write(
                f"[{finding['status']}] {finding['timestamp']} -- {finding['action']} by "
                f"{finding['user']} in {finding['vault']} (ip: {finding['ip_address']})\n"
            )

    return filename


def write_csv(findings: list[dict], run_date: str) -> str:
    filename = f"itemusage_monitor_{run_date}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["status", "timestamp", "action", "user", "vault", "item_uuid", "ip_address"],
        )
        writer.writeheader()
        writer.writerows(findings)
    return filename


def write_pdf(findings: list[dict], run_date: str) -> str:
    filename = f"itemusage_monitor_{run_date}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "1Password Item Usage Monitor")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Run date: {run_date}")
    pdf.ln(12)

    pdf.set_font("Helvetica", "B", 9)
    col_widths = [15, 35, 25, 30, 35, 45]
    headers = ["Status", "Timestamp", "Action", "User", "Vault", "IP"]
    for w, h in zip(col_widths, headers):
        pdf.cell(w, 8, h, border=1)
    pdf.ln()

    pdf.set_font("Helvetica", "", 7)
    for finding in findings:
        pdf.cell(col_widths[0], 8, finding["status"], border=1)
        pdf.cell(col_widths[1], 8, finding["timestamp"][:19], border=1)
        pdf.cell(col_widths[2], 8, finding["action"][:15], border=1)
        pdf.cell(col_widths[3], 8, finding["user"][:18], border=1)
        pdf.cell(col_widths[4], 8, finding["vault"][:18], border=1)
        pdf.cell(col_widths[5], 8, finding["ip_address"][:20], border=1)
        pdf.ln()

    pdf.output(filename)
    return filename


def print_summary(findings: list[dict]) -> None:
    flags = [f for f in findings if f["status"] == "FLAG"]

    print("\n1Password Item Usage Monitor")
    print(f"Total events: {len(findings)}")
    print(f"Flagged: {len(flags)}\n")

    if flags:
        print("FLAGGED EVENTS (notable action on a broad-access vault item):")
        for f in flags:
            print(f"  !! {f['timestamp']} -- {f['action']} by {f['user']} in {f['vault']}")
    else:
        print("No flagged events on this run.")


def main():
    token = get_token()
    cursor = load_cursor()

    try:
        response = fetch_item_usages(token, cursor)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    items = response.get("items", [])
    new_cursor = response.get("cursor")

    broad_vaults = get_broad_vault_ids()
    findings = analyze_events(items, broad_vaults)

    if new_cursor:
        save_cursor(new_cursor)

    if not findings:
        print("No item usage events found in this window.")
        sys.exit(0)

    run_date = date.today().isoformat()
    txt_file = write_txt(findings, run_date)
    csv_file = write_csv(findings, run_date)
    pdf_file = write_pdf(findings, run_date)

    print_summary(findings)
    print(f"\nReports written: {txt_file}, {csv_file}, {pdf_file}")
    print(f"Cursor saved to {CURSOR_FILE} -- next run continues from here.")


if __name__ == "__main__":
    main()