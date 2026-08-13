"""
vault_access_review.py

Audits a 1Password Business account via the `op` CLI, looking for two distinct patterns
that don't show up in a simple "who has access to what" list:

1. Vault placement risk -- a service/system-looking credential (title matches keywords like
   "test", "admin", "service", a known SaaS name) sitting in a vault with broad, company-wide
   access (e.g. the default "Team Members" group). This is the shape of the real incident this
   script is modeled on: a test account credential saved into a shared vault, visible to far more
   people than anyone intended, undetected for weeks.

2. Access sprawl -- an individual granted direct access to a vault that is *also* covered by a
   group. A redundant, untracked grant sitting alongside the "official" access path is exactly
   the kind of thing that gets forgotten and never reviewed.

Auth: relies on an already-authenticated `op` CLI session (`eval $(op signin)` run beforehand).
Never stores or touches the account password/secret key -- this script only reads what the
CLI already has access to.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from datetime import date

from fpdf import FPDF

# ---- config -----------------------------------------------------------------

# Group names treated as "broad, company-wide access" when paired with a service-looking item.
# "Team Members" is 1Password Business's default all-employee group.
BROAD_ACCESS_GROUPS = {"Team Members"}

# Default groups every vault gets automatically -- not evidence of a deliberate,
# team-specific access decision, so they don't count toward the sprawl check.
DEFAULT_GROUPS = {"Administrators", "Owners", "Team Members"}
SERVICE_KEYWORDS = [
    "test", "admin", "service", "system", "bot", "svc", "root", "prod", "staging",
    "server", "ssh", "database", "db", "api key", "workspace", "portal",
]


def run_op(args: list[str]) -> list | dict:
    """Run an `op` CLI command and parse its JSON output."""
    result = subprocess.run(
        ["op"] + args + ["--format=json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"op {' '.join(args)} failed: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else []


def get_vaults() -> list[dict]:
    return run_op(["vault", "list"])


def get_vault_groups(vault_name: str) -> list[dict]:
    try:
        return run_op(["vault", "group", "list", vault_name])
    except RuntimeError:
        return []


def get_vault_users(vault_name: str) -> list[dict]:
    try:
        return run_op(["vault", "user", "list", vault_name])
    except RuntimeError:
        return []


def get_vault_items(vault_name: str) -> list[dict]:
    try:
        return run_op(["item", "list", "--vault", vault_name])
    except RuntimeError:
        return []


def looks_like_service_credential(title: str) -> bool:
    lowered = title.lower()
    return any(keyword in lowered for keyword in SERVICE_KEYWORDS)


def analyze_vault(vault: dict) -> dict:
    """Pull groups, users, and items for one vault and compute both finding types."""
    name = vault["name"]
    groups = get_vault_groups(name)
    users = get_vault_users(name)
    items = get_vault_items(name)

    group_names = {g.get("name", "") for g in groups}
    has_broad_group = bool(group_names & BROAD_ACCESS_GROUPS)

    return {
        "vault_name": name,
        "vault_id": vault.get("id", ""),
        "item_count": vault.get("items", len(items)),
        "groups": groups,
        "users": users,
        "items": items,
        "has_broad_group": has_broad_group,
        "group_names": sorted(group_names),
        "individual_user_count": len(users),
    }


def find_placement_risks(vault_analysis: dict) -> list[dict]:
    """Flag service-looking items sitting in a vault with broad, company-wide access."""
    findings = []
    if not vault_analysis["has_broad_group"]:
        return findings

    for item in vault_analysis["items"]:
        title = item.get("title", "(untitled)")
        if looks_like_service_credential(title):
            findings.append(
                {
                    "type": "VAULT_PLACEMENT_RISK",
                    "status": "FAIL",
                    "vault": vault_analysis["vault_name"],
                    "item": title,
                    "detail": (
                        f"Service-looking credential in a broad-access vault "
                        f"(groups: {', '.join(vault_analysis['group_names'])})"
                    ),
                }
            )
    return findings


def find_access_sprawl(vault_analysis: dict) -> list[dict]:
    """Flag individual users who have direct access to a vault a custom team group covers."""
    findings = []

    # Only meaningful if the vault has a deliberate, team-specific group -- not just the
    # defaults every vault gets automatically.
    custom_groups = set(vault_analysis["group_names"]) - DEFAULT_GROUPS
    if not custom_groups:
        return findings

    for user in vault_analysis["users"]:
        permissions = user.get("permissions", [])
        if "manage_vault" in permissions:
            # Admin-level access is expected and not itself a sprawl finding.
            continue

        name = user.get("name", user.get("email", "unknown"))
        findings.append(
            {
                "type": "ACCESS_SPRAWL_CHECK",
                "status": "FLAG",
                "vault": vault_analysis["vault_name"],
                "item": name,
                "detail": (
                    f"Individual grant alongside team group access "
                    f"(custom group(s): {', '.join(sorted(custom_groups))}). "
                    f"Verify this person needs direct access outside the group path."
                ),
            }
        )
    return findings

    # Admins/owners are expected to show up individually regardless -- only flag
    # non-admin individual grants sitting alongside group-based access.
    for user in vault_analysis["users"]:
        name = user.get("name", user.get("email", "unknown"))
        findings.append(
            {
                "type": "ACCESS_SPRAWL_CHECK",
                "status": "FLAG",
                "vault": vault_analysis["vault_name"],
                "item": name,
                "detail": (
                    f"Individual grant alongside group-based access "
                    f"(vault also has group(s): {', '.join(vault_analysis['group_names'])}). "
                    f"Verify this person needs direct access outside the group path."
                ),
            }
        )
    return findings


def write_txt(findings: list[dict], run_date: str) -> str:
    filename = f"vault_access_review_{run_date}.txt"
    fails = [f for f in findings if f["status"] == "FAIL"]

    with open(filename, "w") as f:
        f.write("1Password Vault Access Review\n")
        f.write(f"Run date: {run_date}\n")
        f.write(f"Total findings: {len(findings)}\n")
        f.write(f"High-priority (vault placement risk): {len(fails)}\n\n")
        for finding in findings:
            f.write(f"[{finding['status']}] {finding['type']} -- {finding['vault']} / {finding['item']}\n")
            f.write(f"    {finding['detail']}\n")

    return filename


def write_csv(findings: list[dict], run_date: str) -> str:
    filename = f"vault_access_review_{run_date}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "status", "vault", "item", "detail"])
        writer.writeheader()
        writer.writerows(findings)
    return filename


def write_pdf(findings: list[dict], run_date: str) -> str:
    filename = f"vault_access_review_{run_date}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "1Password Vault Access Review")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Run date: {run_date}")
    pdf.ln(12)

    pdf.set_font("Helvetica", "B", 9)
    col_widths = [45, 20, 35, 45, 45]
    headers = ["Type", "Status", "Vault", "Item", "Detail"]
    for w, h in zip(col_widths, headers):
        pdf.cell(w, 8, h, border=1)
    pdf.ln()

    pdf.set_font("Helvetica", "", 7)
    for finding in findings:
        pdf.cell(col_widths[0], 8, finding["type"][:28], border=1)
        pdf.cell(col_widths[1], 8, finding["status"], border=1)
        pdf.cell(col_widths[2], 8, finding["vault"][:22], border=1)
        pdf.cell(col_widths[3], 8, finding["item"][:28], border=1)
        pdf.cell(col_widths[4], 8, finding["detail"][:28], border=1)
        pdf.ln()

    pdf.output(filename)
    return filename


def print_summary(findings: list[dict]) -> None:
    fails = [f for f in findings if f["status"] == "FAIL"]
    flags = [f for f in findings if f["status"] == "FLAG"]

    print("\n1Password Vault Access Review")
    print(f"Total findings: {len(findings)}")
    print(f"Vault placement risks (FAIL): {len(fails)}")
    print(f"Access sprawl checks (FLAG): {len(flags)}\n")

    if fails:
        print("VAULT PLACEMENT RISKS:")
        for f in fails:
            print(f"  !! {f['vault']} / {f['item']}")
            print(f"     {f['detail']}")

    print("\nACCESS SPRAWL CHECKS:")
    for f in flags:
        print(f"  -  {f['vault']} / {f['item']}")


def main():
    try:
        vaults = get_vaults()
    except RuntimeError as e:
        print(f"ERROR: {e}")
        print("Make sure you've run `eval $(op signin)` in this terminal session first.")
        sys.exit(1)

    all_findings = []
    for vault in vaults:
        analysis = analyze_vault(vault)
        all_findings.extend(find_placement_risks(analysis))
        all_findings.extend(find_access_sprawl(analysis))

    if not all_findings:
        print("No findings -- check that vaults have groups/items configured.")
        sys.exit(0)

    run_date = date.today().isoformat()
    txt_file = write_txt(all_findings, run_date)
    csv_file = write_csv(all_findings, run_date)
    pdf_file = write_pdf(all_findings, run_date)

    print_summary(all_findings)
    print(f"\nReports written: {txt_file}, {csv_file}, {pdf_file}")


if __name__ == "__main__":
    main()