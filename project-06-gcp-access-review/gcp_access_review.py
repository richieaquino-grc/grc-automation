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
from datetime import datetime, timezone

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
            rows.append(
                {
                    "role": role,
                    "member_type": member_type,
                    "identity": identity or member,
                    "high_privilege": role in HIGH_PRIVILEGE_ROLES,
                    "note": HIGH_PRIVILEGE_ROLES.get(role, ""),
                }
            )
    return rows


def write_report(rows: list[dict], project_id: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"gcp_access_review_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["role", "member_type", "identity", "high_privilege", "note"]
        )
        writer.writeheader()
        writer.writerows(rows)

    return filename


def print_summary(rows: list[dict], project_id: str) -> None:
    print(f"\nGCP Access Review -- project: {project_id}")
    print(f"Pulled at: {datetime.now(timezone.utc).isoformat()}")
    print(f"Total role bindings: {len(rows)}\n")

    flagged = [r for r in rows if r["high_privilege"]]

    if flagged:
        print(f"HIGH-PRIVILEGE FINDINGS ({len(flagged)}):")
        for r in flagged:
            print(f"  [{r['role']}] {r['member_type']}:{r['identity']}")
            print(f"    -> {r['note']}")
    else:
        print("No Owner/Editor role bindings found.")

    print("\nAll bindings:")
    for r in rows:
        marker = "!!" if r["high_privilege"] else "  "
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

    filename = write_report(rows, PROJECT_ID)
    print_summary(rows, PROJECT_ID)
    print(f"\nReport written to: {filename}")


if __name__ == "__main__":
    main()