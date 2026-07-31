"""
Daily housekeeping. Two jobs, neither of which deletes anything.

1. A high-scoring resource ignored for the whole grace window goes to Purgatory.
   Silence is a decision.
2. A resource that has sat in Purgatory for its full term is reported as
   releasable. A human does the deleting, because this role cannot.
"""

import json
import os
from datetime import datetime, timezone

import boto3

from common import PURGATORY_DAYS, days_from_now, scan_state, update_state
from decide import enter_purgatory

REGION = os.environ["AWS_REGION"]
SENDER = os.environ["SENDER_EMAIL"]
RECIPIENT = os.environ["RECIPIENT_EMAIL"]
ses = boto3.client("ses", region_name=REGION)


def expired(ts) -> bool:
    if not ts:
        return False
    try:
        return datetime.fromisoformat(str(ts)) < datetime.now(timezone.utc)
    except ValueError:
        return False


def handler(event, context):
    moved, releasable = [], []

    for item in scan_state("FLAGGED"):
        if item.get("verdict") != "PURGATORY_CANDIDATE":
            continue
        if not expired(item.get("graceUntil")):
            continue
        detail = enter_purgatory(item)
        update_state(item["resourceId"], "PURGATORY", {
            "purgatoryUntil": days_from_now(PURGATORY_DAYS),
            "purgatoryActions": detail,
            "purgatoryReason": "grace period expired with no response",
        })
        moved.append(f"{item['resourceId']}: {detail}")

    for item in scan_state("PURGATORY"):
        if expired(item.get("purgatoryUntil")):
            update_state(item["resourceId"], "RELEASABLE")
            releasable.append(item["resourceId"])

    if moved or releasable:
        body = ""
        if moved:
            body += (
                "<h3>Moved to Purgatory (no response in the grace window)</h3>"
                "<ul>" + "".join(f"<li>{m}</li>" for m in moved) + "</ul>"
            )
        if releasable:
            body += (
                "<h3>Purgatory complete, safe to delete by hand</h3>"
                "<p>These sat stopped for the full term and nobody claimed them. "
                "<b>This app cannot delete them.</b> Its IAM role has no "
                "<code>Delete*</code> or <code>Terminate*</code> permission. "
                "That is on purpose. You do the deleting.</p><ul>"
                + "".join(f"<li><code>{r}</code></li>" for r in releasable)
                + "</ul>"
            )
        ses.send_email(
            Source=SENDER,
            Destination={"ToAddresses": [RECIPIENT]},
            Message={
                "Subject": {"Data": "Who Made This? Purgatory update"},
                "Body": {"Html": {"Data": f"<html><body>{body}</body></html>"}},
            },
        )

    result = {"movedToPurgatory": len(moved), "releasable": len(releasable)}
    print(json.dumps(result))
    return result
