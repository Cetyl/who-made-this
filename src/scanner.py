"""
Weekly account archaeology.

Three passes: read-only inventory, CloudTrail attribution, Orphan Score.
Then a deterministic summary and an SES digest with signed decision links.

No generative model is involved. Every number in the email is reproducible.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from common import (
    GRACE_DAYS,
    days_from_now,
    decision_url,
    get_finding,
    now_iso,
    put_finding,
    scan_state,
)

REGION = os.environ["AWS_REGION"]
SENDER = os.environ["SENDER_EMAIL"]
RECIPIENT = os.environ["RECIPIENT_EMAIL"]
BASE_URL = os.environ["DECISION_BASE_URL"]

ec2 = boto3.client("ec2", region_name=REGION)
ct = boto3.client("cloudtrail", region_name=REGION)
iam = boto3.client("iam", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)

OWNER_TAG_KEYS = {"owner", "createdby", "created-by", "team", "contact"}
IAC_HINTS = ("cloudformation", "terraform", "cdk", "serverless", "pulumi")


# --------------------------------------------------------------------------
# pass 1: inventory (read-only, no mutations anywhere in this function)
# --------------------------------------------------------------------------

def tags_to_dict(tags):
    return {t["Key"]: t["Value"] for t in (tags or [])}


def inventory():
    found = []

    for page in ec2.get_paginator("describe_instances").paginate():
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst["State"]["Name"] in ("terminated", "shutting-down"):
                    continue
                found.append({
                    "resourceId": inst["InstanceId"],
                    "type": "ec2:instance",
                    "tags": tags_to_dict(inst.get("Tags")),
                    "launchTime": inst["LaunchTime"].isoformat(),
                    "idle": inst["State"]["Name"] == "stopped",
                    "detail": f"{inst['InstanceType']} ({inst['State']['Name']})",
                })

    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page["Volumes"]:
            found.append({
                "resourceId": vol["VolumeId"],
                "type": "ec2:volume",
                "tags": tags_to_dict(vol.get("Tags")),
                "launchTime": vol["CreateTime"].isoformat(),
                "idle": vol["State"] == "available",   # available means unattached
                "detail": f"{vol['Size']} GiB {vol['VolumeType']} ({vol['State']})",
            })

    for addr in ec2.describe_addresses().get("Addresses", []):
        found.append({
            "resourceId": addr.get("AllocationId", addr["PublicIp"]),
            "type": "ec2:eip",
            "tags": tags_to_dict(addr.get("Tags")),
            "launchTime": None,
            "idle": "AssociationId" not in addr,
            "detail": addr["PublicIp"],
        })

    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        for eni in page["NetworkInterfaces"]:
            if eni.get("RequesterManaged"):
                continue
            found.append({
                "resourceId": eni["NetworkInterfaceId"],
                "type": "ec2:eni",
                "tags": tags_to_dict(eni.get("TagSet")),
                "launchTime": None,
                "idle": eni["Status"] == "available",
                "detail": f"{eni.get('PrivateIpAddress', '')} ({eni['Status']})",
            })

    return found


# --------------------------------------------------------------------------
# pass 2: attribution from CloudTrail Event history (free, 90 day window)
# --------------------------------------------------------------------------

def attribute(resource_id: str) -> dict:
    """
    Ask CloudTrail who touched this resource in the last 90 days.
    LookupEvents throttles around 2 requests/second, so back off politely.
    """
    events = []
    for attempt in range(4):
        try:
            resp = ct.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
                ],
                StartTime=datetime.now(timezone.utc) - timedelta(days=90),
                EndTime=datetime.now(timezone.utc),
                MaxResults=50,
            )
            events = resp.get("Events", [])
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "ThrottlingException", "TooManyRequestsException"
            ):
                time.sleep(2 ** attempt)
                continue
            raise
    time.sleep(0.6)   # stay under the API's ~2 TPS ceiling

    if not events:
        return {
            "creator": None,
            "creatorType": None,
            "createdVia": None,
            "lastActivity": None,
            "cold": True,
            "eventCount": 0,
        }

    events.sort(key=lambda e: e["EventTime"])
    create_evt = next(
        (e for e in events
         if e["EventName"].startswith(("Create", "Run", "Allocate", "Import"))),
        events[0],
    )
    ident = json.loads(create_evt["CloudTrailEvent"]).get("userIdentity", {})
    principal = (
        ident.get("arn")
        or ident.get("userName")
        or ident.get("principalId")
        or "unknown"
    )
    return {
        "creator": principal,
        "creatorType": ident.get("type"),
        "createdVia": create_evt["EventName"],
        "createdAt": create_evt["EventTime"].isoformat(),
        "lastActivity": events[-1]["EventTime"].isoformat(),
        "cold": False,
        "eventCount": len(events),
    }


def principal_alive(creator: str | None) -> bool:
    """Best-effort check that the creating IAM identity still exists."""
    if not creator:
        return False
    if ":assumed-role/" in creator:
        role = creator.split(":assumed-role/")[1].split("/")[0]
        try:
            iam.get_role(RoleName=role)
            return True
        except ClientError:
            return False
    if ":user/" in creator:
        try:
            iam.get_user(UserName=creator.split(":user/")[-1])
            return True
        except ClientError:
            return False
    return True   # root or a service principal, treat as alive


# --------------------------------------------------------------------------
# pass 3: the Orphan Score (deterministic, explainable, reproducible)
# --------------------------------------------------------------------------

NO_OWNER_TAG = "No owner tag (+25)"
COLD = "Cold attribution: no CloudTrail activity in 90 days (+25)"


def score(resource: dict, attribution: dict) -> tuple[int, list]:
    points, reasons = 0, []
    tag_keys = {k.lower() for k in resource["tags"]}

    if not (tag_keys & OWNER_TAG_KEYS):
        points += 25
        reasons.append(NO_OWNER_TAG)

    if attribution["cold"]:
        points += 25
        reasons.append(COLD)

    if resource["idle"]:
        points += 20
        reasons.append(f"Idle shape: {resource['detail']} (+20)")

    creator = (attribution.get("creator") or "").lower()
    has_stack_tag = any(k.startswith("aws:cloudformation") for k in resource["tags"])
    if not has_stack_tag and not any(h in creator for h in IAC_HINTS):
        points += 15
        reasons.append("No IaC provenance, looks hand-made (+15)")

    if not attribution["cold"] and not principal_alive(attribution.get("creator")):
        points += 15
        reasons.append("Creating IAM identity no longer exists (+15)")

    return min(points, 100), reasons


def verdict(points: int) -> str:
    if points >= 60:
        return "PURGATORY_CANDIDATE"
    if points >= 40:
        return "FLAGGED"
    return "INFO"


# --------------------------------------------------------------------------
# summary and digest
# --------------------------------------------------------------------------

def summarise(findings: list) -> str:
    """Deterministic prose. Same input always produces the same sentence."""
    if not findings:
        return "Nothing needs a decision this week. Clean account."

    ranked = sorted(findings, key=lambda f: -f["orphanScore"])
    top = ", ".join(
        f"{f['resourceId']} (score {f['orphanScore']})" for f in ranked[:3]
    )
    cold = sum(1 for f in findings if f["attribution"]["cold"])
    untagged = sum(1 for f in findings if NO_OWNER_TAG in f["reasons"])
    candidates = sum(
        1 for f in findings if f["verdict"] == "PURGATORY_CANDIDATE"
    )

    parts = [
        f"{len(findings)} resources need a decision this week, "
        f"{candidates} of them scoring 60 or above.",
        f"Highest scoring: {top}.",
    ]
    if cold:
        parts.append(
            f"{cold} have no CloudTrail record at all in the last 90 days, "
            f"which means nobody has created, modified or touched them in that "
            f"window. That silence is the strongest signal here."
        )
    if untagged:
        parts.append(f"{untagged} carry no owner tag.")
    parts.append(
        f"Anything you ignore for {GRACE_DAYS} days that scores 60 or above "
        f"goes to Purgatory, stopped and snapshotted, never deleted."
    )
    return " ".join(parts)


def render_email(summary: str, findings: list, purgatory: list) -> str:
    rows = []
    for f in sorted(findings, key=lambda x: -x["orphanScore"]):
        creator = f["attribution"].get("creator") or "no CloudTrail record in 90 days"
        if f["verdict"] == "INFO":
            actions = "&mdash;"
        else:
            keep = decision_url(BASE_URL, f["resourceId"], "keep")
            purge = decision_url(BASE_URL, f["resourceId"], "purgatory")
            actions = (
                f'<a href="{keep}">Keep</a> &nbsp;|&nbsp; '
                f'<a href="{purge}">Send to Purgatory</a>'
            )
        rows.append(
            f"<tr><td><code>{f['resourceId']}</code><br>"
            f"<small>{f['type']} &middot; {f['detail']}</small></td>"
            f"<td align='center'><b>{f['orphanScore']}</b><br>"
            f"<small>{f['verdict']}</small></td>"
            f"<td><small>{creator}</small></td>"
            f"<td><small>{'<br>'.join(f['reasons'])}</small></td>"
            f"<td>{actions}</td></tr>"
        )

    pending = ""
    if purgatory:
        lines = "".join(
            f"<li><code>{p['resourceId']}</code> releases "
            f"{str(p.get('purgatoryUntil', ''))[:10]} &mdash; "
            f'<a href="{decision_url(BASE_URL, p["resourceId"], "keep")}">'
            f"restore it</a></li>"
            for p in purgatory
        )
        pending = (
            f"<h3>Currently in Purgatory ({len(purgatory)})</h3>"
            f"<p>Stopped and snapshotted, not deleted. Restore any of these "
            f"with one click.</p><ul>{lines}</ul>"
        )

    body_rows = "".join(rows) or (
        '<tr><td colspan="5">Nothing to review. Clean account.</td></tr>'
    )

    return f"""<html><body style="font-family:-apple-system,Segoe UI,sans-serif;
      max-width:820px;color:#16191f">
  <h2>Who Made This? weekly account archaeology</h2>
  <p style="font-size:15px;line-height:1.55">{summary}</p>
  <p style="background:#fff8e1;padding:10px;border-left:3px solid #f0ad4e;
     font-size:13px"><b>This app cannot delete anything.</b> Its IAM roles contain
     no <code>Delete*</code> and no <code>Terminate*</code> permission. Purgatory
     means stopped, snapshotted, and tagged with a 30 day release date.</p>
  <table border="0" cellpadding="8" cellspacing="0" width="100%"
         style="border-collapse:collapse;font-size:13px">
    <tr style="background:#f2f3f3;text-align:left">
      <th>Resource</th><th>Orphan Score</th><th>Created by</th>
      <th>Signals</th><th>Decision</th>
    </tr>
    {body_rows}
  </table>
  {pending}
  <p style="color:#687078;font-size:11px">Attribution from CloudTrail Event
     history, 90 day window, no charge. Scoring is deterministic Python, so the
     same account state always produces the same numbers.</p>
</body></html>"""


# --------------------------------------------------------------------------

def handler(event, context):
    resources = inventory()
    print(f"inventory: {len(resources)} resources")

    findings = []
    for r in resources:
        existing = get_finding(r["resourceId"])
        if existing and existing.get("state") in ("KEEP", "PURGATORY"):
            continue   # already decided, do not nag twice

        attribution = attribute(r["resourceId"])
        points, reasons = score(r, attribution)
        v = verdict(points)

        item = {
            **r,
            "orphanScore": points,
            "reasons": reasons,
            "verdict": v,
            "attribution": attribution,
            "state": "FLAGGED" if v != "INFO" else "INFO",
            "flaggedAt": now_iso(),
            "graceUntil": days_from_now(GRACE_DAYS),
            "updatedAt": now_iso(),
        }
        put_finding(item)
        if v != "INFO":
            findings.append(item)

    purgatory = scan_state("PURGATORY")
    summary = summarise(findings)

    ses.send_email(
        Source=SENDER,
        Destination={"ToAddresses": [RECIPIENT]},
        Message={
            "Subject": {
                "Data": f"Who Made This? {len(findings)} resources need a decision"
            },
            "Body": {"Html": {"Data": render_email(summary, findings, purgatory)}},
        },
    )
    result = {
        "scanned": len(resources),
        "flagged": len(findings),
        "inPurgatory": len(purgatory),
    }
    print(json.dumps(result))
    return result
