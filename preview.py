#!/usr/bin/env python3
"""
Preview only. Read-only. Cannot stop, snapshot, tag, or delete anything.

Run this BEFORE deploying the app, to see the exact list of resources it
would flag and why, using only your local AWS CLI login. It calls nothing
but Describe* and LookupEvents, the same read-only calls a person clicks
through in the AWS console.

Usage:
    python3 preview.py [region]
"""
import sys
import time
import json
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

REGION = sys.argv[1] if len(sys.argv) > 1 else "us-east-1"

ec2 = boto3.client("ec2", region_name=REGION)
ct = boto3.client("cloudtrail", region_name=REGION)
iam = boto3.client("iam", region_name=REGION)

OWNER_TAG_KEYS = {"owner", "createdby", "created-by", "team", "contact"}
IAC_HINTS = ("cloudformation", "terraform", "cdk", "serverless", "pulumi")


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
                    "resourceId": inst["InstanceId"], "type": "ec2:instance",
                    "tags": tags_to_dict(inst.get("Tags")),
                    "idle": inst["State"]["Name"] == "stopped",
                    "detail": f"{inst['InstanceType']} ({inst['State']['Name']})",
                })
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page["Volumes"]:
            found.append({
                "resourceId": vol["VolumeId"], "type": "ec2:volume",
                "tags": tags_to_dict(vol.get("Tags")),
                "idle": vol["State"] == "available",
                "detail": f"{vol['Size']} GiB {vol['VolumeType']} ({vol['State']})",
            })
    for addr in ec2.describe_addresses().get("Addresses", []):
        found.append({
            "resourceId": addr.get("AllocationId", addr["PublicIp"]), "type": "ec2:eip",
            "tags": tags_to_dict(addr.get("Tags")),
            "idle": "AssociationId" not in addr, "detail": addr["PublicIp"],
        })
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        for eni in page["NetworkInterfaces"]:
            if eni.get("RequesterManaged"):
                continue
            found.append({
                "resourceId": eni["NetworkInterfaceId"], "type": "ec2:eni",
                "tags": tags_to_dict(eni.get("TagSet")),
                "idle": eni["Status"] == "available",
                "detail": f"{eni.get('PrivateIpAddress', '')} ({eni['Status']})",
            })
    return found


def attribute(resource_id):
    try:
        resp = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_id}],
            StartTime=datetime.now(timezone.utc) - timedelta(days=90),
            EndTime=datetime.now(timezone.utc), MaxResults=50,
        )
        events = resp.get("Events", [])
    except ClientError as e:
        print(f"  (CloudTrail lookup failed for {resource_id}: {e})")
        events = []
    time.sleep(0.6)
    if not events:
        return {"creator": None, "cold": True}
    events.sort(key=lambda e: e["EventTime"])
    ident = json.loads(events[0]["CloudTrailEvent"]).get("userIdentity", {})
    creator = ident.get("arn") or ident.get("userName") or "unknown"
    return {"creator": creator, "cold": False}


def principal_alive(creator):
    if not creator:
        return False
    if ":assumed-role/" in creator:
        role = creator.split(":assumed-role/")[1].split("/")[0]
        try:
            iam.get_role(RoleName=role)
            return True
        except ClientError:
            return False
    return True


def score(resource, attribution):
    points, reasons = 0, []
    tag_keys = {k.lower() for k in resource["tags"]}
    if not (tag_keys & OWNER_TAG_KEYS):
        points += 25; reasons.append("no owner tag")
    if attribution["cold"]:
        points += 25; reasons.append("no CloudTrail activity in 90 days")
    if resource["idle"]:
        points += 20; reasons.append(f"idle: {resource['detail']}")
    creator = (attribution.get("creator") or "").lower()
    has_stack_tag = any(k.startswith("aws:cloudformation") for k in resource["tags"])
    if not has_stack_tag and not any(h in creator for h in IAC_HINTS):
        points += 15; reasons.append("no IaC provenance")
    if not attribution["cold"] and not principal_alive(attribution.get("creator")):
        points += 15; reasons.append("creator identity no longer exists")
    return min(points, 100), reasons


def verdict(points):
    if points >= 60:
        return "WOULD BE A PURGATORY CANDIDATE"
    if points >= 40:
        return "would be flagged"
    return "informational only, no action"


def main():
    print(f"Region: {REGION}")
    print("This is READ-ONLY. It changes nothing. It only shows what the app")
    print("would put in this week's email if you deployed it.\n")

    resources = inventory()
    if not resources:
        print("No EC2 instances, volumes, Elastic IPs, or loose ENIs found at all.")
        print("There is nothing this app could act on in this account/region.")
        return

    print(f"Found {len(resources)} resource(s) in scope. Checking each one "
          f"against CloudTrail (this can take a few seconds per resource)...\n")

    rows = []
    for r in resources:
        attribution = attribute(r["resourceId"])
        points, reasons = score(r, attribution)
        rows.append((r, attribution, points, reasons))

    rows.sort(key=lambda x: -x[2])

    print(f"{'RESOURCE':<22} {'TYPE':<14} {'SCORE':<6} {'RESULT':<32} REASONS")
    print("-" * 120)
    action_needed = False
    for r, attribution, points, reasons in rows:
        v = verdict(points)
        if points >= 60:
            action_needed = True
        creator = attribution.get("creator") or "unknown / no record in 90 days"
        print(f"{r['resourceId']:<22} {r['type']:<14} {points:<6} {v:<32} "
              f"{', '.join(reasons) or 'none'}")
        print(f"{'':<22} created/last-touched by: {creator}")
    print("-" * 120)

    if action_needed:
        print("\nIMPORTANT: at least one resource above scores 60+ and would show a")
        print("'Send to Purgatory' link in the email. NOTHING happens to it unless")
        print("YOU click that link, or you ignore the email for 7 full days.")
        print("If any of these are things a teammate is actively using, either")
        print("tag them with an Owner tag now, or just don't click Purgatory on them.")
    else:
        print("\nNothing in this account currently scores high enough to be a")
        print("Purgatory candidate. Deploying right now would be low-drama.")


if __name__ == "__main__":
    main()
