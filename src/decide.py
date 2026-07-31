"""
The decision endpoint, exposed as a Lambda Function URL with AuthType NONE.

The signed link *is* the credential: each URL carries the resource id, the
action, an expiry, and an HMAC-SHA256 signature over all three. Tamper with
any of them and you get a 403.

Nothing in this module deletes anything. Purgatory means stop and snapshot.
"""

import os

import boto3

from common import (
    PURGATORY_DAYS,
    days_from_now,
    get_finding,
    now_iso,
    update_state,
    verify,
)

REGION = os.environ["AWS_REGION"]
ec2 = boto3.client("ec2", region_name=REGION)


def page(title: str, body: str, code: int = 200):
    return {
        "statusCode": code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            "<html><body style='font-family:-apple-system,Segoe UI,sans-serif;"
            "max-width:600px;margin:80px auto;color:#16191f'>"
            f"<h2>{title}</h2><p style='line-height:1.6'>{body}</p>"
            "<p style='color:#687078;font-size:12px'>Who Made This?</p>"
            "</body></html>"
        ),
    }


def enter_purgatory(item: dict) -> str:
    """Stop and snapshot. Never delete. Returns what actually happened."""
    rid, rtype = item["resourceId"], item["type"]
    release_after = days_from_now(PURGATORY_DAYS)[:10]
    done = []

    if rtype == "ec2:instance":
        ec2.create_tags(Resources=[rid], Tags=[
            {"Key": "whomadethis:state", "Value": "purgatory"},
            {"Key": "whomadethis:release-after", "Value": release_after},
        ])
        vols = ec2.describe_volumes(Filters=[
            {"Name": "attachment.instance-id", "Values": [rid]}
        ])["Volumes"]
        for v in vols:
            snap = ec2.create_snapshot(
                VolumeId=v["VolumeId"],
                Description=f"whomadethis purgatory snapshot of {rid}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [{"Key": "whomadethis:source", "Value": rid}],
                }],
            )
            done.append(f"snapshot {snap['SnapshotId']} of {v['VolumeId']}")
        ec2.stop_instances(InstanceIds=[rid])
        done.append("instance stopped")

    elif rtype == "ec2:volume":
        snap = ec2.create_snapshot(
            VolumeId=rid,
            Description="whomadethis purgatory snapshot",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [{"Key": "whomadethis:source", "Value": rid}],
            }],
        )
        ec2.create_tags(Resources=[rid], Tags=[
            {"Key": "whomadethis:state", "Value": "purgatory"},
            {"Key": "whomadethis:snapshot", "Value": snap["SnapshotId"]},
            {"Key": "whomadethis:release-after", "Value": release_after},
        ])
        done.append(f"snapshot {snap['SnapshotId']} taken, volume left in place")

    else:
        # Elastic IPs and ENIs: tag only. Releasing an EIP is not reversible,
        # you may not get the same address back, so this app refuses to touch it.
        ec2.create_tags(Resources=[rid], Tags=[
            {"Key": "whomadethis:state", "Value": "purgatory"},
            {"Key": "whomadethis:release-after", "Value": release_after},
        ])
        done.append("tagged for review, not modified (release is irreversible)")

    return "; ".join(done)


def release(item: dict) -> None:
    """Undo Purgatory. Snapshots are deliberately kept."""
    rid = item["resourceId"]
    try:
        ec2.delete_tags(Resources=[rid], Tags=[
            {"Key": "whomadethis:state"},
            {"Key": "whomadethis:release-after"},
        ])
    except Exception as e:
        print(f"tag cleanup on {rid} failed, non-fatal: {e}")
    if item["type"] == "ec2:instance":
        try:
            ec2.start_instances(InstanceIds=[rid])
        except Exception as e:
            print(f"could not restart {rid}: {e}")


def handler(event, context):
    qs = event.get("queryStringParameters") or {}
    rid, action = qs.get("rid"), qs.get("action")
    sig, exp = qs.get("sig"), qs.get("exp")

    if not all([rid, action, sig, exp]):
        return page("Bad request", "Missing parameters.", 400)
    try:
        exp_i = int(exp)
    except (TypeError, ValueError):
        return page("Bad request", "Malformed expiry.", 400)

    if not verify(rid, action, exp_i, sig):
        return page(
            "Link expired or invalid",
            "This decision link is no longer valid. Wait for the next weekly "
            "digest, or check the resource in the console.",
            403,
        )

    item = get_finding(rid)
    if not item:
        return page("Not found", f"No record of <code>{rid}</code>.", 404)

    if action == "keep":
        if item.get("state") == "PURGATORY":
            release(item)
            update_state(rid, "KEEP", {"decidedAt": now_iso()})
            return page(
                "Restored",
                f"<code>{rid}</code> is out of Purgatory and back to its "
                f"previous state. The recovery snapshot is kept. It will not be "
                f"flagged again.",
            )
        update_state(rid, "KEEP", {"decidedAt": now_iso()})
        return page(
            "Kept",
            f"<code>{rid}</code> is marked as intentional and will be skipped "
            f"in future scans. Consider adding an <code>Owner</code> tag so the "
            f"next person does not have to ask.",
        )

    if action == "purgatory":
        if item.get("state") == "PURGATORY":
            return page("Already in Purgatory",
                        f"<code>{rid}</code> is already there.")
        detail = enter_purgatory(item)
        update_state(rid, "PURGATORY", {
            "purgatoryUntil": days_from_now(PURGATORY_DAYS),
            "purgatoryActions": detail,
        })
        return page(
            "Sent to Purgatory",
            f"<code>{rid}</code>: {detail}.<br><br>It stays recoverable for "
            f"{PURGATORY_DAYS} days and appears in every digest until then. "
            f"Nothing was deleted.",
        )

    return page("Unknown action", f"Cannot do <code>{action}</code>.", 400)
