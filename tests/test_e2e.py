"""
End-to-end logic test for Who Made This?

Every boto3 client is stubbed, so this needs no AWS account and no credentials.
Covers: full weekly scan, exact Orphan Score assertions, idempotence, HMAC
signature tampering (bad sig / expired / swapped resource / swapped action),
the Purgatory round trip including snapshot-before-stop ordering, and the
enforcer ageing out both a grace window and a Purgatory term.

Run from the repo root:  python3 tests/test_e2e.py
"""
import os, sys, json, base64, time
from datetime import datetime, timedelta, timezone

os.environ.update(TABLE_NAME="t", HMAC_PARAM="/whomadethis/hmac-key",
                  AWS_REGION="us-east-1", SENDER_EMAIL="a@b.c",
                  RECIPIENT_EMAIL="a@b.c", DECISION_BASE_URL="https://x.lambda-url/",
                  GRACE_DAYS="7", PURGATORY_DAYS="30")

NOW = datetime.now(timezone.utc)
TABLE = {}
SENT = []
EC2_CALLS = []

class Paginator:
    def __init__(self, pages): self.pages = pages
    def paginate(self, **kw): return self.pages

class FakeEC2:
    def get_paginator(self, op):
        if op == "describe_instances":
            return Paginator([{"Reservations": [{"Instances": [
                {"InstanceId": "i-live", "State": {"Name": "running"},
                 "InstanceType": "t3.small", "LaunchTime": NOW - timedelta(days=5),
                 "Tags": [{"Key": "Owner", "Value": "rohan"},
                          {"Key": "aws:cloudformation:stack-name", "Value": "app"}]},
                {"InstanceId": "i-ghost", "State": {"Name": "stopped"},
                 "InstanceType": "t3.micro", "LaunchTime": NOW - timedelta(days=200),
                 "Tags": []},
                {"InstanceId": "i-dead", "State": {"Name": "terminated"},
                 "InstanceType": "t3.nano", "LaunchTime": NOW, "Tags": []},
            ]}]}])
        if op == "describe_volumes":
            return Paginator([{"Volumes": [
                {"VolumeId": "vol-orphan", "State": "available", "Size": 100,
                 "VolumeType": "gp3", "CreateTime": NOW - timedelta(days=120),
                 "Tags": []}]}])
        if op == "describe_network_interfaces":
            return Paginator([{"NetworkInterfaces": [
                {"NetworkInterfaceId": "eni-mgd", "Status": "in-use",
                 "RequesterManaged": True, "TagSet": []},
                {"NetworkInterfaceId": "eni-loose", "Status": "available",
                 "PrivateIpAddress": "10.0.0.9", "TagSet": []}]}])
        raise AssertionError(op)
    def describe_addresses(self):
        return {"Addresses": [{"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4",
                               "Tags": []}]}
    def describe_volumes(self, **kw):
        EC2_CALLS.append(("describe_volumes", kw))
        return {"Volumes": [{"VolumeId": "vol-attached"}]}
    def create_tags(self, **kw): EC2_CALLS.append(("create_tags", kw)); return {}
    def delete_tags(self, **kw): EC2_CALLS.append(("delete_tags", kw)); return {}
    def stop_instances(self, **kw): EC2_CALLS.append(("stop_instances", kw)); return {}
    def start_instances(self, **kw): EC2_CALLS.append(("start_instances", kw)); return {}
    def create_snapshot(self, **kw):
        EC2_CALLS.append(("create_snapshot", kw)); return {"SnapshotId": "snap-abc"}

class FakeCT:
    def lookup_events(self, **kw):
        rid = kw["LookupAttributes"][0]["AttributeValue"]
        if rid in ("vol-orphan", "eni-loose", "eipalloc-1"):
            return {"Events": []}                        # cold attribution
        who = ("arn:aws:sts::1:assumed-role/DeletedRole/x" if rid == "i-ghost"
               else "arn:aws:sts::1:assumed-role/cfn-exec/y")
        return {"Events": [{"EventName": "RunInstances", "EventTime": NOW - timedelta(days=60),
                            "CloudTrailEvent": json.dumps(
                                {"userIdentity": {"type": "AssumedRole", "arn": who}})}]}

class Denied(Exception):
    def __init__(self): self.response = {"Error": {"Code": "NoSuchEntity"}}
from botocore.exceptions import ClientError
class FakeIAM:
    def get_role(self, RoleName):
        if RoleName == "DeletedRole":
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetRole")
        return {}
    def get_user(self, **kw): return {}

class FakeSES:
    def send_email(self, **kw): SENT.append(kw); return {"MessageId": "m1"}

class FakeSSM:
    def get_parameter(self, **kw):
        return {"Parameter": {"Value": "test-signing-key-do-not-use"}}

class FakeTable:
    def put_item(self, Item): TABLE[Item["resourceId"]] = json.loads(json.dumps(Item, default=str))
    def get_item(self, Key):
        it = TABLE.get(Key["resourceId"])
        return {"Item": it} if it else {}
    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames,
                    ExpressionAttributeValues, **kw):
        it = TABLE.setdefault(Key["resourceId"], {"resourceId": Key["resourceId"]})
        rev = {v: k for k, v in ExpressionAttributeNames.items()}
        for part in UpdateExpression.replace("SET ", "").split(","):
            lhs, rhs = [p.strip() for p in part.split("=")]
            name = ExpressionAttributeNames.get(lhs, lhs)
            it[name] = ExpressionAttributeValues[rhs]
    def scan(self, **kw):
        want = kw["ExpressionAttributeValues"][":s"]
        return {"Items": [v for v in TABLE.values() if v.get("state") == want]}

class FakeDDB:
    def Table(self, n): return FakeTable()

import boto3
_clients = {"ec2": FakeEC2(), "cloudtrail": FakeCT(), "iam": FakeIAM(),
            "ses": FakeSES(), "ssm": FakeSSM()}
boto3.client = lambda name, **kw: _clients[name]
boto3.resource = lambda name, **kw: FakeDDB()

sys.path.insert(0, "src")
import scanner, decide, enforcer, common

print("=" * 66)
print("TEST 1: full weekly scan")
res = scanner.handler({}, None)
print("  result:", res)
assert res["scanned"] == 5, f"expected 5 (terminated + requester-managed skipped), got {res['scanned']}"
assert res["flagged"] == 4, f"expected 4 flagged, got {res['flagged']}"
assert "i-live" in TABLE and TABLE["i-live"]["state"] == "INFO", "tagged IaC instance must be INFO"
print("  i-live      score", TABLE["i-live"]["orphanScore"], TABLE["i-live"]["verdict"])
print("  i-ghost     score", TABLE["i-ghost"]["orphanScore"], TABLE["i-ghost"]["verdict"])
print("  vol-orphan  score", TABLE["vol-orphan"]["orphanScore"], TABLE["vol-orphan"]["verdict"])
assert TABLE["i-ghost"]["orphanScore"] == 75, TABLE["i-ghost"]["orphanScore"]
assert TABLE["vol-orphan"]["orphanScore"] == 85, TABLE["vol-orphan"]["orphanScore"]
assert TABLE["i-live"]["orphanScore"] == 0
assert len(SENT) == 1
html = SENT[0]["Message"]["Body"]["Html"]["Data"]
assert "cannot delete anything" in html
assert "vol-orphan" in html and "Send to Purgatory" in html
print("  email sent, subject:", SENT[0]["Message"]["Subject"]["Data"])
print("  summary:", TABLE and scanner.summarise([TABLE['vol-orphan'], TABLE['i-ghost']])[:120], "...")

print("=" * 66)
print("TEST 2: idempotence, second scan must not re-nag decided items")
common.update_state("vol-orphan", "KEEP")
SENT.clear()
res2 = scanner.handler({}, None)
print("  result:", res2)
assert res2["flagged"] == 3, res2

print("=" * 66)
print("TEST 3: signature verification")
url = common.decision_url("https://x.lambda-url/", "vol-orphan", "purgatory")
from urllib.parse import urlparse, parse_qs
q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
assert common.verify(q["rid"], q["action"], int(q["exp"]), q["sig"]) is True
print("  valid signature      -> accepted")
assert common.verify(q["rid"], q["action"], int(q["exp"]), q["sig"][:-1] + "Z") is False
print("  tampered signature   -> rejected")
assert common.verify(q["rid"], "keep", int(q["exp"]), q["sig"]) is False
print("  swapped action       -> rejected")
assert common.verify("i-ghost", q["action"], int(q["exp"]), q["sig"]) is False
print("  swapped resource     -> rejected")
assert common.verify(q["rid"], q["action"], int(time.time()) - 10,
                     common.sign(q["rid"], q["action"], int(time.time()) - 10)) is False
print("  expired but signed   -> rejected")

print("=" * 66)
print("TEST 4: decide endpoint, tampered link returns 403")
bad = {"queryStringParameters": {**q, "sig": q["sig"][:-1] + "Z"}}
r = decide.handler(bad, None)
print("  status", r["statusCode"], "|", "Link expired or invalid" in r["body"])
assert r["statusCode"] == 403

print("=" * 66)
print("TEST 5: Purgatory round trip on the ghost instance")
url = common.decision_url("https://x.lambda-url/", "i-ghost", "purgatory")
q2 = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
EC2_CALLS.clear()
r = decide.handler({"queryStringParameters": q2}, None)
print("  status", r["statusCode"])
assert r["statusCode"] == 200 and "Sent to Purgatory" in r["body"]
ops = [c[0] for c in EC2_CALLS]
print("  ec2 ops:", ops)
assert "create_snapshot" in ops, "must snapshot BEFORE stopping"
assert "stop_instances" in ops
assert ops.index("create_snapshot") < ops.index("stop_instances")
assert TABLE["i-ghost"]["state"] == "PURGATORY"
tags = [t["Key"] for c in EC2_CALLS if c[0] == "create_tags" for t in c[1]["Tags"]]
assert "whomadethis:release-after" in tags
print("  tags applied:", tags)

print("  now restoring via Keep...")
url = common.decision_url("https://x.lambda-url/", "i-ghost", "keep")
q3 = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
EC2_CALLS.clear()
r = decide.handler({"queryStringParameters": q3}, None)
assert r["statusCode"] == 200 and "Restored" in r["body"], r["body"]
assert "start_instances" in [c[0] for c in EC2_CALLS]
assert TABLE["i-ghost"]["state"] == "KEEP"
print("  restored, instance restarted, state =", TABLE["i-ghost"]["state"])

print("=" * 66)
print("TEST 6: enforcer ages out an expired grace window")
TABLE["eni-loose"]["graceUntil"] = (NOW - timedelta(days=1)).isoformat()
TABLE["eni-loose"]["state"] = "FLAGGED"
TABLE["eni-loose"]["verdict"] = "PURGATORY_CANDIDATE"
SENT.clear()
r = enforcer.handler({}, None)
print("  result:", r)
assert r["movedToPurgatory"] == 1, r
assert TABLE["eni-loose"]["state"] == "PURGATORY"
assert "no response in the grace window" in SENT[0]["Message"]["Body"]["Html"]["Data"]
print("  eni-loose ->", TABLE["eni-loose"]["state"], "| notification sent")

print("  ageing Purgatory out to RELEASABLE...")
TABLE["eni-loose"]["purgatoryUntil"] = (NOW - timedelta(days=1)).isoformat()
SENT.clear()
r = enforcer.handler({}, None)
assert r["releasable"] == 1, r
assert TABLE["eni-loose"]["state"] == "RELEASABLE"
body = SENT[0]["Message"]["Body"]["Html"]["Data"]
assert "cannot delete them" in body
print("  eni-loose ->", TABLE["eni-loose"]["state"], "| human-delete report sent")

print("=" * 66)
print("ALL TESTS PASSED")
