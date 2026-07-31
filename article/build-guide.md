# Who Made This? Weekend Build Guide

**Challenge:** AWS Builder Center Weekend Challenge, "Turn One Annoying Task Into an App"
**Window:** 31 July 2026 00:00 PT to 3 August 2026 13:00 PT
**Target:** one of the first 73 qualifying submissions

---

## 0. What we are building and why this version differs from the pitch

**The annoying task.** Every quarter someone has to go through the AWS account and work out which resources are still needed. Nobody remembers what they created. Tags are missing or wrong. The person who spun it up may have left. So the resources stay, because deleting something you cannot explain is worse than paying for it.

**Who Made This?** runs weekly, finds resources that look abandoned, works out *who created them and when* from CloudTrail, scores how likely each one is to be dead, and emails a digest with two buttons per resource: **Keep** or **Send to Purgatory**.

**Purgatory is the mechanism.** It is a reversible middle state. Nothing is ever deleted by this app. A resource in Purgatory is stopped, snapshotted and tagged with a release date 30 days out. If someone needs it back, one click restores it. If nobody claims it in 30 days, the app reports it as safe to delete and a human does the deleting. The IAM role deliberately has no `Delete*` or `Terminate*` permission at all, so the app physically cannot destroy anything.

### One change from the original pitch, and it matters

The pitch said CloudTrail Lake. Two problems:

1. **Cost.** CloudTrail Lake ingestion is $0.75/GB on one-year extendable retention pricing, plus $0.005/GB scanned per query. It has no free tier. Small for a dev account, but not zero, and the challenge asks for Free Tier services.
2. **It has no history.** An event data store only captures events from the moment you create it. Creating one on Friday gives you zero events to do archaeology on. The whole idea depends on looking backwards.

**CloudTrail Event history** solves both. It is on by default in every account, holds the last 90 days of management events, is queryable via the `LookupEvents` API, and AWS states there is no charge for viewing it. So we get 90 days of retroactive attribution for free, working the moment we deploy.

Bonus: the idea bank shows at least three other builders using CloudTrail Lake for attribution. `LookupEvents` is the less crowded choice, and the 90-day boundary turns into a feature. If a resource was created and has had no API activity in 90 days, that silence is itself the strongest orphan signal in the app. We call it **cold attribution**, and it scores higher than a known creator.

The guide keeps a note in Phase 3 on how to swap in CloudTrail Lake later if you want SQL and longer retention.

---

## 1. Cost check before you touch anything

| Service | Our usage | Cost |
|---|---|---|
| CloudTrail Event history (`LookupEvents`) | a few hundred calls/week | No charge for viewing 90-day management event history |
| Lambda | ~40 invocations/month, <10s each | Free tier: 1M requests + 400,000 GB-seconds/month, always free |
| DynamoDB on-demand | a few hundred items | Free tier: 25 GB storage always free; our reads/writes are pennies at most |
| EventBridge Scheduler | 4 to 8 invocations/month | Free tier: 14,000,000 invocations/month, permanent, not 12-month limited |
| Bedrock Nova Lite | ~4,000 tokens/week | $0.00006 per 1K input, $0.00024 per 1K output. Roughly $0.0001/week |
| SES | 4 to 8 emails/month | $0.10 per 1,000 messages. The old 3,000/month SES free tier closed to new customers on 21 July 2026, so budget cents, or use the $200 Free Tier credits |
| Lambda Function URL | the decision endpoint | No extra charge, no API Gateway needed |
| SSM Parameter Store (standard) | one SecureString for the HMAC key | Standard parameters are free |

**Realistic total for the weekend: well under $1.** Deliberately avoided: CloudTrail Lake, Secrets Manager ($0.40/secret/month), API Gateway, NAT Gateway, anything in a VPC.

> Set a billing alarm before you start. Five minutes, saves a bad Monday.

---

## 2. Prerequisites

```bash
# Verify identity and region
aws sts get-caller-identity
export AWS_REGION=us-east-1        # pick a region where Nova is available
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# SAM CLI (one deploy command beats twenty)
sam --version    # if missing: pip install aws-sam-cli

# Confirm the Nova model ID available to you. Do not guess this.
aws bedrock list-foundation-models --region $AWS_REGION \
  --query "modelSummaries[?contains(modelId,'nova')].[modelId,modelName]" --output table
```

Two things to sort in the console now, because both have a lag:

1. **Bedrock model access.** Bedrock console, Model access, request access to Amazon Nova Lite. Usually instant for Amazon's own models, but check.
2. **SES identity verification.** SES console, Verified identities, add your email address, click the link in the confirmation mail. A brand-new SES account is in the sandbox, which means you can only send *to* verified addresses. That is fine, you are emailing yourself. Verify both the sender and the recipient address even if they are the same.

Note the model ID you found above. If plain `amazon.nova-lite-v1:0` is not invokable, you may need the cross-region inference profile form `us.amazon.nova-lite-v1:0`. Test it before wiring it into Lambda:

```bash
aws bedrock-runtime converse \
  --model-id amazon.nova-lite-v1:0 \
  --messages '[{"role":"user","content":[{"text":"Say OK"}]}]' \
  --region $AWS_REGION
```

---

## 3. Project layout

```
who-made-this/
├── template.yaml
├── src/
│   ├── scanner.py       # inventory + attribution + Orphan Score + digest
│   ├── decide.py        # signed-link decision endpoint
│   ├── enforcer.py      # applies Purgatory, reports expiries
│   └── common.py        # shared helpers: signing, DDB, tags
└── README.md
```

```bash
mkdir -p who-made-this/src && cd who-made-this
```

---

## 4. The Orphan Score

A named, explainable scoring mechanism, out of 100. Every point is traceable to a signal, and the email shows the breakdown. This matters: reviewers and teammates will not trust a black-box number attached to "should we kill this".

| Signal | Points | Why |
|---|---|---|
| No `Owner`, `owner` or `CreatedBy` tag | 25 | Nobody claimed it |
| Cold attribution: no CloudTrail event in 90 days | 25 | Not created, modified or touched recently |
| Idle shape: stopped instance, unattached volume, unassociated EIP | 20 | Costing money, doing nothing |
| No IaC provenance: no `aws:cloudformation:stack-name` tag and not created by a role with `cfn`/`terraform`/`cdk` in the principal | 15 | One-off manual creation, most likely to be forgotten |
| Creator principal is a deleted or inactive IAM identity | 15 | Owner is gone |

- **Score below 40** → mentioned in the digest as informational only.
- **40 to 59** → flagged, asks for a Keep confirmation.
- **60 and above** → Purgatory candidate. Ignoring the email for 7 days sends it to Purgatory.

Resource classes scanned in v1, all cheap read-only API calls: EC2 instances, EBS volumes, Elastic IPs, and unattached ENIs. Deliberately narrow. A tool that does four resource types correctly beats one that half-covers thirty.

---

## 5. `src/common.py`

```python
import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE_NAME = os.environ["TABLE_NAME"]
HMAC_PARAM = os.environ["HMAC_PARAM"]

PURGATORY_DAYS = int(os.environ.get("PURGATORY_DAYS", "30"))
GRACE_DAYS = int(os.environ.get("GRACE_DAYS", "7"))

_ssm = boto3.client("ssm", region_name=REGION)
_ddb = boto3.resource("dynamodb", region_name=REGION)
_table = _ddb.Table(TABLE_NAME)

_secret_cache = None


def signing_key() -> bytes:
    """Fetch the HMAC key from SSM Parameter Store, cached for the container's life."""
    global _secret_cache
    if _secret_cache is None:
        resp = _ssm.get_parameter(Name=HMAC_PARAM, WithDecryption=True)
        _secret_cache = resp["Parameter"]["Value"].encode()
    return _secret_cache


def sign(resource_id: str, action: str, expires_at: int) -> str:
    msg = f"{resource_id}|{action}|{expires_at}".encode()
    digest = hmac.new(signing_key(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def verify(resource_id: str, action: str, expires_at: int, token: str) -> bool:
    if expires_at < int(time.time()):
        return False
    return hmac.compare_digest(sign(resource_id, action, expires_at), token)


def decision_url(base_url: str, resource_id: str, action: str) -> str:
    expires_at = int(time.time()) + GRACE_DAYS * 86400
    token = sign(resource_id, action, expires_at)
    return (
        f"{base_url.rstrip('/')}/?rid={resource_id}&action={action}"
        f"&exp={expires_at}&sig={token}"
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def days_from_now(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def put_finding(item: dict) -> None:
    _table.put_item(Item=item)


def get_finding(resource_id: str):
    return _table.get_item(Key={"resourceId": resource_id}).get("Item")


def update_state(resource_id: str, state: str, extra: dict | None = None) -> None:
    expr = "SET #s = :s, updatedAt = :u"
    names = {"#s": "state"}
    values = {":s": state, ":u": now_iso()}
    for i, (k, v) in enumerate((extra or {}).items()):
        expr += f", #k{i} = :v{i}"
        names[f"#k{i}"] = k
        values[f":v{i}"] = v
    _table.update_item(
        Key={"resourceId": resource_id},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def scan_state(state: str) -> list:
    """Small table, a filtered scan is honest and cheap here."""
    items, kwargs = [], {
        "FilterExpression": "#s = :s",
        "ExpressionAttributeNames": {"#s": "state"},
        "ExpressionAttributeValues": {":s": state},
    }
    while True:
        resp = _table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
```

---

## 6. `src/scanner.py`

The heart of it. Three passes: inventory, attribution, score. Then narrate and email.

```python
import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from common import (
    GRACE_DAYS, days_from_now, decision_url, get_finding,
    now_iso, put_finding, scan_state,
)

REGION = os.environ["AWS_REGION"]
MODEL_ID = os.environ["MODEL_ID"]
SENDER = os.environ["SENDER_EMAIL"]
RECIPIENT = os.environ["RECIPIENT_EMAIL"]
BASE_URL = os.environ["DECISION_BASE_URL"]

ec2 = boto3.client("ec2", region_name=REGION)
ct = boto3.client("cloudtrail", region_name=REGION)
iam = boto3.client("iam", region_name=REGION)
brt = boto3.client("bedrock-runtime", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)

OWNER_TAG_KEYS = {"owner", "createdby", "created-by", "team", "contact"}
IAC_HINTS = ("cloudformation", "terraform", "cdk", "serverless", "pulumi")


# ---------- pass 1: inventory ----------

def tags_to_dict(tags):
    return {t["Key"]: t["Value"] for t in (tags or [])}


def inventory():
    """Read-only sweep of four resource classes. No mutations here."""
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
                "idle": vol["State"] == "available",   # available == unattached
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


# ---------- pass 2: attribution ----------

def attribute(resource_id: str) -> dict:
    """
    Ask CloudTrail Event history who touched this resource in the last 90 days.
    LookupEvents is throttled around 2 requests/second, so we back off politely.
    Returns creator, last activity, and whether attribution is 'cold'.
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
            if e.response["Error"]["Code"] in ("ThrottlingException",
                                               "TooManyRequestsException"):
                time.sleep(2 ** attempt)
                continue
            raise
    time.sleep(0.6)   # stay under the API's 2 TPS ceiling

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
        (e for e in events if e["EventName"].startswith(
            ("Create", "Run", "Allocate", "Import"))),
        events[0],
    )
    raw = json.loads(create_evt["CloudTrailEvent"])
    ident = raw.get("userIdentity", {})
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
        user = creator.split(":user/")[-1]
        try:
            iam.get_user(UserName=user)
            return True
        except ClientError:
            return False
    return True   # root or a service principal, treat as alive


# ---------- pass 3: the Orphan Score ----------

def score(resource: dict, attribution: dict) -> tuple[int, list]:
    points, reasons = 0, []
    tag_keys = {k.lower() for k in resource["tags"]}

    if not (tag_keys & OWNER_TAG_KEYS):
        points += 25
        reasons.append("No owner tag (+25)")

    if attribution["cold"]:
        points += 25
        reasons.append("Cold attribution: no CloudTrail activity in 90 days (+25)")

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


# ---------- narration ----------

def narrate(findings: list) -> str:
    """
    Bedrock writes the human summary. Note what it is NOT doing:
    it does not decide anything and it never touches an AWS API.
    Scoring is deterministic Python. The model only explains.
    """
    payload = [
        {
            "id": f["resourceId"],
            "type": f["type"],
            "score": f["orphanScore"],
            "creator": f["attribution"].get("creator") or "unattributable",
            "reasons": f["reasons"],
        }
        for f in findings[:25]
    ]
    prompt = (
        "You are writing the opening paragraph of a weekly AWS cleanup email for "
        "the engineer who owns this account. Below is JSON of resources that look "
        "abandoned, each with an Orphan Score out of 100 and the signals behind it.\n\n"
        "Write 4 to 6 sentences of plain English. Say how many resources need a "
        "decision and which two or three deserve attention first, naming them. "
        "Where a creator is known, say who. Where attribution is cold, say plainly "
        "that CloudTrail has no record in 90 days and that silence is the signal. "
        "Do not invent resources, costs or dates that are not in the JSON. Do not "
        "recommend deletion; this system only stops and snapshots. No preamble, no "
        "bullet points, no headings.\n\n"
        f"JSON:\n{json.dumps(payload, indent=2)}"
    )
    try:
        resp = brt.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 500, "temperature": 0.2},
        )
        return resp["output"]["message"]["content"][0]["text"].strip()
    except Exception as e:
        print(f"Bedrock narration failed, falling back to plain text: {e}")
        return (
            f"{len(findings)} resources need a decision this week. "
            "Details in the table below."
        )


# ---------- digest ----------

def render_email(summary: str, findings: list, purgatory: list) -> str:
    rows = []
    for f in sorted(findings, key=lambda x: -x["orphanScore"]):
        keep = decision_url(BASE_URL, f["resourceId"], "keep")
        purge = decision_url(BASE_URL, f["resourceId"], "purgatory")
        creator = f["attribution"].get("creator") or "no CloudTrail record in 90 days"
        actions = (
            f'<a href="{keep}">Keep</a> &nbsp;|&nbsp; '
            f'<a href="{purge}">Send to Purgatory</a>'
            if f["verdict"] != "INFO" else "&mdash;"
        )
        rows.append(
            f"<tr><td><code>{f['resourceId']}</code><br><small>{f['type']} &middot; "
            f"{f['detail']}</small></td>"
            f"<td align='center'><b>{f['orphanScore']}</b><br><small>{f['verdict']}</small></td>"
            f"<td><small>{creator}</small></td>"
            f"<td><small>{'<br>'.join(f['reasons'])}</small></td>"
            f"<td>{actions}</td></tr>"
        )

    pending = ""
    if purgatory:
        lines = "".join(
            f"<li><code>{p['resourceId']}</code> releases "
            f"{p.get('purgatoryUntil', '')[:10]} "
            f'&mdash; <a href="{decision_url(BASE_URL, p["resourceId"], "keep")}">'
            f"restore it</a></li>"
            for p in purgatory
        )
        pending = (
            f"<h3>Currently in Purgatory ({len(purgatory)})</h3>"
            f"<p>Stopped and snapshotted, not deleted. Restore any of these with one "
            f"click.</p><ul>{lines}</ul>"
        )

    return f"""<html><body style="font-family:-apple-system,Segoe UI,sans-serif;
      max-width:820px;color:#16191f">
  <h2>Who Made This? &mdash; weekly account archaeology</h2>
  <p style="font-size:15px;line-height:1.55">{summary}</p>
  <p style="background:#fff8e1;padding:10px;border-left:3px solid #f0ad4e;
     font-size:13px">Anything you ignore for {GRACE_DAYS} days and that scores 60 or
     above goes to <b>Purgatory</b>: stopped, snapshotted, tagged with a 30 day release
     date. Nothing is deleted. This app has no delete permission.</p>
  <table border="0" cellpadding="8" cellspacing="0" width="100%"
         style="border-collapse:collapse;font-size:13px">
    <tr style="background:#f2f3f3;text-align:left">
      <th>Resource</th><th>Orphan Score</th><th>Created by</th>
      <th>Signals</th><th>Decision</th>
    </tr>
    {''.join(rows) or '<tr><td colspan="5">Nothing to review. Clean account.</td></tr>'}
  </table>
  {pending}
  <p style="color:#687078;font-size:11px">Attribution from CloudTrail Event history,
     90 day window. Scoring is deterministic; Amazon Nova Lite wrote the summary
     paragraph only.</p>
</body></html>"""


# ---------- entrypoint ----------

def handler(event, context):
    resources = inventory()
    print(f"inventory: {len(resources)} resources")

    findings = []
    for r in resources:
        existing = get_finding(r["resourceId"])
        if existing and existing.get("state") in ("KEEP", "PURGATORY"):
            continue   # already decided, do not re-nag

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
    summary = narrate(findings) if findings else (
        "Nothing needs a decision this week."
    )

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
    return {"scanned": len(resources), "flagged": len(findings),
            "inPurgatory": len(purgatory)}
```

### If you later want CloudTrail Lake instead

Swap `attribute()` for a `cloudtrail.start_query` against an event data store:

```sql
SELECT userIdentity.arn, eventName, eventTime
FROM <event-data-store-id>
WHERE element_at(requestParameters, 'resourceId') = 'i-0123'
   OR eventID IN (SELECT eventID FROM <eds> WHERE ...)
ORDER BY eventTime
```

You gain SQL and up to seven-year retention. You lose the free tier and you only see events from the day you created the store. Not worth it this weekend.

---

## 7. `src/decide.py`, the signed-link endpoint

A Lambda Function URL with `AuthType: NONE`, protected by an HMAC signature and an expiry. No API Gateway, no login, no cost. The link in the email is the credential.

```python
import os
from urllib.parse import parse_qs

import boto3

from common import (
    PURGATORY_DAYS, days_from_now, get_finding, update_state, verify,
)

REGION = os.environ["AWS_REGION"]
ec2 = boto3.client("ec2", region_name=REGION)


def page(title: str, body: str, code: int = 200):
    return {
        "statusCode": code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": (
            f"<html><body style='font-family:-apple-system,sans-serif;"
            f"max-width:600px;margin:80px auto;color:#16191f'>"
            f"<h2>{title}</h2><p style='line-height:1.6'>{body}</p>"
            f"<p style='color:#687078;font-size:12px'>Who Made This?</p>"
            f"</body></html>"
        ),
    }


def enter_purgatory(item: dict) -> str:
    """Stop and snapshot. Never delete. Returns what actually happened."""
    rid, rtype = item["resourceId"], item["type"]
    done = []

    if rtype == "ec2:instance":
        ec2.create_tags(Resources=[rid], Tags=[
            {"Key": "whomadethis:state", "Value": "purgatory"},
            {"Key": "whomadethis:release-after",
             "Value": days_from_now(PURGATORY_DAYS)[:10]},
        ])
        ec2.stop_instances(InstanceIds=[rid])
        done.append("instance stopped")

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
            {"Key": "whomadethis:release-after",
             "Value": days_from_now(PURGATORY_DAYS)[:10]},
        ])
        done.append(f"snapshot {snap['SnapshotId']} taken, volume left in place")

    else:   # eip, eni: tag only, releasing them is not reversible
        ec2.create_tags(Resources=[rid], Tags=[
            {"Key": "whomadethis:state", "Value": "purgatory"},
            {"Key": "whomadethis:release-after",
             "Value": days_from_now(PURGATORY_DAYS)[:10]},
        ])
        done.append("tagged for review, not modified (release is irreversible)")

    return "; ".join(done)


def release(item: dict) -> None:
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
    except ValueError:
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
        was = item.get("state")
        if was == "PURGATORY":
            release(item)
            update_state(rid, "KEEP", {"decidedAt": days_from_now(0)})
            return page(
                "Restored",
                f"<code>{rid}</code> is out of Purgatory and back to its previous "
                f"state. Any snapshot taken is kept. It will not be flagged again.",
            )
        update_state(rid, "KEEP", {"decidedAt": days_from_now(0)})
        return page(
            "Kept",
            f"<code>{rid}</code> is marked as intentional and will be skipped in "
            f"future scans. Consider adding an <code>Owner</code> tag so the next "
            f"person does not have to ask.",
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
```

---

## 8. `src/enforcer.py`, grace expiry and release reporting

Runs daily. Two jobs, and neither one deletes anything.

```python
import os
from datetime import datetime, timezone

import boto3

from common import days_from_now, scan_state, update_state
from decide import enter_purgatory

REGION = os.environ["AWS_REGION"]
SENDER = os.environ["SENDER_EMAIL"]
RECIPIENT = os.environ["RECIPIENT_EMAIL"]
ses = boto3.client("ses", region_name=REGION)


def expired(ts: str | None) -> bool:
    if not ts:
        return False
    return datetime.fromisoformat(ts) < datetime.now(timezone.utc)


def handler(event, context):
    moved, releasable = [], []

    # Job 1: ignoring the email for the grace period is a decision.
    for item in scan_state("FLAGGED"):
        if item.get("verdict") != "PURGATORY_CANDIDATE":
            continue
        if not expired(item.get("graceUntil")):
            continue
        detail = enter_purgatory(item)
        update_state(item["resourceId"], "PURGATORY", {
            "purgatoryUntil": days_from_now(30),
            "purgatoryActions": detail,
            "purgatoryReason": "grace period expired with no response",
        })
        moved.append(f"{item['resourceId']}: {detail}")

    # Job 2: report what a human could now delete. Do not delete it.
    for item in scan_state("PURGATORY"):
        if expired(item.get("purgatoryUntil")):
            update_state(item["resourceId"], "RELEASABLE")
            releasable.append(item["resourceId"])

    if moved or releasable:
        body = ""
        if moved:
            body += ("<h3>Moved to Purgatory (no response in the grace window)</h3>"
                     "<ul>" + "".join(f"<li>{m}</li>" for m in moved) + "</ul>")
        if releasable:
            body += (
                "<h3>Purgatory complete, safe to delete by hand</h3>"
                "<p>These sat stopped for 30 days and nobody claimed them. "
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

    return {"movedToPurgatory": len(moved), "releasable": len(releasable)}
```

---

## 9. `template.yaml`

Note the IAM policies. There is no `ec2:TerminateInstances`, no `ec2:DeleteVolume`, no `ec2:ReleaseAddress`, no `Delete*` anywhere. Say this out loud in the article, it is the most defensible design decision in the build.

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: Who Made This? Orphan AWS resource archaeologist with a Purgatory state.

Parameters:
  SenderEmail:
    Type: String
    Description: SES-verified sender address
  RecipientEmail:
    Type: String
    Description: SES-verified recipient address
  ModelId:
    Type: String
    Default: amazon.nova-lite-v1:0
  GraceDays:
    Type: Number
    Default: 7
  PurgatoryDays:
    Type: Number
    Default: 30
  HmacParamName:
    Type: String
    Default: /whomadethis/hmac-key
    Description: SSM SecureString parameter holding the link-signing key

Globals:
  Function:
    Runtime: python3.12
    Timeout: 300
    MemorySize: 512
    Architectures: [arm64]
    Environment:
      Variables:
        TABLE_NAME: !Ref FindingsTable
        HMAC_PARAM: !Ref HmacParamName
        SENDER_EMAIL: !Ref SenderEmail
        RECIPIENT_EMAIL: !Ref RecipientEmail
        GRACE_DAYS: !Ref GraceDays
        PURGATORY_DAYS: !Ref PurgatoryDays

Resources:

  FindingsTable:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: resourceId
          AttributeType: S
      KeySchema:
        - AttributeName: resourceId
          KeyType: HASH
      PointInTimeRecoverySpecification:
        PointInTimeRecoveryEnabled: false

  DecideFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/
      Handler: decide.handler
      Timeout: 60
      FunctionUrlConfig:
        AuthType: NONE
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref FindingsTable
        - Statement:
            - Effect: Allow
              Action:
                - ec2:StopInstances
                - ec2:StartInstances
                - ec2:CreateSnapshot
                - ec2:CreateTags
                - ec2:DeleteTags
                - ec2:DescribeVolumes
                - ec2:DescribeInstances
              Resource: '*'
            - Effect: Allow
              Action: ssm:GetParameter
              Resource: !Sub
                arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter${HmacParamName}

  ScannerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/
      Handler: scanner.handler
      Timeout: 600
      Environment:
        Variables:
          MODEL_ID: !Ref ModelId
          DECISION_BASE_URL: !GetAtt DecideFunctionUrl.FunctionUrl
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref FindingsTable
        - Statement:
            - Effect: Allow
              Action:
                - ec2:DescribeInstances
                - ec2:DescribeVolumes
                - ec2:DescribeAddresses
                - ec2:DescribeNetworkInterfaces
                - cloudtrail:LookupEvents
                - iam:GetRole
                - iam:GetUser
              Resource: '*'
            - Effect: Allow
              Action: bedrock:InvokeModel
              Resource: '*'
            - Effect: Allow
              Action: ses:SendEmail
              Resource: '*'
            - Effect: Allow
              Action: ssm:GetParameter
              Resource: !Sub
                arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter${HmacParamName}
      Events:
        WeeklySweep:
          Type: ScheduleV2          # EventBridge Scheduler
          Properties:
            ScheduleExpression: cron(30 12 ? * FRI *)
            ScheduleExpressionTimezone: Asia/Kolkata
            Description: Friday 6pm IST account archaeology

  EnforcerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/
      Handler: enforcer.handler
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref FindingsTable
        - Statement:
            - Effect: Allow
              Action:
                - ec2:StopInstances
                - ec2:StartInstances
                - ec2:CreateSnapshot
                - ec2:CreateTags
                - ec2:DeleteTags
                - ec2:DescribeVolumes
                - ec2:DescribeInstances
              Resource: '*'
            - Effect: Allow
              Action: ses:SendEmail
              Resource: '*'
            - Effect: Allow
              Action: ssm:GetParameter
              Resource: !Sub
                arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter${HmacParamName}
      Events:
        DailyCheck:
          Type: ScheduleV2
          Properties:
            ScheduleExpression: cron(0 3 * * ? *)
            ScheduleExpressionTimezone: Asia/Kolkata

Outputs:
  DecisionEndpoint:
    Description: Signed-link decision endpoint
    Value: !GetAtt DecideFunctionUrl.FunctionUrl
  TableName:
    Value: !Ref FindingsTable
  ScannerName:
    Value: !Ref ScannerFunction
```

> Run `sam validate --lint` before every deploy. The three SSM `Resource` ARNs all resolve from the single `HmacParamName` parameter, so if you change the parameter path you do not have to hunt for hardcoded strings. `ScheduleV2` is the EventBridge Scheduler event source, not the older `Schedule` type which uses EventBridge rules and does not support `ScheduleExpressionTimezone`.

---

## 10. Deploy

```bash
# 1. Generate and store the HMAC signing key (free, standard SSM parameter)
aws ssm put-parameter \
  --name /whomadethis/hmac-key \
  --type SecureString \
  --value "$(openssl rand -base64 48)" \
  --region $AWS_REGION

# 2. Build and deploy
sam validate --lint
sam build
sam deploy --guided \
  --stack-name who-made-this \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
      SenderEmail=you@example.com \
      RecipientEmail=you@example.com \
      ModelId=amazon.nova-lite-v1:0

# 3. Grab the decision endpoint
aws cloudformation describe-stacks --stack-name who-made-this \
  --query "Stacks[0].Outputs" --output table
```

**Chicken and egg warning.** `ScannerFunction` reads `DECISION_BASE_URL` from `!GetAtt DecideFunctionUrl.FunctionUrl`. CloudFormation resolves this fine because the two functions are separate resources. If you hit a circular dependency, remove the env var, deploy, then set it with `aws lambda update-function-configuration`.

---

## 11. Test it, and manufacture something to find

An empty account produces an empty email, which makes a bad screenshot. Create a genuine orphan:

```bash
# An unattached, untagged volume. Costs about $0.08/GB/month, delete it after.
VOL=$(aws ec2 create-volume --size 1 --volume-type gp3 \
  --availability-zone ${AWS_REGION}a \
  --query VolumeId --output text)
echo "created $VOL"

# A stopped micro instance with no owner tag (Free Tier eligible)
AMI=$(aws ssm get-parameter \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)
INST=$(aws ec2 run-instances --image-id $AMI --instance-type t3.micro \
  --query 'Instances[0].InstanceId' --output text)
aws ec2 stop-instances --instance-ids $INST
```

Wait about 5 minutes. CloudTrail Event history is not instant, events typically appear within roughly 15 minutes. Then:

```bash
# Confirm CloudTrail can see the creation before you blame your code
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=$VOL \
  --query 'Events[].[EventName,Username,EventTime]' --output table

# Run the scanner by hand
aws lambda invoke --function-name <ScannerName-from-outputs> \
  --payload '{}' /tmp/out.json && cat /tmp/out.json

# Watch it work
sam logs -n ScannerFunction --stack-name who-made-this --tail
```

Check your inbox. Click **Send to Purgatory** on the volume, confirm a snapshot appears:

```bash
aws ec2 describe-snapshots --owner-ids self \
  --filters Name=tag:whomadethis:source,Values=$VOL \
  --query 'Snapshots[].[SnapshotId,State,Description]' --output table

aws ec2 describe-tags --filters Name=resource-id,Values=$VOL --output table
```

Then click **Keep** on the same resource to prove the reversal works. That round trip, flag to Purgatory to restore, is your best screenshot and your best 20 seconds of demo video.

Finally, prove the safety property. This should fail with `AccessDenied`, and the failure is a feature:

```bash
aws lambda invoke --function-name <DecideFunctionName> \
  --payload '{"queryStringParameters":{"rid":"'$VOL'","action":"delete","sig":"x","exp":"1"}}' \
  /tmp/deny.json; cat /tmp/deny.json
```

### Test the signature guard

Tamper with a link from the email, change one character in `sig`, and confirm you get the 403 page. Screenshot that too. It shows you thought about the fact that an unauthenticated Function URL is a public endpoint.

---

## 12. Teardown

```bash
aws ec2 terminate-instances --instance-ids $INST
aws ec2 delete-volume --volume-id $VOL          # after deleting its snapshot
aws ec2 describe-snapshots --owner-ids self \
  --filters Name=tag:whomadethis:source,Values=$VOL \
  --query 'Snapshots[].SnapshotId' --output text | xargs -n1 -I{} \
  aws ec2 delete-snapshot --snapshot-id {}

sam delete --stack-name who-made-this
aws ssm delete-parameter --name /whomadethis/hmac-key
```

Leave the stack up until the challenge is evaluated if you are linking a live demo. Delete the seeded EC2 instance and volume either way.

---

## 13. Evidence checklist for the article

Capture these while you build, not after. Going back for screenshots after teardown is misery.

- [ ] The digest email, full width, Orphan Scores and signal breakdown visible
- [ ] The "Sent to Purgatory" confirmation page
- [ ] The "Restored" confirmation page after clicking Keep
- [ ] `describe-tags` output showing `whomadethis:release-after`
- [ ] `describe-snapshots` output showing the recovery snapshot
- [ ] The 403 page from a tampered signature
- [ ] The IAM policy JSON, showing the absence of `Delete*` and `Terminate*`
- [ ] A `cloudtrail lookup-events` table proving the attribution source
- [ ] Architecture diagram (see `who-made-this-architecture.svg`)
- [ ] Public GitHub repo URL with this code and a README

The repo link satisfies the "working link" requirement on its own, per the article rules ("a working link to your deployed app **OR** a public GitHub repo"). A live demo of an account-scanning tool would mean handing strangers read access to your account, so the repo is the right call here. Say that in the article rather than leaving it unexplained.

---

## 14. Timeline for the weekend

| When | Do |
|---|---|
| Fri evening | Prereqs, Bedrock access, SES verification, seed the orphans. Both have lag, start them first |
| Sat morning | Phases 5 to 6, scanner working locally with real CloudTrail data |
| Sat afternoon | Phases 7 to 9, deploy, first real email |
| Sat evening | Purgatory round trip, capture all screenshots |
| Sun morning | Architecture diagram, push the repo, write the article |
| Sun evening | Publish. Deadline is Monday 3 August 13:00 PT, which is 01:30 IST Tuesday. Do not use that buffer |

---

## 15. Honest limitations to state in the article

Naming these makes the write-up more credible, not less. Reviewers notice.

- **90 day attribution window.** Resources older than 90 days come back unattributed. Handled as a signal, not a bug, but it is a real limit.
- **Single region, single account.** No AWS Organizations sweep. `LookupEvents` is per-region.
- **Four resource types.** No RDS, S3, Lambda, load balancers, or the long tail where the real money hides.
- **`LookupEvents` throttling.** Roughly 2 requests per second. The 0.6s sleep makes a 200-resource account take about two minutes. Fine weekly, wrong for an enterprise account.
- **Scan-based DynamoDB reads.** Correct at this size, wrong at scale. A GSI on `state` is the fix.
- **EIP and ENI Purgatory is tag-only.** Releasing an Elastic IP is not reversible, you may not get the same address back, so the app refuses to touch them and only flags.
- **Nova writes prose, not decisions.** Deliberate. Scoring is deterministic Python so the output is auditable and reproducible. The model can only make the email nicer, never more destructive.

---

## Appendix: what makes this submission stand out

From the idea bank analysis of last weekend's 221 entries: at least five idle-resource cleaners and four ownership-attribution tools were pitched. Attribution alone is not a differentiator any more. Two things are:

1. **Purgatory as a reversible middle state.** Every other entry either alerts or terminates. None built a recoverable intermediate state with a one-click undo and a 30 day window.
2. **The withheld permission.** The app cannot delete. That is enforced in IAM, not in code comments. It converts "would you let a bot near your production account" from a worry into the selling point.

Lead the article with both.
