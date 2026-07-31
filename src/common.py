"""Shared helpers: link signing, DynamoDB access, time formatting."""

import base64
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE_NAME = os.environ["TABLE_NAME"]
HMAC_PARAM = os.environ["HMAC_PARAM"]

PURGATORY_DAYS = int(os.environ.get("PURGATORY_DAYS", "30"))
GRACE_DAYS = int(os.environ.get("GRACE_DAYS", "7"))

# Decision links must outlive the grace window so that a "restore from
# Purgatory" link stays clickable until the next weekly digest regenerates it.
LINK_TTL_DAYS = max(GRACE_DAYS + 7, 14)

_ssm = boto3.client("ssm", region_name=REGION)
_table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)

_secret_cache = None


def signing_key() -> bytes:
    """Fetch the HMAC key from Parameter Store, cached for the container's life."""
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
    expires_at = int(time.time()) + LINK_TTL_DAYS * 86400
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
    """Small table, so a filtered scan is honest and cheap. A GSI on `state`
    is the right fix if this ever runs against a large account."""
    items = []
    kwargs = {
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
