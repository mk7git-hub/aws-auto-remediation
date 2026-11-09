"""Auto-remediate public S3 buckets.

Triggered by EventBridge on either:
  * CloudTrail API calls that can expose a bucket (DeleteBucketPublicAccessBlock, PutBucketPolicy, PutBucketAcl), or
  * Security Hub findings for control S3.8 (block public access) or S3.2/S3.3 (public read/write).

Re-applies the bucket public access block, tags the bucket, notifies SNS and,
for Security Hub findings, marks the finding RESOLVED with a note.
Buckets tagged public-allowed=true are left alone (documented exception).
"""
import json
import logging
import os
from datetime import datetime, timezone

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

EXEMPT_TAG = "public-allowed"
TRIGGER_EVENTS = {"DeleteBucketPublicAccessBlock", "PutBucketPolicy", "PutBucketAcl"}
CONTROLS = {"S3.2", "S3.3", "S3.8"}


def clients():
    return boto3.client("s3"), boto3.client("sns"), boto3.client("securityhub")


def buckets_from_event(event):
    """Return [(bucket, finding_or_None)] for the event shapes we accept."""
    detail = event.get("detail", {})
    if event.get("detail-type") == "AWS API Call via CloudTrail":
        if detail.get("eventName") in TRIGGER_EVENTS:
            name = (detail.get("requestParameters") or {}).get("bucketName")
            return [(name, None)] if name else []
        return []
    if event.get("detail-type") == "Security Hub Findings - Imported":
        out = []
        for f in detail.get("findings", []):
            control = (f.get("Compliance") or {}).get("SecurityControlId") or ""
            if control not in CONTROLS or (f.get("Compliance") or {}).get("Status") != "FAILED":
                continue
            for r in f.get("Resources", []):
                if r.get("Type") == "AwsS3Bucket":
                    out.append((r["Id"].split(":::")[-1], f))
        return out
    return []


def is_exempt(s3, bucket):
    try:
        tags = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
    except s3.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchTagSet":
            return False
        raise
    return any(t["Key"] == EXEMPT_TAG and t["Value"].lower() == "true" for t in tags)


def remediate(s3, bucket):
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def handler(event, context=None, _clients=None):
    s3, sns, sh = _clients or clients()
    topic = os.environ.get("ALERT_TOPIC_ARN")
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    results = []
    for bucket, finding in buckets_from_event(event):
        if is_exempt(s3, bucket):
            results.append({"bucket": bucket, "action": "skipped-exempt"})
            continue
        if not dry_run:
            remediate(s3, bucket)
        action = "would-block" if dry_run else "blocked"
        results.append({"bucket": bucket, "action": action})
        if finding and not dry_run:
            sh.batch_update_findings(
                FindingIdentifiers=[{"Id": finding["Id"], "ProductArn": finding["ProductArn"]}],
                Workflow={"Status": "RESOLVED"},
                Note={"Text": "Public access block re-applied by aws-auto-remediation", "UpdatedBy": "auto-remediation"},
            )
        if topic:
            sns.publish(
                TopicArn=topic,
                Subject=f"S3 public access {action}: {bucket}"[:100],
                Message=json.dumps({"bucket": bucket, "action": action,
                                    "trigger": event.get("detail-type"),
                                    "time": datetime.now(timezone.utc).isoformat()}),
            )
    log.info(json.dumps({"results": results}))
    return {"results": results}
