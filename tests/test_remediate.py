import pathlib
import sys

import boto3
import pytest
from botocore.stub import ANY, Stubber

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import remediate_s3 as r

REGION = "us-east-1"


@pytest.fixture
def stubbed(monkeypatch):
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:alerts")
    monkeypatch.setenv("DRY_RUN", "false")
    s3 = boto3.client("s3", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="x")
    sns = boto3.client("sns", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="x")
    sh = boto3.client("securityhub", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="x")
    stubs = Stubber(s3), Stubber(sns), Stubber(sh)
    for s in stubs:
        s.activate()
    yield (s3, sns, sh), stubs
    for s in stubs:
        s.assert_no_pending_responses()


def ct_event(name="DeleteBucketPublicAccessBlock", bucket="demo-bucket"):
    return {"detail-type": "AWS API Call via CloudTrail",
            "detail": {"eventName": name, "requestParameters": {"bucketName": bucket}}}


def sh_event(control="S3.8", status="FAILED"):
    return {"detail-type": "Security Hub Findings - Imported", "detail": {"findings": [{
        "Id": "finding-1", "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "Compliance": {"SecurityControlId": control, "Status": status},
        "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::demo-bucket"}]}]}}


def expect_block(s3s, snss, tags=None):
    if tags is None:
        s3s.add_client_error("get_bucket_tagging", "NoSuchTagSet", expected_params={"Bucket": "demo-bucket"})
    else:
        s3s.add_response("get_bucket_tagging", {"TagSet": tags}, {"Bucket": "demo-bucket"})
    s3s.add_response("put_public_access_block", {}, {"Bucket": "demo-bucket", "PublicAccessBlockConfiguration": ANY})
    snss.add_response("publish", {"MessageId": "1"}, {"TopicArn": ANY, "Subject": ANY, "Message": ANY})


def test_cloudtrail_trigger_blocks_bucket(stubbed):
    c, (s3s, snss, _) = stubbed
    expect_block(s3s, snss)
    assert r.handler(ct_event(), _clients=c)["results"] == [{"bucket": "demo-bucket", "action": "blocked"}]


def test_securityhub_finding_is_resolved(stubbed):
    c, (s3s, snss, shs) = stubbed
    s3s.add_client_error("get_bucket_tagging", "NoSuchTagSet", expected_params={"Bucket": "demo-bucket"})
    s3s.add_response("put_public_access_block", {}, {"Bucket": "demo-bucket", "PublicAccessBlockConfiguration": ANY})
    shs.add_response("batch_update_findings", {"ProcessedFindings": [], "UnprocessedFindings": []},
                     {"FindingIdentifiers": ANY, "Workflow": {"Status": "RESOLVED"}, "Note": ANY})
    snss.add_response("publish", {"MessageId": "1"}, {"TopicArn": ANY, "Subject": ANY, "Message": ANY})
    assert r.handler(sh_event(), _clients=c)["results"][0]["action"] == "blocked"


def test_exempt_bucket_is_skipped(stubbed):
    c, (s3s, _, _) = stubbed
    s3s.add_response("get_bucket_tagging", {"TagSet": [{"Key": "public-allowed", "Value": "true"}]}, {"Bucket": "demo-bucket"})
    assert r.handler(ct_event(), _clients=c)["results"] == [{"bucket": "demo-bucket", "action": "skipped-exempt"}]


def test_dry_run_changes_nothing(stubbed, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    c, (s3s, snss, _) = stubbed
    s3s.add_client_error("get_bucket_tagging", "NoSuchTagSet", expected_params={"Bucket": "demo-bucket"})
    snss.add_response("publish", {"MessageId": "1"}, {"TopicArn": ANY, "Subject": ANY, "Message": ANY})
    assert r.handler(ct_event(), _clients=c)["results"][0]["action"] == "would-block"


@pytest.mark.parametrize("event", [ct_event(name="GetBucketPolicy"), sh_event(control="EC2.1"), sh_event(status="PASSED"), {"detail-type": "other"}])
def test_irrelevant_events_ignored(stubbed, event):
    c, _ = stubbed
    assert r.handler(event, _clients=c)["results"] == []
