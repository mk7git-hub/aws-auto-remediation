#!/usr/bin/env bash
# Live demo: make a bucket public-capable and watch the function close it (needs CloudTrail, e.g. from P1).
set -euo pipefail
B="remediation-demo-$(aws sts get-caller-identity --query Account --output text)-$RANDOM"
aws s3api create-bucket --bucket "$B" --region us-east-1
echo "Removing the public access block on $B ..."
aws s3api delete-public-access-block --bucket "$B"
echo "Waiting 90s for CloudTrail -> EventBridge -> Lambda ..."
sleep 90
aws s3api get-public-access-block --bucket "$B" --query PublicAccessBlockConfiguration
echo "All four true = remediated. Clean up: aws s3api delete-bucket --bucket $B"
