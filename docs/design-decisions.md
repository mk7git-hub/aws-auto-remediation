# Design decisions: AWS Auto-Remediation

### 1. Two triggers: CloudTrail API events and Security Hub findings
- **Why:** API events react within about a minute of the change; Security Hub findings catch buckets that were already public or changed while the rule was down. Both feed one function.

### 2. Re-apply the bucket public access block rather than delete policies or ACLs
- **Why:** the block overrides public policies and ACLs without destroying anyone's configuration; it's reversible and non-destructive.

### 3. Exception by tag
- **Why:** the business sometimes needs public buckets (static sites). A tag is visible, auditable and controlled through IaC. In production, restrict who can set that tag with an SCP or tag policy.

### 4. Dry-run mode
- **Why:** new auto-remediation should run in report-only mode first to measure what it would change before it changes anything.

### 5. Least-privilege role, reserved concurrency 5, DLQ, retries
- **Why:** limits blast radius if the function misbehaves; retries handle transient errors; DLQ plus alarm makes failures visible instead of silent.

### 6. Stubbed unit tests (botocore Stubber) instead of a mocking library
- **Why:** no extra dependencies, and the Stubber validates the exact API parameters against the real AWS service model.

### 7. Lambda outside a VPC
- **Why:** it only calls public AWS APIs; putting it in a VPC would need NAT or endpoints and add cost with no security gain here.

### 8. Single-purpose function
- **Why:** one control, one function, easy to reason about and test. More controls (open security groups, unencrypted volumes) would be separate functions or a Step Functions workflow.
