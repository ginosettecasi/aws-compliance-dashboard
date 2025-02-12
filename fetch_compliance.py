import boto3
import json

# 🔍 Debugging: Print AWS Caller Identity to verify credentials
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"DEBUG: AWS Account ID: {identity['Account']}")
print(f"DEBUG: IAM User ARN: {identity['Arn']}")

# Initialize AWS Security Hub client
securityhub_client = boto3.client('securityhub', region_name="us-east-2")

try:
    # Fetch compliance findings
    response = securityhub_client.get_findings()

    findings = []
    for finding in response.get('Findings', []):
        findings.append({
            "title": finding.get("Title", "No Title"),
            "severity": finding.get("Severity", {}).get("Label", "Unknown"),
            "service": finding.get("Resources", [{}])[0].get("Type", "Unknown")
        })

    # Save findings to JSON file
    with open("compliance-report.json", "w") as f:
        json.dump({"findings": findings}, f, indent=4)

    print("✅ Compliance report updated successfully!")

except securityhub_client.exceptions.InvalidAccessException:
    print("❌ ERROR: Invalid Access - AWS Security Hub may not be enabled or IAM permissions may be missing.")
    print("🔹 Ensure your IAM user has `AWSSecurityHubReadOnlyAccess` attached.")
    print("🔹 Ensure Security Hub is enabled in `us-east-2` region.")
    exit(1)
except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    exit(1)
