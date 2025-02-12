import boto3
import json

# 🔍 Debugging: Print AWS Caller Identity to verify credentials
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"DEBUG: AWS Account ID: {identity['Account']}")
print(f"DEBUG: IAM User ARN: {identity['Arn']}")

# Initialize AWS Security Hub client
securityhub_client = boto3.client('securityhub', region_name="us-east-2")

# Compliance Standard Mapping (Based on AWS Security Hub Standards)
COMPLIANCE_MAPPING = {
    "S3 Bucket Publicly Accessible": ["CIS Controls", "ISO 27001", "SOC 2 Type II", "FedRAMP"],
    "Root Account Has Active Keys": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP", "CIS Controls"],
    "CloudTrail Not Enabled": ["CIS Controls", "FedRAMP", "SOC 2 Type II", "ISO 27001"],
    "IAM User Without MFA": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "CIS Controls"],
    "Security Hub Not Enabled": ["AWS Best Practices", "CIS Controls", "ISO 27001"],
    "EC2 Security Group Allows All Traffic": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP", "CIS Controls"],
    "IAM Policy Allows Full Admin Access": ["SOC 2 Type II", "ISO 27001", "FedRAMP", "CIS Controls"],
    "Unencrypted EBS Volume": ["PCI DSS", "ISO 27001", "SOC 2 Type II", "FedRAMP"],
    "RDS Publicly Accessible": ["CIS Controls", "ISO 27001", "FedRAMP", "SOC 2 Type II"],
    "Unused IAM Credentials Not Removed": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP"],
}

# Remediation Timeframe Mapping (Based on Industry Best Practices)
REMEDIATION_TIME = {
    "Critical": "Immediate (Within 24 hours)",
    "High": "Within 7 Days",
    "Medium": "Within 30 Days",
    "Low": "Within 90 Days",
    "Informational": "Best Effort",
}

try:
    # Fetch compliance findings
    response = securityhub_client.get_findings()

    findings = []
    for finding in response.get('Findings', []):
        title = finding.get("Title", "No Title")
        severity = finding.get("Severity", {}).get("Label", "Unknown")
        service = finding.get("Resources", [{}])[0].get("Type", "Unknown")

        # Get Compliance Standards & Remediation Time
        compliance_standards = COMPLIANCE_MAPPING.get(title, ["Not Mapped"])
        remediation_time = REMEDIATION_TIME.get(severity, "Unknown")

        findings.append({
            "title": title,
            "severity": severity,
            "service": service,
            "compliance_standard": ", ".join(compliance_standards),
            "remediation_time": remediation_time
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
