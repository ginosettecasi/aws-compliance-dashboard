import boto3
import json

# 🔍 Debugging: Print AWS Caller Identity to verify credentials
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"DEBUG: AWS Account ID: {identity['Account']}")
print(f"DEBUG: IAM User ARN: {identity['Arn']}")

# Initialize AWS Security Hub client
securityhub_client = boto3.client('securityhub', region_name="us-east-2")

# Standard compliance frameworks used in AWS Security Hub
COMPLIANCE_STANDARDS = {
    "S3 Bucket Publicly Accessible": ["ISO 27001", "SOC 2 Type II", "CIS Controls", "FedRAMP"],
    "Root Account Has Active Keys": ["ISO 27001", "PCI DSS", "SOC 2 Type II", "FedRAMP"],
    "CloudTrail Not Enabled": ["CIS Controls", "ISO 27001", "SOC 2 Type II", "FedRAMP"],
    "IAM User Without MFA": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP", "CIS Controls"],
    "EC2 Security Group Allows All Traffic": ["ISO 27001", "PCI DSS", "SOC 2 Type II", "FedRAMP", "CIS Controls"],
    "IAM Policy Allows Full Admin Access": ["SOC 2 Type II", "ISO 27001", "FedRAMP", "CIS Controls"],
    "Unencrypted EBS Volume": ["PCI DSS", "ISO 27001", "SOC 2 Type II", "FedRAMP"],
    "RDS Publicly Accessible": ["ISO 27001", "CIS Controls", "SOC 2 Type II", "FedRAMP"],
    "Unused IAM Credentials Not Removed": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP"],
}

# If finding is not explicitly mapped, assign all frameworks
DEFAULT_COMPLIANCE_STANDARDS = ["ISO 27001", "SOC 2 Type II", "FedRAMP", "CIS Controls"]

# Remediation Timeframe Mapping (Industry Best Practices)
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
        title = finding.get("Title", "Unknown Finding")
        severity = finding.get("Severity", {}).get("Label", "Unknown")
        service = finding.get("Resources", [{}])[0].get("Type", "Unknown")

        # Assign Compliance Standards Dynamically
        compliance_standards = COMPLIANCE_STANDARDS.get(title, DEFAULT_COMPLIANCE_STANDARDS)  
        compliance_text = ", ".join(compliance_standards)

        # Assign Remediation Timeframe based on severity
        remediation_time = REMEDIATION_TIME.get(severity, "90 Days (Default)")

        findings.append({
            "title": title,
            "severity": severity,
            "service": service,
            "compliance_standard": compliance_text,
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
