import boto3
import json

# 🔍 Debugging: Print AWS Caller Identity to verify credentials
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"DEBUG: AWS Account ID: {identity['Account']}")
print(f"DEBUG: IAM User ARN: {identity['Arn']}")

# Initialize AWS Security Hub client
securityhub_client = boto3.client('securityhub', region_name="us-east-2")

# Industry-standard compliance frameworks commonly used in AWS Security Hub
COMPLIANCE_STANDARDS = [
    "ISO 27001", "ISO 27701", "SOC 2 Type II", "SOC 3",
    "PCI DSS (all versions)", "FedRAMP", "GDPR",
    "DISA STIG", "CIS Controls", "AWS Best Practices"
]

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

        # Dynamically map compliance standards based on keywords in the title
        mapped_standards = []
        for standard in COMPLIANCE_STANDARDS:
            if any(keyword.lower() in title.lower() for keyword in ["s3", "iam", "encryption", "mfa", "security group", "logging", "access control"]):
                mapped_standards.append(standard)

        # Ensure no empty compliance mappings
        compliance_standards = ", ".join(mapped_standards) if mapped_standards else "Not Specified"

        # Assign remediation timeframe based on severity
        remediation_time = REMEDIATION_TIME.get(severity, "Unknown")

        findings.append({
            "title": title,
            "severity": severity,
            "service": service,
            "compliance_standard": compliance_standards,
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
