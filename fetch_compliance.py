import boto3
import json

# 🔍 Debugging: Print AWS Caller Identity to verify credentials
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"DEBUG: AWS Account ID: {identity['Account']}")
print(f"DEBUG: IAM User ARN: {identity['Arn']}")

# Initialize AWS Security Hub client
securityhub_client = boto3.client('securityhub', region_name="us-east-2")

# Compliance Standard Mapping (Example: Mapping AWS Controls to Common Compliance Standards)
COMPLIANCE_MAPPING = {
    "S3 Bucket Publicly Accessible": "CIS, PCI DSS, FedRAMP",
    "Root Account Has Active Keys": "CIS, ISO 27001, SOC 2",
    "CloudTrail Not Enabled": "CIS, FedRAMP, PCI DSS",
    "IAM User Without MFA": "CIS, SOC 2, ISO 27001",
    "Security Hub Not Enabled": "AWS Best Practices, CIS",
}

# Estimated Remediation Time (Based on Industry Best Practices)
REMEDIATION_TIME = {
    "Critical": "Immediate",
    "High": "7 Days",
    "Medium": "30 Days",
    "Low": "90 Days",
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
        
        # Get Compliance Standard & Remediation Time
        compliance_standard = COMPLIANCE_MAPPING.get(title, "Unknown")
        remediation_time = REMEDIATION_TIME.get(severity, "Unknown")

        findings.append({
            "title": title,
            "severity": severity,
            "service": service,
            "compliance_standard": compliance_standard,
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
