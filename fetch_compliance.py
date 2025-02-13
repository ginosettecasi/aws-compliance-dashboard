import boto3
import json
import datetime

# 🔍 Debugging: Print AWS Caller Identity to verify credentials
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"DEBUG: AWS Account ID: {identity['Account']}")
print(f"DEBUG: IAM User ARN: {identity['Arn']}")

# Initialize AWS Security Hub client
securityhub_client = boto3.client('securityhub', region_name="us-east-2")

# **Manually Assigned Severity Levels**
CUSTOM_SEVERITIES = {
    "S3 Bucket Publicly Accessible": "Critical",
    "Root Account Has Active Keys": "High",
    "CloudTrail Not Enabled": "High",
    "IAM User Without MFA": "Medium",
    "EC2 Security Group Allows All Traffic": "Low",
    "IAM Policy Allows Full Admin Access": "Low",
}

# **FedRAMP Remediation Timeframes**
REMEDIATION_TIME = {
    "Critical": "Immediate (24h)",
    "High": "7 Days",
    "Medium": "30 Days",
    "Low": "90 Days",
    "Informational": "Best Effort",
}

# **Remediation Steps**
REMEDIATION_STEPS = {
    "S3 Bucket Publicly Accessible": "Apply bucket policies to deny public access. Use VPC endpoints for secure access.",
    "Root Account Has Active Keys": "Disable root access keys and enforce IAM role-based access.",
    "CloudTrail Not Enabled": "Enable AWS CloudTrail in all regions for audit logging.",
    "IAM User Without MFA": "Require MFA for all IAM users in security policies.",
    "EC2 Security Group Allows All Traffic": "Restrict security groups to only necessary IP ranges.",
    "IAM Policy Allows Full Admin Access": "Apply least privilege IAM policies. Use AWS IAM Access Analyzer.",
}

# **Timestamp for Compliance Report**
report_timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

try:
    # **Fetch findings from AWS Security Hub**
    response = securityhub_client.get_findings()

    findings = []
    for finding in response.get('Findings', []):
        title = finding.get("Title", "Unknown Finding")
        service = finding.get("Resources", [{}])[0].get("Type", "Unknown")

        # **Assign custom severity or default to Informational**
        severity = CUSTOM_SEVERITIES.get(title, "Informational")

        # **Assign Remediation Timeframe based on severity (FedRAMP-aligned)**
        remediation_time = REMEDIATION_TIME.get(severity, "Best Effort")

        # **Assign Remediation Steps**
        remediation_steps = REMEDIATION_STEPS.get(title, "Refer to AWS Security Hub documentation.")

        findings.append({
            "title": title,
            "severity": severity,
            "service": service,
            "remediation_time": remediation_time,
            "remediation_steps": remediation_steps
        })

    # **Save findings to JSON file**
    compliance_report = {
        "timestamp": report_timestamp,
        "findings": findings
    }

    with open("compliance-report.json", "w") as f:
        json.dump(compliance_report, f, indent=4)

    print("✅ Compliance report updated successfully!")
    print(f"📅 Report Timestamp: {report_timestamp}")
    print(f"🔍 Total Findings: {len(findings)}")

except securityhub_client.exceptions.InvalidAccessException:
    print("❌ ERROR: Invalid Access - AWS Security Hub may not be enabled or IAM permissions may be missing.")
    print("🔹 Ensure your IAM user has `AWSSecurityHubReadOnlyAccess` attached.")
    print("🔹 Ensure Security Hub is enabled in `us-east-2` region.")
    exit(1)
except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    exit(1)
