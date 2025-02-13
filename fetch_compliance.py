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

# **Manually Assigned Severities for Showcase Purposes**
SHOWCASE_SEVERITIES = {
    "S3 Bucket Publicly Accessible": "Critical",
    "Root Account Has Active Keys": "Critical",
    "CloudTrail Not Enabled": "High",
    "IAM User Without MFA": "Medium",
    "EC2 Security Group Allows All Traffic": "Medium",
    "IAM Policy Allows Full Admin Access": "Low",
    "Unencrypted EBS Volume": "Informational",
    "RDS Publicly Accessible": "Informational",
    "Unused IAM Credentials Not Removed": "Informational",
}

# **Compliance Standards (Includes PCI DSS & AWS Well-Architected Framework)**
COMPLIANCE_STANDARDS = {
    "S3 Bucket Publicly Accessible": ["ISO 27001", "SOC 2 Type II", "CIS Controls", "FedRAMP", "PCI DSS", "AWS Well-Architected Security Pillar"],
    "Root Account Has Active Keys": ["ISO 27001", "PCI DSS", "SOC 2 Type II", "FedRAMP", "AWS Well-Architected Security Pillar"],
    "CloudTrail Not Enabled": ["CIS Controls", "ISO 27001", "SOC 2 Type II", "FedRAMP", "PCI DSS", "AWS Well-Architected Security Pillar"],
    "IAM User Without MFA": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP", "CIS Controls", "AWS Well-Architected Security Pillar"],
    "EC2 Security Group Allows All Traffic": ["ISO 27001", "PCI DSS", "SOC 2 Type II", "FedRAMP", "CIS Controls", "AWS Well-Architected Security Pillar"],
    "IAM Policy Allows Full Admin Access": ["SOC 2 Type II", "ISO 27001", "FedRAMP", "CIS Controls", "PCI DSS", "AWS Well-Architected Security Pillar"],
    "Unencrypted EBS Volume": ["PCI DSS", "ISO 27001", "SOC 2 Type II", "FedRAMP", "AWS Well-Architected Security Pillar"],
    "RDS Publicly Accessible": ["ISO 27001", "CIS Controls", "SOC 2 Type II", "FedRAMP", "PCI DSS", "AWS Well-Architected Security Pillar"],
    "Unused IAM Credentials Not Removed": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP", "AWS Well-Architected Security Pillar"],
}

# **Remediation Timeframe Mapping**
REMEDIATION_TIME = {
    "Critical": "Immediate (Within 24 hours)",
    "High": "Within 7 Days",
    "Medium": "Within 30 Days",
    "Low": "Within 90 Days",
    "Informational": "Best Effort",
}

# **Automated Remediation Recommendations**
REMEDIATION_STEPS = {
    "S3 Bucket Publicly Accessible": "Apply bucket policies to deny public access. Use VPC endpoints for secure access.",
    "Root Account Has Active Keys": "Disable root access keys and enforce IAM role-based access.",
    "CloudTrail Not Enabled": "Enable AWS CloudTrail in all regions for audit logging.",
    "IAM User Without MFA": "Require MFA for all IAM users in security policies.",
    "EC2 Security Group Allows All Traffic": "Restrict security groups to only necessary IP ranges.",
    "IAM Policy Allows Full Admin Access": "Apply least privilege IAM policies. Use AWS IAM Access Analyzer.",
    "Unencrypted EBS Volume": "Enable default encryption for new EBS volumes.",
    "RDS Publicly Accessible": "Restrict RDS access using security groups and parameter groups.",
    "Unused IAM Credentials Not Removed": "Regularly review and remove inactive IAM credentials.",
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

        # **Assign severity based on showcase mapping**
        severity = SHOWCASE_SEVERITIES.get(title, "Informational")

        # **Assign Compliance Standards Dynamically**
        compliance_standards = COMPLIANCE_STANDARDS.get(title, ["AWS Best Practices"])

        # **Format compliance text for UI space efficiency**
        if len(compliance_standards) > 1:
            compliance_text = f"{compliance_standards[0]} + {len(compliance_standards) - 1} more"
        else:
            compliance_text = compliance_standards[0]

        # **Assign Remediation Timeframe based on severity**
        remediation_time = REMEDIATION_TIME.get(severity, "90 Days (Default)")

        # **Assign Remediation Steps**
        remediation_steps = REMEDIATION_STEPS.get(title, "Refer to AWS Security Hub documentation.")

        findings.append({
            "title": title,
            "severity": severity,
            "service": service,
            "compliance_standard": compliance_text,
            "full_compliance_standards": "\n".join(compliance_standards),
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
