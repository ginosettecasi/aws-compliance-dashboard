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

# **FedRAMP Remediation Timeframes**
FEDRAMP_REMEDIATION_TIME = {
    "Critical": "Immediate (Within 24 Hours)",
    "High": "Within 7 Days",
    "Medium": "Within 30 Days",
    "Low": "Within 90 Days",
    "Informational": "Best Effort (Best Practice)",
}

# **Fetch findings from AWS Security Hub**
response = securityhub_client.get_findings()

findings = []
for finding in response.get('Findings', []):
    title = finding.get("Title", "Unknown Finding")
    service = finding.get("Resources", [{}])[0].get("Type", "Unknown")

    # **Override severity with showcase values if applicable**
    severity = SHOWCASE_SEVERITIES.get(title, "Informational")

    # **Assign FedRAMP-based Remediation Timeframe**
    remediation_time = FEDRAMP_REMEDIATION_TIME.get(severity, "Best Effort")

    # **Assign Compliance Standards Dynamically**
    compliance_standards = [
        "ISO 27001", "SOC 2 Type II", "CIS Controls", "FedRAMP", "PCI DSS", "AWS Well-Architected Security Pillar"
    ] if title in SHOWCASE_SEVERITIES else ["AWS Best Practices"]

    # **Format compliance text for space efficiency**
    compliance_text = f"{compliance_standards[0]} + {len(compliance_standards) - 1} more" if len(compliance_standards) > 1 else compliance_standards[0]

    findings.append({
        "title": title,
        "severity": severity,
        "service": service,
        "compliance_standard": compliance_text,
        "full_compliance_standards": compliance_standards,  # Store full list for tooltip
        "remediation_time": remediation_time
    })

# **Save findings to JSON file**
compliance_report = {
    "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    "findings": findings
}

with open("compliance-report.json", "w") as f:
    json.dump(compliance_report, f, indent=4)

print("✅ Compliance report updated successfully!")
