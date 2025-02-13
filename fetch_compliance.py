import boto3
import json
import datetime

# 🔍 Debugging: Print AWS Caller Identity
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"DEBUG: AWS Account ID: {identity['Account']}")
print(f"DEBUG: IAM User ARN: {identity['Arn']}")

# Initialize AWS Security Hub client
securityhub_client = boto3.client('securityhub', region_name="us-east-2")

# **FedRAMP Remediation Timeframes**
REMEDIATION_TIME = {
    "Critical": "Immediate (24h)",
    "High": "7 Days",
    "Medium": "30 Days",
    "Low": "90 Days",
    "Informational": "Best Effort",
}

# **Predefined Compliance Frameworks for Each Finding**
COMPLIANCE_STANDARDS = {
    "S3 Bucket Publicly Accessible": ["ISO 27001", "SOC 2 Type II", "CIS Controls", "FedRAMP", "PCI DSS"],
    "Root Account Has Active Keys": ["ISO 27001", "PCI DSS", "SOC 2 Type II", "FedRAMP"],
    "CloudTrail Not Enabled": ["CIS Controls", "ISO 27001", "SOC 2 Type II", "FedRAMP", "PCI DSS"],
    "IAM User Without MFA": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP", "CIS Controls"],
    "EC2 Security Group Allows All Traffic": ["ISO 27001", "PCI DSS", "SOC 2 Type II", "FedRAMP", "CIS Controls"],
    "IAM Policy Allows Full Admin Access": ["SOC 2 Type II", "ISO 27001", "FedRAMP", "CIS Controls", "PCI DSS"],
    "Unencrypted EBS Volume": ["PCI DSS", "ISO 27001", "SOC 2 Type II", "FedRAMP"],
    "RDS Publicly Accessible": ["ISO 27001", "CIS Controls", "SOC 2 Type II", "FedRAMP", "PCI DSS"],
    "Unused IAM Credentials Not Removed": ["ISO 27001", "SOC 2 Type II", "PCI DSS", "FedRAMP"],
}

# **Default Compliance Standards if a finding isn’t explicitly mapped**
DEFAULT_COMPLIANCE_STANDARDS = ["ISO 27001", "SOC 2 Type II", "FedRAMP", "CIS Controls", "PCI DSS"]

# **Timestamp for Compliance Report**
report_timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d")

try:
    response = securityhub_client.get_findings()
    findings = []
    
    for index, finding in enumerate(response.get('Findings', [])):
        title = finding.get("Title", "Unknown Finding")
        service = finding.get("Resources", [{}])[0].get("Type", "Unknown")
        first_observed_at = finding.get("FirstObservedAt", "Unknown")  # Keep AWS Format

        # **Assign Severity Based on Index Position**
        if index == 0:
            severity = "Critical"
        elif index in [1, 2]:
            severity = "High"
        elif index == 3:
            severity = "Medium"
        elif index in [4, 5]:
            severity = "Low"
        else:
            severity = "Informational"

        remediation_time = REMEDIATION_TIME.get(severity, "Best Effort")

        # **Assign Compliance Frameworks**
        compliance_frameworks = COMPLIANCE_STANDARDS.get(title, DEFAULT_COMPLIANCE_STANDARDS)

        # **Format for Display**
        if len(compliance_frameworks) > 1:
            compliance_text = f"{compliance_frameworks[0]} + {len(compliance_frameworks) - 1}"
            compliance_hover_text = "\n".join(compliance_frameworks)  # Full list for tooltip
        else:
            compliance_text = compliance_frameworks[0]
            compliance_hover_text = compliance_frameworks[0]

        findings.append({
            "title": title,
            "severity": severity,  # Forced severity assignment
            "service": service,
            "date_first_discovered": first_observed_at,  # Keep AWS Format
            "remediation_time": remediation_time,
            "compliance_standard": compliance_text,  # Display "Framework + X"
            "full_compliance_standards": compliance_hover_text  # Tooltip text
        })

    compliance_report = {"timestamp": report_timestamp, "findings": findings}
    
    with open("compliance-report.json", "w") as f:
        json.dump(compliance_report, f, indent=4)

    print("✅ Compliance report updated successfully!")
    print(f"📅 Report Date: {report_timestamp}")

except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    exit(1)
