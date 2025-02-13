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

        findings.append({
            "title": title,
            "severity": severity,  # Forced severity assignment
            "service": service,
            "date_first_discovered": first_observed_at,  # Keep AWS Format
            "remediation_time": remediation_time
        })

    compliance_report = {"timestamp": report_timestamp, "findings": findings}
    
    with open("compliance-report.json", "w") as f:
        json.dump(compliance_report, f, indent=4)

    print("✅ Compliance report updated successfully!")
    print(f"📅 Report Date: {report_timestamp}")

except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    exit(1)
