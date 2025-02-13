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

# **Timestamp for Compliance Report**
report_timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d")

try:
    response = securityhub_client.get_findings()
    findings = []
    
    for finding in response.get('Findings', []):
        title = finding.get("Title", "Unknown Finding")
        service = finding.get("Resources", [{}])[0].get("Type", "Unknown")
        first_observed_at = finding.get("FirstObservedAt", "Unknown")

        # **Fix: Handle timestamps with or without milliseconds**
        full_timestamp = "Unknown"
        formatted_date = "Unknown"

        if first_observed_at != "Unknown":
            try:
                # Try parsing with milliseconds
                full_timestamp = datetime.datetime.strptime(first_observed_at, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                try:
                    # If that fails, try parsing without milliseconds
                    full_timestamp = datetime.datetime.strptime(first_observed_at, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError as e:
                    print(f"⚠️ WARNING: Failed to parse timestamp '{first_observed_at}': {e}")
                    full_timestamp = "Unknown"

            # Extract only the date (YYYY-MM-DD) for UI display
            if full_timestamp != "Unknown":
                formatted_date = full_timestamp.strftime("%Y-%m-%d")

        severity = CUSTOM_SEVERITIES.get(title, "Informational")
        remediation_time = REMEDIATION_TIME.get(severity, "Best Effort")

        findings.append({
            "title": title,
            "severity": severity,
            "service": service,
            "date_first_discovered": formatted_date,  # Display only YYYY-MM-DD
            "full_timestamp": full_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if full_timestamp != "Unknown" else "Unknown",  # Store full timestamp for accuracy
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
