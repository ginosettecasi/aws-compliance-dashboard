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

# **Default Compliance Standards**
DEFAULT_COMPLIANCE_STANDARDS = ["ISO 27001", "SOC 2 Type II", "FedRAMP", "CIS Controls", "PCI DSS"]

# **Timestamp for Compliance Report**
report_timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

try:
    response = securityhub_client.get_findings()
    findings = []
    
    for index, finding in enumerate(response.get('Findings', [])):
        original_title = finding.get("Title", "Unknown Finding")
        service = finding.get("Resources", [{}])[0].get("Type", "Unknown")
        first_observed_at = finding.get("FirstObservedAt", None)

        # **Redact Vulnerability Names for Public Display**
        title = f"Example Finding - CVE-XXXX-XXXX ({index+1})" if "CVE" in original_title else f"Security Issue {index+1}"

        # **Fix: Ensure First Observed Date is Correctly Extracted**
        if first_observed_at:
            try:
                parsed_date = datetime.datetime.strptime(first_observed_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                first_observed_at = parsed_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")  
            except ValueError:
                try:
                    parsed_date = datetime.datetime.strptime(first_observed_at, "%Y-%m-%dT%H:%M:%SZ")
                    first_observed_at = parsed_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")  
                except ValueError:
                    first_observed_at = None

        if index < 3 and not first_observed_at:
            first_observed_at = report_timestamp

        # **Assign Severity Based on Index Position**
        severity_order = ["Critical", "High", "High", "Medium", "Low", "Low"]
        severity = severity_order[index] if index < len(severity_order) else "Informational"
        
        remediation_time = REMEDIATION_TIME.get(severity, "Best Effort")

        # **Assign Compliance Frameworks (Use Default Since Titles Are Redacted)**
        compliance_frameworks = DEFAULT_COMPLIANCE_STANDARDS

        if len(compliance_frameworks) > 1:
            compliance_text = f"{compliance_frameworks[0]} + {len(compliance_frameworks) - 1}"
            compliance_hover_text = "\n".join(compliance_frameworks)
        else:
            compliance_text = compliance_frameworks[0]
            compliance_hover_text = compliance_frameworks[0]

        findings.append({
            "title": title,  # Redacted Title
            "severity": severity,
            "service": service,
            "date_first_discovered": first_observed_at,
            "remediation_time": remediation_time,
            "compliance_standard": compliance_text,
            "full_compliance_standards": compliance_hover_text
        })

    compliance_report = {"timestamp": report_timestamp, "findings": findings}
    
    with open("compliance-report.json", "w") as f:
        json.dump(compliance_report, f, indent=4)

    print("✅ Compliance report updated successfully!")
    print(f"📅 Report Date: {report_timestamp}")

except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    exit(1)
