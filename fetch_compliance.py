import boto3
import json

# Initialize AWS SecurityHub client
securityhub_client = boto3.client('securityhub', region_name="us-east-1")

# Fetch compliance findings
response = securityhub_client.get_findings()

findings = []
for finding in response['Findings']:
    findings.append({
        "title": finding["Title"],
        "severity": finding["Severity"]["Label"],
        "service": finding["Resources"][0]["Type"]
    })

# Save to JSON file
with open("compliance-report.json", "w") as f:
    json.dump({"findings": findings}, f, indent=4)

print("✅ Compliance report updated successfully!")
