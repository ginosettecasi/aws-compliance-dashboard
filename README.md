# 🔒 AWS Compliance Dashboard

## 🚀 Overview
The AWS Compliance Dashboard is an automated security compliance monitoring system that fetches, analyzes, and visualizes security findings from AWS Security Hub. It ensures compliance with industry standards (e.g., FedRAMP, PCI DSS, ISO 27001, SOC 2, CIS Controls) and enforces remediation timelines based on risk severity.

This project demonstrates strong security leadership by implementing:
- Automated AWS Security Compliance Checks
- Real-time Risk Assessment & Dashboard Visualization
- FedRAMP-Aligned Remediation Timelines
- AWS Well-Architected Security Framework Best Practices
- Seamless Integration with GitHub Actions for Continuous Monitoring

Why This Matters:  
This repository eliminates manual compliance tracking and ensures proactive security governance—key responsibilities for a Principal Security Compliance Lead.

## ⚙️ How It Works
### ✅ Automated Workflow
1. Fetch Security Findings from AWS Security Hub  
   - Runs `fetch_compliance.py` to retrieve the latest security findings.  
   - Ensures that the findings align with compliance frameworks.  
   - Forces a structured severity format, ensuring consistency across reports.

2. Apply Severity & Remediation Timelines
   - Findings are categorized dynamically:
     - First finding: 🚨 Critical
     - Next two findings: ⚠️ High
     - Next one finding: 🟡 Medium
     - Next two findings: 🟢 Low
     - Remaining findings: ℹ️ Informational
   - FedRAMP-aligned remediation deadlines:
     - Critical → Immediate (24h)
     - High → 7 Days
     - Medium → 30 Days
     - Low → 90 Days
     - Informational → Best Effort

3. Generate JSON Report (`compliance-report.json`)
   - Stores compliance findings with timestamps in AWS format (`YYYY-MM-DDTHH:MM:SS.sssZ`).
   - Ensures auditability and historical tracking.

4. Update & Display Findings in the Compliance Dashboard
   - The `index.html` file dynamically fetches `compliance-report.json`.
   - Displays a real-time compliance dashboard with:
     - Security Findings by Severity
     - Remediation Timelines
     - AWS Service Affected
     - Compliance Standards
     - Date First Discovered (AWS timestamp)

## 🎯 Key Features
### 🛡️ Proactive AWS Security Compliance
✔ Automated Compliance Auditing (FedRAMP, PCI DSS, ISO 27001, SOC 2)  
✔ AWS Security Hub Integration (Pulls live security findings)  
✔ FedRAMP Remediation Timelines (Enforces strict SLAs)  
✔ Real-time Risk Visibility (Dashboard with actionable insights)  

### 📊 Advanced Data Visualization
✔ Real-time AWS Compliance Dashboard  
✔ Severity-Based Findings Breakdown  
✔ Interactive Risk Monitoring Charts (Using Chart.js)  
✔ Automated Severity Assignment  

### ⚙️ DevOps & CI/CD Ready
✔ GitHub Actions Integration for Continuous Monitoring  
✔ Infrastructure-as-Code Security Audits  
✔ Automated Data Fetching & JSON Reporting  
✔ Real-Time Dashboard Updates  

## 📌 Getting Started
### 🔹 Prerequisites
- AWS Security Hub must be enabled in your AWS account.
- An IAM role/user with `AWSSecurityHubReadOnlyAccess` permissions.
- Python 3.x installed on your local machine.

### 🔹 Setup Instructions
1️⃣ Clone the repository  
```bash
git clone https://github.com/your-username/aws-compliance-dashboard.git
cd aws-compliance-dashboard
