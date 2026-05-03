\# 🛡️ AWS Security Scanner



> AI-powered cloud security misconfiguration detection using boto3 and Groq AI



\## 🖥️ Live Demo

👉 \[Try it here](https://aws-security-scanner-soc.streamlit.app)



\## 📸 Screenshots



!\[Demo 1](demo1.png)

!\[Demo 2](demo2.png)

!\[Demo 3](demo3.png)

!\[Demo 4](demo4.png)

!\[Demo 5](demo5.png)



\## What it detects



\### 🔐 IAM Security

\- Root account MFA status

\- Root access keys exposure

\- Password policy strength

\- Users without MFA



\### 🪣 S3 Bucket Security

\- Public access settings

\- Encryption configuration

\- Versioning status



\### 🛡️ Network Security

\- Open security groups

\- Dangerous exposed ports (SSH, RDP, SMB)

\- Internet-facing services



\### 📊 Full AI Report

\- Overall security score

\- Executive summary

\- Risk analysis

\- Remediation priority list

\- CIS AWS Benchmark compliance notes



\## Tech Stack

\- Python

\- boto3 (AWS SDK)

\- Groq API (Llama 3.3 70B)

\- Streamlit



\## Real Findings Example

Scanner detected on a real AWS account:

\- Root MFA not enabled — critical risk

\- No password policy configured

\- IAM user without MFA



Built by a SOC intern learning cloud security automation.

