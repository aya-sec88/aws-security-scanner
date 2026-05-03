import streamlit as st
import boto3
import json
from groq import Groq
from datetime import datetime

st.set_page_config(page_title="AWS Security Scanner", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .score-box { padding:1rem 1.5rem; border-radius:12px; margin-bottom:1rem; font-size:1.1rem; font-weight:600; }
    .critical { background:#FCEBEB; color:#A32D2D; border:1px solid #F09595; }
    .high     { background:#FCEBEB; color:#A32D2D; border:1px solid #F09595; }
    .medium   { background:#FAEEDA; color:#854F0B; border:1px solid #FAC775; }
    .low      { background:#EAF3DE; color:#3B6D11; border:1px solid #C0DD97; }
    .pass     { background:#EAF3DE; color:#3B6D11; border:1px solid #C0DD97; }
    .fail     { background:#FCEBEB; color:#A32D2D; border:1px solid #F09595; }
    .warn     { background:#FAEEDA; color:#854F0B; border:1px solid #FAC775; }
    .finding  { padding:8px 12px; border-radius:6px; margin:4px 0; font-size:0.9rem; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AWS Security Scanner")
st.markdown("Automated cloud security misconfiguration detection powered by AI.")
st.divider()

# ── Load credentials from secrets ────────────────────────────────────────────
try:
    aws_key    = st.secrets["AWS_ACCESS_KEY_ID"]
    aws_secret = st.secrets["AWS_SECRET_ACCESS_KEY"]
    aws_region = st.secrets.get("AWS_REGION", "eu-north-1")
    groq_key   = st.secrets.get("GROQ_API_KEY", "")
    st.success("🔑 AWS credentials loaded automatically.")
except:
    st.warning("No secrets found. Enter credentials manually.")
    aws_key    = st.text_input("AWS Access Key ID", type="password")
    aws_secret = st.text_input("AWS Secret Access Key", type="password")
    aws_region = st.text_input("AWS Region", value="eu-north-1")
    groq_key   = st.text_input("Groq API Key", type="password")

st.divider()

# ── AWS client helper ─────────────────────────────────────────────────────────
def get_client(service):
    return boto3.client(
        service,
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name=aws_region
    )

# ── Scanner functions ─────────────────────────────────────────────────────────

def scan_iam():
    findings = []
    score = 100
    try:
        iam = get_client("iam")

        # Check root account MFA
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append({"severity": "CRITICAL", "check": "Root MFA", "detail": "MFA is NOT enabled on root account — critical security risk"})
            score -= 30
        else:
            findings.append({"severity": "PASS", "check": "Root MFA", "detail": "MFA is enabled on root account ✅"})

        # Check root access keys
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append({"severity": "CRITICAL", "check": "Root Access Keys", "detail": "Root account has active access keys — must be deleted immediately"})
            score -= 25
        else:
            findings.append({"severity": "PASS", "check": "Root Access Keys", "detail": "No root access keys found ✅"})

        # Check password policy
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            if policy.get("MinimumPasswordLength", 0) < 14:
                findings.append({"severity": "MEDIUM", "check": "Password Policy", "detail": f"Password minimum length is {policy.get('MinimumPasswordLength')} — should be 14+"})
                score -= 10
            else:
                findings.append({"severity": "PASS", "check": "Password Policy", "detail": "Password policy meets minimum requirements ✅"})
        except:
            findings.append({"severity": "HIGH", "check": "Password Policy", "detail": "No password policy configured — all passwords accepted"})
            score -= 20

        # Check IAM users with console access
        users = iam.list_users()["Users"]
        users_no_mfa = []
        for user in users:
            try:
                mfa = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                if not mfa:
                    users_no_mfa.append(user["UserName"])
            except:
                pass

        if users_no_mfa:
            findings.append({"severity": "HIGH", "check": "User MFA", "detail": f"Users without MFA: {', '.join(users_no_mfa)}"})
            score -= 15
        else:
            findings.append({"severity": "PASS", "check": "User MFA", "detail": f"All {len(users)} users have MFA enabled ✅"})

    except Exception as e:
        findings.append({"severity": "ERROR", "check": "IAM Scan", "detail": str(e)})

    return findings, max(0, score)


def scan_s3():
    findings = []
    score = 100
    try:
        s3 = get_client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            findings.append({"severity": "PASS", "check": "S3 Buckets", "detail": "No S3 buckets found in this account"})
            return findings, score

        for bucket in buckets:
            name = bucket["Name"]

            # Check public access block
            try:
                pub = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all(pub.values()):
                    findings.append({"severity": "HIGH", "check": f"S3 Public Access: {name}", "detail": f"Bucket {name} does not have all public access blocks enabled"})
                    score -= 20
                else:
                    findings.append({"severity": "PASS", "check": f"S3 Public Access: {name}", "detail": f"Bucket {name} has public access blocked ✅"})
            except:
                findings.append({"severity": "HIGH", "check": f"S3 Public Access: {name}", "detail": f"Could not verify public access settings for {name}"})
                score -= 15

            # Check encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
                findings.append({"severity": "PASS", "check": f"S3 Encryption: {name}", "detail": f"Bucket {name} has encryption enabled ✅"})
            except:
                findings.append({"severity": "MEDIUM", "check": f"S3 Encryption: {name}", "detail": f"Bucket {name} does not have default encryption enabled"})
                score -= 10

            # Check versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                if ver.get("Status") != "Enabled":
                    findings.append({"severity": "LOW", "check": f"S3 Versioning: {name}", "detail": f"Bucket {name} does not have versioning enabled"})
                    score -= 5
                else:
                    findings.append({"severity": "PASS", "check": f"S3 Versioning: {name}", "detail": f"Bucket {name} has versioning enabled ✅"})
            except:
                pass

    except Exception as e:
        findings.append({"severity": "ERROR", "check": "S3 Scan", "detail": str(e)})

    return findings, max(0, score)


def scan_security_groups():
    findings = []
    score = 100
    try:
        ec2 = get_client("ec2")
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        dangerous_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}

        for sg in sgs:
            sg_name = sg.get("GroupName", "unknown")
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        if from_port == 0 and to_port == 65535:
                            findings.append({"severity": "CRITICAL", "check": f"SG: {sg_name}", "detail": f"Security group allows ALL traffic from internet (0.0.0.0/0)"})
                            score -= 30
                        elif from_port in dangerous_ports:
                            findings.append({"severity": "HIGH", "check": f"SG: {sg_name}", "detail": f"Port {from_port} ({dangerous_ports[from_port]}) is open to the entire internet"})
                            score -= 20
                        else:
                            findings.append({"severity": "MEDIUM", "check": f"SG: {sg_name}", "detail": f"Port {from_port}-{to_port} is open to internet — verify if intentional"})
                            score -= 5

        if not any(f["severity"] in ["CRITICAL", "HIGH", "MEDIUM"] for f in findings):
            findings.append({"severity": "PASS", "check": "Security Groups", "detail": "No dangerous security group rules found ✅"})

    except Exception as e:
        findings.append({"severity": "ERROR", "check": "Security Group Scan", "detail": str(e)})

    return findings, max(0, score)


def generate_ai_report(iam_findings, s3_findings, sg_findings, scores):
    client = Groq(api_key=groq_key)
    all_issues = [f for f in iam_findings + s3_findings + sg_findings if f["severity"] not in ["PASS", "ERROR"]]

    prompt = f"""You are an expert AWS cloud security architect and SOC analyst.
Analyze these AWS security scan results and provide a professional security assessment report.

Scan Results:
- IAM Security Score: {scores['iam']}/100
- S3 Security Score: {scores['s3']}/100
- Network Security Score: {scores['sg']}/100
- Overall Score: {scores['overall']}/100

Issues Found:
{json.dumps(all_issues, indent=2)}

Provide your analysis in this format:

## 🛡️ AWS Security Assessment Report
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Overall Security Score:** {scores['overall']}/100
**Risk Level:** [Critical/High/Medium/Low]

## Executive Summary
[2-3 sentences explaining the overall security posture]

## Critical Findings
[List and explain each critical/high issue found]

## Risk Analysis
[What could happen if these issues are exploited]

## Remediation Priority
1. [Most urgent fix]
2. [Second priority]
3. [Third priority]

## Compliance Notes
[How these findings relate to CIS AWS Benchmark and ISO 27001]

## Analyst Recommendation
[Overall recommendation and next steps]"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=2000,
    )
    return response.choices[0].message.content


# ── UI TABS ───────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["🔐 IAM Security", "🪣 S3 Buckets", "🛡️ Network Security", "📊 Full Report"])

def severity_color(sev):
    colors = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "PASS": "pass", "ERROR": "warn"}
    return colors.get(sev, "warn")

def severity_emoji(sev):
    emojis = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "PASS": "✅", "ERROR": "⚠️"}
    return emojis.get(sev, "ℹ️")

with tab1:
    st.subheader("IAM Security Scan")
    if st.button("🔍 Scan IAM", type="primary", use_container_width=True):
        with st.spinner("Scanning IAM configuration..."):
            findings, score = scan_iam()
            st.session_state["iam_findings"] = findings
            st.session_state["iam_score"] = score

    if "iam_findings" in st.session_state:
        score = st.session_state["iam_score"]
        color = "critical" if score < 50 else "medium" if score < 75 else "pass"
        st.markdown(f'<div class="score-box {color}">IAM Security Score: {score}/100</div>', unsafe_allow_html=True)
        for f in st.session_state["iam_findings"]:
            st.markdown(f'<div class="finding {severity_color(f["severity"])}">{severity_emoji(f["severity"])} <b>{f["check"]}</b> — {f["detail"]}</div>', unsafe_allow_html=True)

with tab2:
    st.subheader("S3 Bucket Security Scan")
    if st.button("🔍 Scan S3 Buckets", type="primary", use_container_width=True):
        with st.spinner("Scanning S3 buckets..."):
            findings, score = scan_s3()
            st.session_state["s3_findings"] = findings
            st.session_state["s3_score"] = score

    if "s3_findings" in st.session_state:
        score = st.session_state["s3_score"]
        color = "critical" if score < 50 else "medium" if score < 75 else "pass"
        st.markdown(f'<div class="score-box {color}">S3 Security Score: {score}/100</div>', unsafe_allow_html=True)
        for f in st.session_state["s3_findings"]:
            st.markdown(f'<div class="finding {severity_color(f["severity"])}">{severity_emoji(f["severity"])} <b>{f["check"]}</b> — {f["detail"]}</div>', unsafe_allow_html=True)

with tab3:
    st.subheader("Network Security Group Scan")
    if st.button("🔍 Scan Security Groups", type="primary", use_container_width=True):
        with st.spinner("Scanning security groups..."):
            findings, score = scan_security_groups()
            st.session_state["sg_findings"] = findings
            st.session_state["sg_score"] = score

    if "sg_findings" in st.session_state:
        score = st.session_state["sg_score"]
        color = "critical" if score < 50 else "medium" if score < 75 else "pass"
        st.markdown(f'<div class="score-box {color}">Network Security Score: {score}/100</div>', unsafe_allow_html=True)
        for f in st.session_state["sg_findings"]:
            st.markdown(f'<div class="finding {severity_color(f["severity"])}">{severity_emoji(f["severity"])} <b>{f["check"]}</b> — {f["detail"]}</div>', unsafe_allow_html=True)

with tab4:
    st.subheader("Full AI Security Report")
    if "iam_findings" not in st.session_state or "s3_findings" not in st.session_state:
        st.info("Run all 3 scans first (IAM, S3, Security Groups) then generate the full report.")
    else:
        iam_score = st.session_state.get("iam_score", 0)
        s3_score  = st.session_state.get("s3_score", 0)
        sg_score  = st.session_state.get("sg_score", 0)
        overall   = (iam_score + s3_score + sg_score) // 3

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🔐 IAM Score", f"{iam_score}/100")
        col2.metric("🪣 S3 Score",  f"{s3_score}/100")
        col3.metric("🛡️ Network",   f"{sg_score}/100")
        col4.metric("📊 Overall",   f"{overall}/100")

        if st.button("🤖 Generate AI Security Report", type="primary", use_container_width=True):
            with st.spinner("AI is analyzing your AWS security posture..."):
                try:
                    scores = {"iam": iam_score, "s3": s3_score, "sg": sg_score, "overall": overall}
                    report = generate_ai_report(
                        st.session_state["iam_findings"],
                        st.session_state["s3_findings"],
                        st.session_state.get("sg_findings", []),
                        scores
                    )
                    st.markdown(report)
                except Exception as e:
                    st.error(f"Error: {str(e)}")

st.divider()
st.caption("AWS Security Scanner — Built with boto3, Groq AI and Streamlit · For educational and professional use")