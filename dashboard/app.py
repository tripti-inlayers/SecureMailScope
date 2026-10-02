import streamlit as st
import pandas as pd
import json
import glob
import subprocess
import tempfile
import os
import sys

st.set_page_config(page_title="SecureMailScope", layout="wide", page_icon="🔒")

@st.cache_data
def load_data(path):
    with open(path) as f:
        return json.load(f)

def safe(val, default="N/A"):
    return val if val is not None and val != "" else default

st.sidebar.title("🔒 SecureMailScope")
st.sidebar.markdown("---")

# Initialize session state for live analysis
if "live_data" not in st.session_state:
    st.session_state.live_data = None
if "active_upload_name" not in st.session_state:
    st.session_state.active_upload_name = None

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE_DIR = os.path.join(ROOT_DIR, "sample_results")

# Day 2: Live PCAP Upload (with a Safety Net)
st.sidebar.subheader("📥 PCAP Input Analysis")
uploaded_file = st.sidebar.file_uploader("Upload a PCAP capture directly", type=["pcap", "pcapng"])

# If file uploader was cleared by user, reset live data
if uploaded_file is None and st.session_state.live_data is not None:
    st.session_state.live_data = None
    st.session_state.active_upload_name = None

if uploaded_file is not None:
    if st.sidebar.button("Run PCAP Analysis"):
        with st.spinner("Running cryptographic analyzer engine..."):
            uploaded_file.seek(0)
            file_bytes = uploaded_file.read()
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            try:
                # Use sys.executable for reliable subprocess invocation
                cmd = [sys.executable, "-m", "analyzer.analyzer", tmp_path]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=90, cwd=ROOT_DIR
                )
                if result.returncode != 0:
                    err_msg = result.stderr or result.stdout
                    if "tshark is not installed" in err_msg or "FileNotFoundError" in err_msg:
                        st.sidebar.warning("⚠️ TShark / Wireshark is not available in this runtime. Please explore the interactive findings using the precomputed captures below.")
                    else:
                        st.sidebar.error(f"⚠️ Analysis Engine Error: {err_msg}")
                else:
                    parsed_data = json.loads(result.stdout)
                    if "metadata" in parsed_data:
                        parsed_data["metadata"]["filename"] = uploaded_file.name
                    st.session_state.live_data = parsed_data
                    st.session_state.active_upload_name = uploaded_file.name
                    st.sidebar.success("✅ PCAP Analysis Completed!")
            except Exception as e:
                st.sidebar.error(f"⚠️ Failed to launch analyzer: {e}")
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

# Precomputed results fallback dropdown
st.sidebar.subheader("📂 Precomputed Demo Captures")
available_files = sorted(glob.glob(os.path.join(SAMPLE_DIR, "*.json")))
if not available_files:
    st.error("No sample JSON files found in sample_results/ directory.")
    st.stop()

# Friendly label mapping for SIH demo
SAMPLE_LABELS = {
    "attack.json": "🚨 attack.json (Active STARTTLS Stripping)",
    "demo_full.json": "📊 demo_full.json (Enterprise Multi-Session Audit)",
    "good.json": "✅ good.json (Modern TLS 1.3 Baseline)",
    "weak.json": "⚠️ weak.json (Deprecated TLS 1.0 & Weak Ciphers)",
    "mock_attack.json": "🚨 mock_attack.json (STARTTLS Downgrade)",
    "mock_critical.json": "🔴 mock_critical.json (Plaintext Cleartext Auth)",
    "mock_good.json": "✅ mock_good.json (Full TLS 1.3 Baseline)",
    "mock_weak.json": "⚠️ mock_weak.json (Weak Cipher Suite Suite)",
}

def format_sample_name(filepath):
    base = os.path.basename(filepath)
    return SAMPLE_LABELS.get(base, f"📁 {base}")

live_data = st.session_state.get("live_data")
if live_data is not None:
    st.sidebar.success(f"🟢 **Analysis Mode:** `{st.session_state.get('active_upload_name', 'Uploaded File')}`")
    if st.sidebar.button("↩️ Switch to Sample Captures"):
        st.session_state.live_data = None
        st.session_state.active_upload_name = None
        st.rerun()
    data = live_data
    choice = None
else:
    choice = st.sidebar.selectbox("Select Sample Scenario", available_files, format_func=format_sample_name)
    data = load_data(choice)

st.sidebar.markdown("---")
st.sidebar.caption("🛡️ **SecureMailScope** | Offline Cryptographic Posture Assessment")

# Main Title & Header
st.title("🛡️ SecureMailScope Security Dashboard")
filename = os.path.basename(data['metadata']['filename'])
analyzed_at = data['metadata']['analyzed_at']
st.caption(f"📁 **File:** `{filename}` | ⏱️ **Analyzed:** `{analyzed_at}`")

total_sessions = data["summary"]["total_sessions"]
high_risk_count = data["summary"]["high_risk"]
med_risk_count = data["summary"].get("medium_risk", 0)
low_risk_count = data["summary"].get("low_risk", 0)

if high_risk_count > 0:
    st.error(f"🚨 **Security Warning:** {total_sessions} sessions analyzed — **{high_risk_count} HIGH/CRITICAL risk** findings requiring attention!")
elif med_risk_count > 0:
    st.warning(f"⚠️ **Security Notice:** {total_sessions} sessions analyzed — {med_risk_count} MEDIUM risk findings detected.")
else:
    st.success(f"✅ **Security Clean:** {total_sessions} sessions analyzed — All connections use strong modern encryption.")

# Metrics Cards
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Sessions", total_sessions)
m2.metric("Low Risk", low_risk_count)
m3.metric("Medium Risk", med_risk_count)
m4.metric("High / Critical Risk", high_risk_count)

st.markdown("---")

# Sessions Summary Table
st.subheader("📊 Session Overview")

rows = []
for s in data["sessions"]:
    tls = s.get("tls") or {}
    cert = s.get("certificate") or {}
    stls = s.get("starttls") or {}
    risk = s.get("risk") or {}
    anomaly = s.get("anomaly") or {}

    tls_ver = safe(tls.get("version"))
    if not tls.get("detected"):
        tls_status = "Plaintext"
    else:
        tls_status = tls_ver

    if cert.get("present"):
        cert_status = "Expired" if cert.get("expired") else "Valid"
    else:
        cert_status = "Missing"

    if stls.get("attempted") and not stls.get("succeeded"):
        stls_status = "⚡ Stripped"
    elif stls.get("succeeded"):
        stls_status = "Negotiated"
    else:
        stls_status = "Not Used"

    anom_flag = anomaly.get("flagged")
    if anom_flag is True:
        anom_str = "🚩 Flagged"
    elif anom_flag is False:
        anom_str = "Normal"
    else:
        anom_str = "N/A"

    rows.append({
        "Session ID": s["session_id"],
        "Protocol": safe(s.get("protocol")),
        "TLS Version": tls_status,
        "Cipher Suite": safe(tls.get("cipher_suite")),
        "Certificate": cert_status,
        "STARTTLS": stls_status,
        "Risk Level": risk.get("level", "UNKNOWN"),
        "Behavioral Anomaly (ML)": anom_str,
    })

df = pd.DataFrame(rows)

def highlight_risk(row):
    color_map = {
        "LOW": "background-color: #d4edda; color: #155724;",
        "MEDIUM": "background-color: #fff3cd; color: #856404;",
        "HIGH": "background-color: #f8d7da; color: #721c24;",
        "CRITICAL": "background-color: #f5c6cb; color: #721c24; font-weight: bold;"
    }
    return [color_map.get(row["Risk Level"], "")] * len(row)

st.dataframe(df.style.apply(highlight_risk, axis=1), use_container_width=True)

st.markdown("---")

# Session Detail Inspector
session_ids = [s["session_id"] for s in data["sessions"]]
selected_id = st.selectbox("🔍 Select Session to Inspect", session_ids)
session = next(s for s in data["sessions"] if s["session_id"] == selected_id)

st.subheader(f"📌 Security Details — {selected_id}")

tls_data = session.get("tls") or {}
cert_data = session.get("certificate") or {}
starttls_data = session.get("starttls") or {}
risk_data = session.get("risk") or {}
anom_data = session.get("anomaly") or {}

# Structured Security Detail Cards
col_a, col_b, col_c, col_d = st.columns(4)

with col_a:
    st.markdown("### 🔒 TLS Status")
    if tls_data.get("detected"):
        st.success(f"**Status:** Encrypted\n\n**Version:** {safe(tls_data.get('version'))}")
    else:
        st.error("**Status:** Plaintext (No TLS)\n\n**Version:** N/A")

with col_b:
    st.markdown("### 🔑 Cipher Suite")
    st.info(f"**Suite:** {safe(tls_data.get('cipher_suite'))}")

with col_c:
    st.markdown("### 📜 Certificate")
    if cert_data.get("present"):
        if cert_data.get("expired"):
            st.error(f"**Status:** Expired ❌\n\n**Subject:** {safe(cert_data.get('subject'))}")
        else:
            st.success(f"**Status:** Present & Valid ✅\n\n**Subject:** {safe(cert_data.get('subject'))}")
    else:
        st.warning("**Status:** No Certificate Observed")

with col_d:
    st.markdown("### ⚡ STARTTLS & Risk")
    st.metric("Risk Level", risk_data.get("level", "UNKNOWN"), delta=f"Score: {risk_data.get('score', 'N/A')}")

# Behavioral Anomaly Card
st.markdown("#### 🤖 Behavioral Anomaly Detection (ML)")
if anom_data.get("flagged") is True:
    st.warning(f"🚩 **Behavioral Anomaly Flagged** (Score: `{anom_data.get('anomaly_score')}`). This session deviates statistically from baseline traffic pattern.")
elif anom_data.get("flagged") is False:
    st.success(f"✅ **Normal Traffic Behavior** (Score: `{anom_data.get('anomaly_score')}`). No statistical anomaly detected.")
else:
    st.info(f"ℹ️ **N/A / Insufficient Sessions:** {anom_data.get('note', 'Need >= 3 sessions in capture for ML anomaly detection.')}")

# STARTTLS Visual Attack Sequence Diagram
if starttls_data.get("attempted") and not starttls_data.get("succeeded"):
    st.markdown("---")
    st.error("### 🚨 Detected STARTTLS Stripping Attack Sequence")
    st.caption("Active Man-in-the-Middle Interception Signature")
    
    seq_col1, seq_col2, seq_col3, seq_col4 = st.columns(4)
    with seq_col1:
        st.markdown("**1. Server Offers STARTTLS**")
        st.info("Server advertises `250-STARTTLS` in EHLO response")
    with seq_col2:
        st.markdown("**2. Client Requests STARTTLS**")
        st.info("Client issues `STARTTLS` command")
    with seq_col3:
        st.markdown("**3. Attack Block / 502 Failure**")
        st.error("MITM injects `502 Command Not Implemented` ❌")
    with seq_col4:
        st.markdown("**4. Cleartext Continuation**")
        st.error("Connection drops back to unencrypted cleartext ⚠️")

# Detailed Findings
st.markdown("### 📋 Security Findings & Recommendations")
findings = session.get("findings", [])
if not findings:
    st.info("No security findings for this session.")
else:
    for finding in findings:
        sev = finding.get("severity", "LOW")
        icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(sev, "⚪")
        with st.expander(f"{icon} {finding.get('title')} [{sev}]"):
            st.write(finding.get("description", ""))
            st.code(f"Evidence: {finding.get('evidence', 'N/A')}", language="text")
            st.markdown(f"**Remediation Recommendation:** {finding.get('recommendation', 'N/A')}")

# Forensic Report Generation
st.markdown("---")
st.subheader("📄 Export Forensic Report")

try:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from analyzer import report_exporter

    reports_dir = os.path.join(SAMPLE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    if live_data is not None:
        raw_name = data.get("metadata", {}).get("filename", "live_capture")
        clean_base = os.path.splitext(os.path.basename(raw_name.replace("\\", "/")))[0]
        live_json_path = os.path.join(reports_dir, f"{clean_base}.json")
        with open(live_json_path, "w", encoding="utf-8") as f:
            json.dump(live_data, f, indent=2)
        export_json_path = live_json_path
        download_name_base = clean_base
    else:
        export_json_path = choice
        download_name_base = os.path.splitext(os.path.basename(choice))[0]
    
    html_path, pdf_path = report_exporter.export_report(export_json_path, output_dir=reports_dir)
    
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    with open(html_path, "rb") as f:
        html_bytes = f.read()
        
    ec1, ec2 = st.columns(2)
    ec1.download_button("📥 Download PDF Report", data=pdf_bytes, file_name=f"{download_name_base}.pdf", mime="application/pdf")
    ec2.download_button("📥 Download HTML Report", data=html_bytes, file_name=f"{download_name_base}.html", mime="text/html")
except Exception as e:
    st.error(f"Failed to generate forensic reports: {e}")
