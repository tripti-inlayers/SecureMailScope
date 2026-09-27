import streamlit as st
import pandas as pd
import json
import glob
import subprocess
import tempfile
import os

st.set_page_config(page_title="SecureMailScope", layout="wide")

@st.cache_data
def load_data(path):
    with open(path) as f:
        return json.load(f)

st.sidebar.title("SecureMailScope")

# Day 2: Live PCAP Upload (with a Safety Net)
uploaded_file = st.sidebar.file_uploader("Or upload a PCAP directly", type=["pcap", "pcapng"])

live_data = None

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name
        
    if st.sidebar.button("Run live analysis"):
        with st.spinner("Running analyzer..."):
            try:
                # Use python executable depending on OS, or just "python"
                result = subprocess.run(
                    ["python", "analyzer/analyzer.py", tmp_path],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode != 0:
                    raise Exception(f"Analyzer failed: {result.stderr}")
                live_data = json.loads(result.stdout)
                st.sidebar.success("Live analysis complete")
            except Exception as e:
                st.sidebar.error(f"Live analysis failed: {e}. Falling back to precomputed results below.")

# Load available precomputed files
available_files = sorted(glob.glob("sample_results/*.json"))
if not available_files:
    st.error("No sample JSON files found in sample_results/ directory.")
    st.stop()

choice = st.sidebar.selectbox("Load capture", available_files)

# Determine which data to use
data = live_data if live_data else load_data(choice)

st.title("Email Traffic Security Dashboard")
st.caption(f"File: {data['metadata']['filename']} | Analyzed: {data['metadata']['analyzed_at']}")

# Day 2 Polish: "3 sessions analyzed — 2 HIGH risk findings requiring attention."
total_sessions = data["summary"]["total_sessions"]
high_risk_count = data["summary"]["high_risk"]
if high_risk_count > 0:
    st.warning(f"{total_sessions} sessions analyzed — {high_risk_count} HIGH/CRITICAL risk findings requiring attention.")
else:
    st.info(f"{total_sessions} sessions analyzed — No HIGH risk findings.")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Sessions", data["summary"]["total_sessions"])
col2.metric("Low Risk", data["summary"]["low_risk"])
col3.metric("Medium Risk", data["summary"]["medium_risk"])
col4.metric("High Risk", data["summary"]["high_risk"])

# --- Day 4: Dashboard Visualization ---
st.markdown("---")
st.subheader("Risk Distribution")
risk_counts = {
    "Low": data["summary"]["low_risk"],
    "Medium": data["summary"]["medium_risk"],
    "High/Critical": data["summary"]["high_risk"],
}
# Using native Streamlit bar chart for zero new dependencies
st.bar_chart(pd.Series(risk_counts))
st.markdown("---")

def safe(val, default="N/A"):
    return val if val is not None else default

rows = []
for s in data["sessions"]:
    # Parse anomaly explicitly as requested
    anomaly_flag = s.get("anomaly", {}).get("flagged")
    if anomaly_flag is True:
        anomaly_str = "🚩 Flagged"
    elif anomaly_flag is None:
        anomaly_str = "—"
    else:
        anomaly_str = "Normal"

    rows.append({
        "Session": s["session_id"],
        "Protocol": safe(s.get("protocol")),
        "TLS Version": safe(s["tls"].get("version")),
        "Cert Expired": str(s["certificate"].get("expired")) if s.get("certificate") and "expired" in s["certificate"] else "N/A",
        "Risk": s["risk"]["level"],
        "Anomaly": anomaly_str,
    })

df = pd.DataFrame(rows)

def highlight_risk(row):
    # Day 2 Polish: color-code risk levels (red / orange / green)
    color = {"LOW": "#d4edda", "MEDIUM": "#fff3cd", "HIGH": "#f8d7da", "CRITICAL": "#f5c6cb"}.get(row["Risk"], "")
    return [f"background-color: {color}"] * len(row)

st.dataframe(df.style.apply(highlight_risk, axis=1), use_container_width=True)

session_ids = [s["session_id"] for s in data["sessions"]]
selected_id = st.selectbox("Inspect a session", session_ids)
session = next(s for s in data["sessions"] if s["session_id"] == selected_id)

st.subheader(f"Session Detail — {selected_id}")

c1, c2 = st.columns(2)
with c1:
    st.markdown("**TLS**")
    if session.get("tls"):
        st.write(session["tls"])
    else:
        st.write("N/A")
    st.markdown("**STARTTLS**")
    st.write(session.get("starttls", "Not recorded"))

with c2:
    st.markdown("**Certificate**")
    if session.get("certificate"):
        st.write(session["certificate"])
    else:
        st.write("N/A")

st.markdown("**Findings**")
for finding in session.get("findings", []):
    severity_color = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(finding["severity"], "⚪")
    with st.expander(f"{severity_color} {finding['title']} — {finding['severity']}"):
        st.write(finding.get("description", ""))
        st.code(finding.get("evidence", "N/A"))
        st.markdown(f"**Recommendation:** {finding.get('recommendation', 'N/A')}")

# --- Day 3: Report Export ---
st.markdown("---")
st.subheader("Export Forensic Report")

export_json_path = choice
if live_data:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp_j:
        json.dump(live_data, tmp_j)
        export_json_path = tmp_j.name

try:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from analyzer import report_exporter
    
    html_path, pdf_path = report_exporter.export_report(export_json_path, output_dir="sample_results/reports")
    
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    with open(html_path, "rb") as f:
        html_bytes = f.read()
        
    ec1, ec2 = st.columns(2)
    ec1.download_button("Export PDF Report", data=pdf_bytes, file_name=os.path.basename(pdf_path), mime="application/pdf")
    ec2.download_button("Export HTML Report", data=html_bytes, file_name=os.path.basename(html_path), mime="text/html")
except Exception as e:
    st.error(f"Failed to generate reports: {e}")

