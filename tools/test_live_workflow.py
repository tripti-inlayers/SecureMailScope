from streamlit.testing.v1 import AppTest
import os
import json
from pypdf import PdfReader

def p(s):
    print(str(s).encode('ascii', 'backslashreplace').decode('ascii'))

p("=== Starting End-to-End Live Upload Test ===")

# Clean any existing reports for smtp-starttls
for ext in [".json", ".html", ".pdf"]:
    path = os.path.join("sample_results", "reports", f"smtp-starttls{ext}")
    if os.path.exists(path):
        os.remove(path)

at = AppTest.from_file(os.path.abspath("dashboard/app.py"), default_timeout=60)
at.run()

p("Initial load complete.")
# Initial caption should be a sample capture (attack.pcap)
for c in at.caption:
    p(f"Initial caption: {c.value}")

# Read pcap
pcap_path = os.path.abspath("random_pcaps/smtp-starttls.pcap")
with open(pcap_path, "rb") as f:
    file_bytes = f.read()

# 1. Upload file
uploader = at.sidebar.file_uploader[0]
uploader.upload(filename="smtp-starttls.pcap", content=file_bytes)
at.run()
p("File uploaded via Streamlit file_uploader.")

# 2. Click Run Live Analysis
btn = at.sidebar.button[0]
p(f"Clicking button: {btn.label}")
btn.click()
at.run()

# 3. Check sidebar messages
for s in at.sidebar.success:
    p(f"Sidebar success: {s.value}")
for e in at.sidebar.error:
    p(f"Sidebar error: {e.value}")

# 4. Check session_state
p(f"Session state keys: {list(at.session_state.keys())}")
live_data = at.session_state.get("live_data")
assert live_data is not None, "FAILED: live_data is None in session_state!"
p("CONFIRMED: live_data is populated in session_state.")

# 5. Check metadata filename
pcap_fn = live_data.get("metadata", {}).get("filename")
p(f"live_data metadata filename: {pcap_fn}")
assert pcap_fn == "smtp-starttls.pcap", f"FAILED: Expected smtp-starttls.pcap, got {pcap_fn}"
p("CONFIRMED: metadata.filename is 'smtp-starttls.pcap' (not a temp path).")

# 6. Check displayed dashboard values
captions = [c.value for c in at.caption]
p(f"Dashboard captions: {captions}")
assert any("smtp-starttls.pcap" in c for c in captions), "FAILED: smtp-starttls.pcap not found in dashboard captions!"
p("CONFIRMED: Dashboard header displays smtp-starttls.pcap.")

# Check metrics
metrics = [(m.label, m.value) for m in at.metric]
p(f"Metrics: {metrics}")
# Total Sessions: 1, Low: 0, Medium: 0, High: 1
assert any(m[0] == "Total Sessions" and str(m[1]) == "1" for m in metrics), "FAILED: Total sessions metric != 1"
assert any(m[0] == "High / Critical Risk" and str(m[1]) == "1" for m in metrics), "FAILED: High / Critical metric != 1"
p("CONFIRMED: Dashboard displays live metrics (Total: 1, High/Critical: 1).")

# 7. Check Dataframe contents
df = at.dataframe[0].value
p(f"Dataframe columns: {list(df.columns)}")
p(f"Dataframe rows:\n{df}")
assert df.iloc[0]["Protocol"] == "SMTP", "FAILED: Protocol != SMTP"
assert df.iloc[0]["TLS Version"] == "TLS 1.0", "FAILED: TLS Version != TLS 1.0"
assert df.iloc[0]["Cipher Suite"] == "TLS_RSA_WITH_RC4_128_SHA", "FAILED: Cipher Suite != TLS_RSA_WITH_RC4_128_SHA"
assert df.iloc[0]["Risk Level"] == "HIGH", "FAILED: Risk Level != HIGH"
p("CONFIRMED: Dataframe displays live analysis results (SMTP, TLS 1.0, RC4, HIGH).")

pdf_btn = [b for b in at.download_button if "PDF" in b.label][0]
proto_fields = [f for f in dir(pdf_btn.proto) if not f.startswith('_')]
p(f"pdf_btn proto fields: {proto_fields}")
if hasattr(pdf_btn.proto, 'default_file_name'):
    p(f"PDF download filename: {pdf_btn.proto.default_file_name}")
    assert pdf_btn.proto.default_file_name == "smtp-starttls.pdf"
elif hasattr(pdf_btn.proto, 'file_name'):
    p(f"PDF download filename: {pdf_btn.proto.file_name}")
    assert pdf_btn.proto.file_name == "smtp-starttls.pdf"
elif hasattr(pdf_btn.proto, 'url'):
    p(f"PDF download url: {pdf_btn.proto.url}")

# 9. Verify generated PDF on disk
pdf_path = os.path.join("sample_results", "reports", "smtp-starttls.pdf")
assert os.path.exists(pdf_path), f"FAILED: PDF file does not exist at {pdf_path}"
reader = PdfReader(pdf_path)
pdf_text = "".join(page.extract_text() for page in reader.pages)
p(f"PDF page count: {len(reader.pages)}")
assert "smtp-starttls.pcap" in pdf_text, "FAILED: smtp-starttls.pcap not found in PDF text"
assert "TLS_RSA_WITH_RC4_128_SHA" in pdf_text or "RSA-RC4_128_SHA" in pdf_text, "FAILED: Cipher not in PDF text"
p("CONFIRMED: Generated PDF contains 'smtp-starttls.pcap' and live analysis results.")

# 10. Test persistence on subsequent interaction (e.g. rerunning without clicking button again)
p("Testing persistence across rerun...")
at.run()
assert at.session_state.get("live_data") is not None, "FAILED: live_data lost on rerun!"
captions_after = [c.value for c in at.caption]
assert any("smtp-starttls.pcap" in c for c in captions_after), "FAILED: caption reverted on rerun!"
p("CONFIRMED: live_data persists in session_state across reruns.")

p("=== ALL TESTS PASSED SUCCESSFULLY! ===")
