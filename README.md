# 🛡️ PS159 — SecureMailScope

> **AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**  
> *Smart India Hackathon (SIH) Prototype*

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---
## 🚀 Live Demo

[SecureMailScope Dashboard](https://secure-mail-scope.streamlit.app/)

## 📌 Problem Statement

Email protocols (SMTP, IMAP, POP3) carry critical government, enterprise, and personal communications. While TLS encryption protects data in transit, legacy protocol designs rely heavily on opportunistic encryption (e.g. `STARTTLS`), which is inherently vulnerable to:
* **Active Man-in-the-Middle (MITM) STARTTLS Stripping attacks** (downgrading connections to cleartext).
* **Cleartext credential exposure** (`AUTH LOGIN` over plaintext).
* **Weak or deprecated cryptographic configurations** (TLS 1.0/1.1, SSLv3, RC4, 3DES, EXPORT ciphers).
* **Expired, missing, or misconfigured X.509 server certificates**.

Manual inspection of network traffic for cryptographic integrity is slow and requires deep protocol expertise. **SecureMailScope** automates passive cryptographic audits of email network captures.

---

## 🎯 What SecureMailScope Does

**SecureMailScope** is a specialized security posture analyzer that inspects email communication captures (PCAP/PCAPNG), reconstructs mail sessions, audits TLS/STARTTLS handshakes against NIST/RFC standards, runs ML-based anomaly detection, and produces actionable forensic reports.

```
[ Email Network Capture (.pcap) ]
               │
               ▼
[ Passive Protocol Dissector & Session Extractor ]
               │
               ├─────────────────────────────────────────┐
               ▼                                         ▼
   [ Cryptographic Rule Engine ]             [ ML Anomaly Detector ]
   • TLS 1.0–1.3 & Cipher Suite Auditing     • Isolation Forest (5D Vectors)
   • STARTTLS Negotiation & Stripping Check  • Unsupervised Outlier Scoring
   • X.509 Certificate Validity Check
   • Cleartext Credential Exposure Check
               │                                         │
               └────────────────────┬────────────────────┘
                                    ▼
                 [ Interactive Security Dashboard ]
                 • Executive Posture Metrics Cards
                 • Tabular Session Overview (Color-Coded)
                 • STARTTLS MITM Attack Step Sequence
                 • Actionable Remediation Guidance
                 • One-Click PDF & HTML Forensic Export
```

---

## 🔬 Prototype Scope vs. Full System

| Dimension | Hackathon Prototype (Current Scope) | Production / Future Scope |
| :--- | :--- | :--- |
| **Analysis Mode** | **Offline / Passive PCAP Analysis** of supplied network capture files | Continuous inline/SPAN port live capture & streaming alerting |
| **Protocol Support** | SMTP, IMAP, POP3 (Standard + Lab Test Ports) | Expanded to S/MIME, PGP, MTA-STS, DANE validation |
| **Execution Engine** | `tshark` PCAP dissector + Python Rule Engine + scikit-learn | High-speed eBPF packet capture engine + distributed microservices |
| **Deployment Mode** | Zero-dependency interactive web dashboard with precomputed & live PCAP modes | Enterprise SIEM/SOC integration & automated remediation webhooks |

> ⚠️ **Clarification:** The current prototype is an **offline / passive PCAP analyzer**. It does not perform continuous real-time network sniffing.

---

## ✨ Key Implemented Features

1. **Deterministic Cryptographic Evaluation:**
   * Audits TLS versions (TLS 1.3 / 1.2 vs deprecated TLS 1.1 / 1.0 / SSLv3).
   * Identifies weak cipher suites (RC4, 3DES, NULL, EXPORT, MD5).
   * Inspects X.509 certificate expiry and presence.
2. **Active STARTTLS Stripping Attack Detection:**
   * Correlates EHLO advertised capabilities against client `STARTTLS` commands and MITM error codes (e.g. `502 Command Not Implemented`).
   * Renders visual step-by-step MITM sequence diagrams.
3. **Cleartext Credential Exposure Detection:**
   * Flags insecure `AUTH LOGIN` transmissions conducted over plaintext.
4. **Unsupervised Behavioral Anomaly Detection (ML):**
   * Uses `scikit-learn` `IsolationForest` on multidimensional session vectors to highlight atypical sessions without modifying deterministic rule scores.
5. **Interactive Executive Dashboard:**
   * Session overview table with color-coded risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   * Granular session inspector with remediation recommendations.
6. **One-Click Forensic Report Exporter:**
   * Generates downloadable, audit-ready **PDF** and **HTML** security reports via Jinja2 & xhtml2pdf.

---

## 🛠️ Tech Stack

* **Frontend & Dashboard:** [Streamlit](https://streamlit.io/)
* **Data Processing & Analytics:** [Pandas](https://pandas.pydata.org/), [NumPy](https://numpy.org/)
* **Machine Learning:** [scikit-learn](https://scikit-learn.org/) (`IsolationForest`)
* **Packet Dissection & Inspection:** `tshark` (Wireshark CLI backend)
* **Reporting Engine:** [Jinja2](https://palletsprojects.com/p/jinja/), [xhtml2pdf](https://xhtml2pdf.readthedocs.io/)
* **Language:** Python 3.10+

---

## 📁 Project Structure

```
Project_59/
│
├── dashboard/
│   └── app.py                     # Streamlit web dashboard application
│
├── analyzer/
│   ├── analyzer.py                # Core PCAP parsing & extraction engine
│   ├── security_rules.py          # Cryptographic rule engine & risk grading
│   ├── anomaly_detector.py        # scikit-learn IsolationForest anomaly model
│   ├── report_exporter.py         # PDF & HTML report generation pipeline
│   └── templates/
│       └── report.html.j2         # Jinja2 template for forensic reports
│
├── data/                          # Raw sample PCAP capture files
│   ├── attack.pcap                # MITM STARTTLS stripping capture
│   ├── good.pcap                  # Clean modern TLS 1.3 session
│   ├── weak.pcap                  # Deprecated TLS / weak cipher capture
│   └── demo_full.pcap             # Multi-session mixed enterprise capture
│
├── sample_results/                # Precomputed JSON analysis results for instant demo
│   ├── attack.json
│   ├── good.json
│   ├── weak.json
│   ├── demo_full.json
│   └── reports/                   # Pre-rendered PDF & HTML forensic reports
│
├── tools/                         # Synthetic capture & test environment tools
│   ├── starttls_proxy.py          # MITM STARTTLS stripping proxy
│   ├── smtp_server.py             # Configurable SMTP test server
│   ├── smtp_client.py             # Automated SMTP test client
│   └── gen_cert.py                # Certificate generation script
│
├── packages.txt                   # Linux system dependencies (tshark) for Streamlit Cloud
├── requirements.txt               # Python package dependencies
├── .gitignore                     # Git exclusion rules
└── README.md                      # Project documentation & SIH reference
```

---

## 🚀 Running Locally

### 1. Prerequisites
* Python 3.10 or higher
* *(Optional for new PCAP analysis)*: [Wireshark / TShark](https://www.wireshark.org/) installed and in PATH.

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/<your-username>/SecureMailScope.git
cd SecureMailScope

# Create and activate virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Launch the Dashboard
```bash
streamlit run dashboard/app.py
```
Open your browser at `http://localhost:8501`.

---

## ☁️ Streamlit Cloud Deployment

The repository is structured to deploy directly to **Streamlit Community Cloud**:
* **Repository:** `<your-repo>`
* **Main file path:** `dashboard/app.py`
* **Python version:** `3.10+`
* **Dependencies:** Handled automatically via `requirements.txt` (Python) and `packages.txt` (`tshark` for Debian).

> **Judge-Ready Demo Resilience:** Even on cloud environments where raw packet capture privileges or tshark may be constrained, SecureMailScope provides full interactive demonstration across all attack and baseline scenarios via precomputed captures in `sample_results/`.

---

## ⚠️ Limitations & Future Work

* **Passive PCAP Inspection:** The prototype analyzes offline capture files; inline real-time blocking is reserved for future hardware/SPAN-port appliances.
* **Encrypted Payload Inspection:** By design, SecureMailScope evaluates cryptographic metadata, protocol commands, and handshake parameters without breaking end-to-end encryption.
* **Roadmap:** Integration of MTA-STS DNS record validation, DANE (RFC 6698) automated verification, and integration with enterprise SIEM solutions (Splunk, Elastic).
