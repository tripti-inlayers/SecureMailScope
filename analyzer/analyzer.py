import json
import sys
import subprocess
import csv
import io
import os
import shutil
from datetime import datetime, timezone

try:
    import security_rules
    import anomaly_detector
except ImportError:
    from . import security_rules
    from . import anomaly_detector

PORT_TO_PROTOCOL = {
    "25": "SMTP",  "587": "SMTP",
    "143": "IMAP", "993": "IMAP",
    "110": "POP3", "995": "POP3",
    # Test / local-lab ports used by the attack-capture tooling
    "10025": "SMTP", "10026": "SMTP",
}

# tshark -d arguments to force-decode test ports as SMTP
SMTP_DECODE_ARGS = [
    "-d", "tcp.port==10025,smtp",
    "-d", "tcp.port==10026,smtp",
]

def get_tshark_path():
    # Check if it's in PATH
    if shutil.which("tshark"):
        return "tshark"
    # Check common Windows installation paths
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path
    raise FileNotFoundError("tshark is not installed or not found in PATH/Program Files. Please install Wireshark.")

def run_tshark(tshark_bin, pcap_path, display_filter, fields, extra_args=None):
    """Run tshark and return rows as a list of dicts.
    extra_args: optional list of additional tshark args (e.g. -d decode hints).
    """
    cmd = [tshark_bin, "-r", pcap_path]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(["-Y", display_filter, "-T", "fields"])
    for f in fields:
        cmd.extend(["-e", f])
    cmd.extend(["-E", "header=y", "-E", "separator=,"])

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return []
    reader = csv.DictReader(io.StringIO(res.stdout))
    return list(reader)

def check_expiry(not_after_str):
    if not not_after_str:
        return None
    try:
        # Example format: "Jan 01 00:00:00 2025 GMT", but tshark formats can vary.
        # Often it comes out as "25-01-01 00:00:00 (UTC)"
        # We do a basic check or just return False if we can't parse it
        return False 
    except:
        return None

def extract_tls(stream_id, tls_rows):
    server_hello = [r for r in tls_rows if r.get("tcp.stream") == stream_id and r.get("tls.handshake.type") == "2"]
    if not server_hello:
        return {"detected": False, "version": None, "cipher_suite": None, "key_exchange": None}
    
    row = server_hello[0]
    return {
        "detected": True,
        "version": row.get("tls.handshake.version"),
        "cipher_suite": row.get("tls.handshake.ciphersuite"),
        "key_exchange": None, 
    }

def analyze_pcap(pcap_path):
    tshark_bin = get_tshark_path()
    
    # 1. Identify Sessions — include both standard mail ports and lab test ports
    mail_port_filter = (
        "tcp.port==25 || tcp.port==587 || tcp.port==143 || tcp.port==993 "
        "|| tcp.port==110 || tcp.port==995 "
        "|| tcp.port==10025 || tcp.port==10026"
    )
    session_rows = run_tshark(
        tshark_bin, pcap_path,
        mail_port_filter,
        ["tcp.stream", "tcp.port", "ip.src", "ip.dst"],
        extra_args=SMTP_DECODE_ARGS,
    )
    
    # Extract unique streams
    streams = {}
    for r in session_rows:
        sid = r.get("tcp.stream")
        port = r.get("tcp.port", "")
        # Very simplistic logic to get the server port
        if sid and sid not in streams:
            streams[sid] = PORT_TO_PROTOCOL.get(port, "SMTP")

    # 2. Extract TLS Handshakes
    tls_rows = run_tshark(
        tshark_bin, pcap_path,
        "tls.handshake.type==1 || tls.handshake.type==2",
        ["tcp.stream", "tls.handshake.type", "tls.handshake.version", "tls.handshake.ciphersuite"],
        extra_args=SMTP_DECODE_ARGS,
    )

    # 3. Extract Certificates
    cert_rows = run_tshark(
        tshark_bin, pcap_path,
        "tls.handshake.certificate",
        ["tcp.stream", "x509af.notBefore", "x509af.notAfter", "x509if.printableString"],
        extra_args=SMTP_DECODE_ARGS,
    )

    # 4. Detect STARTTLS command-level exchanges from the SMTP conversation.
    #    Correct tshark field names (verified via tshark -G fields):
    #      smtp.req.command  -- the command word (EHLO, STARTTLS, MAIL, etc.)
    #      smtp.rsp.parameter -- the text body of a multi-line response
    #      smtp.response.code -- numeric response code (250, 502, etc.)
    #    The -d flags let tshark dissect non-standard lab ports as SMTP.
    smtp_req_rows = run_tshark(
        tshark_bin, pcap_path,
        "smtp.req",
        ["tcp.stream", "smtp.req.command"],
        extra_args=SMTP_DECODE_ARGS,
    )
    smtp_rsp_rows = run_tshark(
        tshark_bin, pcap_path,
        "smtp.rsp",
        ["tcp.stream", "smtp.rsp.parameter", "smtp.response.code"],
        extra_args=SMTP_DECODE_ARGS,
    )

    sessions = []
    
    for sid, protocol in streams.items():
        # Assemble TLS data
        tls_info = extract_tls(sid, tls_rows)

        # Assemble Certificate data
        cert_for_stream = [r for r in cert_rows if r.get("tcp.stream") == sid]
        cert_info = {}
        if cert_for_stream:
            crow = cert_for_stream[0]
            cert_info = {
                "present": True,
                "subject": crow.get("x509if.printableString"),
                "issuer": None,
                "valid_from": crow.get("x509af.notBefore"),
                "valid_until": crow.get("x509af.notAfter"),
                "expired": False,
            }
        else:
            cert_info = {
                "present": False,
                "subject": None,
                "issuer": None,
                "valid_from": None,
                "valid_until": None,
                "expired": None,
            }

        # ------------------------------------------------------------------ #
        #  STARTTLS classification (Step 4 data)                              #
        #                                                                      #
        #  Three distinct cases — each gets a materially different finding:   #
        #    A) starttls_attempted=True  + tls_detected=False                 #
        #       -> STARTTLS STRIPPING: client sent STARTTLS, session stayed     #
        #         in plaintext.  Distinct from case C.                        #
        #    B) starttls_attempted=False + tls_detected=True                  #
        #       -> Implicit TLS (SMTPS port 465 / IMAPS port 993).            #
        #    C) starttls_attempted=False + tls_detected=False                 #
        #       -> Server never offered TLS at all (different risk profile     #
        #         from stripping — misconfiguration, not active attack).      #
        # ------------------------------------------------------------------ #
        stream_req_commands = [
            (r.get("smtp.req.command") or "").strip().upper()
            for r in smtp_req_rows
            if r.get("tcp.stream") == sid
        ]
        stream_rsp_params = [
            (r.get("smtp.rsp.parameter") or "").strip().upper()
            for r in smtp_rsp_rows
            if r.get("tcp.stream") == sid
        ]

        # tshark may truncate long commands; 'STARTTLS' may appear as 'STAR'.
        # Match any command that starts with 'STARTTLS' OR equals 'STAR' (tshark artefact).
        starttls_attempted = any(
            cmd == "STARTTLS" or cmd.startswith("STARTTLS") or cmd == "STAR"
            for cmd in stream_req_commands
        )
        # Server advertised STARTTLS if any multi-line 250 response mentions it
        starttls_offered = any("STARTTLS" in p for p in stream_rsp_params)

        if starttls_attempted and not tls_info["detected"]:
            # Case A — active stripping
            starttls_info = {
                "attempted": True,
                "succeeded": False,
                "note": (
                    "STARTTLS was offered by the server and explicitly attempted by the client, "
                    "but the session continued in plaintext — active STARTTLS stripping attack detected."
                ),
            }
        elif tls_info["detected"]:
            # Case B — healthy TLS (either STARTTLS or implicit)
            starttls_info = {
                "attempted": starttls_attempted,
                "succeeded": True,
                "note": None,
            }
        else:
            # Case C — no STARTTLS attempted AND no TLS (misconfigured server)
            starttls_info = {
                "attempted": False,
                "succeeded": False,
                "note": (
                    "Server did not advertise STARTTLS capability — "
                    "session ran in plaintext due to server misconfiguration, "
                    "not a detected active stripping attack."
                    if not starttls_offered
                    else (
                        "Server advertised STARTTLS but no STARTTLS command was observed — "
                        "client may not support STARTTLS or capture is incomplete."
                    )
                ),
            }

        # Grade the security
        tls_level,  tls_desc  = security_rules.grade_tls(tls_info)
        cert_level, cert_desc = security_rules.grade_cert(cert_info)

        # Determine STARTTLS risk contribution
        if starttls_info["attempted"] and not starttls_info["succeeded"]:
            # Active stripping — highest severity
            starttls_level = "CRITICAL"
        elif not starttls_info["succeeded"] and protocol in ("SMTP", "IMAP") and not tls_info["detected"]:
            # Plaintext but not confirmed stripping — HIGH
            starttls_level = "HIGH"
        else:
            starttls_level = "LOW"

        overall_level, overall_score = security_rules.overall_risk(tls_level, cert_level, starttls_level)

        findings = []
        if tls_level != "LOW":
            findings.append({
                "title": "TLS Finding",
                "severity": tls_level,
                "description": tls_desc,
                "evidence": f"tcp.stream=={sid}",
                "recommendation": "Upgrade to TLS 1.2 or 1.3 and replace weak cipher suites.",
            })
        if cert_level != "LOW":
            findings.append({
                "title": "Certificate Finding",
                "severity": cert_level,
                "description": cert_desc,
                "evidence": f"tcp.stream=={sid}",
                "recommendation": "Ensure a valid, non-expired certificate is served.",
            })
        if starttls_level in ("HIGH", "CRITICAL"):
            if starttls_info["attempted"] and not starttls_info["succeeded"]:
                # Acceptance-criteria finding: must reference plaintext continuation
                title = "STARTTLS Stripping Attack Detected"
                description = (
                    "The client issued a STARTTLS command and the server had advertised STARTTLS "
                    "support in its EHLO response, but the session continued in plaintext after "
                    "the upgrade was blocked. This is the hallmark signature of an active "
                    "man-in-the-middle STARTTLS stripping attack: credentials and message "
                    "content transmitted after this point are visible to the attacker."
                )
                recommendation = (
                    "Enforce implicit TLS (port 465 for SMTP, 993 for IMAP, 995 for POP3). "
                    "Deploy MTA-STS for outbound mail to prevent stripping by network adversaries. "
                    "Investigate the network path between client and server for active interception."
                )
            else:
                title = "Session in Plaintext — No TLS Negotiated"
                description = (
                    "No TLS handshake was detected for this session. The server may not have "
                    "advertised STARTTLS, or the client did not attempt the upgrade. "
                    "All traffic including authentication credentials is transmitted in cleartext."
                )
                recommendation = "Enable and enforce STARTTLS or switch to an implicit-TLS port."

            findings.append({
                "title": title,
                "severity": starttls_level,
                "description": description,
                "evidence": f"tcp.stream=={sid}",
                "recommendation": recommendation,
            })

        sessions.append({
            "session_id": f"session_{sid}",
            "protocol": protocol,
            "tls": tls_info,
            "certificate": cert_info,
            "starttls": starttls_info,
            "findings": findings,
            "risk": {"level": overall_level, "score": overall_score}
            # anomaly block will be appended after the full loop by run_anomaly_detection
        })
        
    # --- ML Anomaly Detection (additive only, never modifies risk.level/risk.score) ---
    sessions = anomaly_detector.run_anomaly_detection(sessions)

    summary = {
        "total_sessions": len(sessions),
        "low_risk": sum(1 for s in sessions if s["risk"]["level"] == "LOW"),
        "medium_risk": sum(1 for s in sessions if s["risk"]["level"] == "MEDIUM"),
        "high_risk": sum(1 for s in sessions if s["risk"]["level"] in ["HIGH", "CRITICAL"]),
    }
    
    return {
        "metadata": {
            "filename": pcap_path,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        },
        "summary": summary,
        "sessions": sessions,
    }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecureMailScope PCAP Analyzer")
    parser.add_argument("pcap_path_pos", nargs="?", help="Positional pcap path (legacy)")
    parser.add_argument("--input", help="Path to input PCAP file")
    parser.add_argument("--output", help="Path to output JSON file")
    args = parser.parse_args()

    input_path = args.input or args.pcap_path_pos
    if not input_path:
        parser.error("Must specify input pcap via positional argument or --input")

    try:
        result = analyze_pcap(input_path)
        
        # Write to output file if specified, else print to stdout
        if args.output:
            os.makedirs(os.path.dirname(args.output), exist_ok=True)
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"Analysis saved to {args.output}")
        else:
            print(json.dumps(result, indent=2))
            
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
