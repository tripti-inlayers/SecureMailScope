"""
run_attack_capture.py — Master orchestrator for the STARTTLS-stripping demo capture.

Steps:
  1. Generate self-signed TLS certificate (if not already present).
  2. Find the loopback interface via `tshark -D`.
  3. Start tshark capture -> tmp file.
  4. Start SMTP server (background thread).
  5. Start stripping proxy (background thread).
  6. Run SMTP client — completes the stripping attack exchange.
  7. Gracefully stop all components.
  8. Move capture to data/attack.pcap.
  9. Print a packet-count sanity check.

Run from the project root:
  python tools/run_attack_capture.py
"""
import os
import sys
import time
import subprocess
import threading
import shutil
import tempfile

# ---------------------------------------------------------------------- #
#  Paths                                                                   #
# ---------------------------------------------------------------------- #
HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
OUTPUT_PCAP  = os.path.join(DATA_DIR, "attack.pcap")

sys.path.insert(0, HERE)           # so we can import the tool modules
sys.path.insert(0, PROJECT_ROOT)   # for analyzer imports later


# ---------------------------------------------------------------------- #
#  Resolve tshark                                                          #
# ---------------------------------------------------------------------- #
def get_tshark():
    if shutil.which("tshark"):
        return "tshark"
    for p in [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]:
        if os.path.exists(p):
            return p
    raise FileNotFoundError("tshark not found. Install Wireshark first.")


# ---------------------------------------------------------------------- #
#  Find loopback interface                                                 #
# ---------------------------------------------------------------------- #
def find_loopback_interface(tshark_bin):
    """
    Returns the interface number/name tshark can use to capture loopback.
    On Windows with Npcap the loopback adapter is usually listed as
    '\\Device\\NPF_Loopback' or simply 'Loopback'.
    """
    res = subprocess.run(
        [tshark_bin, "-D"],
        capture_output=True, text=True, timeout=10
    )
    lines = res.stdout.strip().splitlines()
    print("[capture] Available interfaces:")
    for line in lines:
        print("  " + line)

    for line in lines:
        lower = line.lower()
        if "loopback" in lower or "npcap_loopback" in lower or "npf_loopback" in lower:
            # extract the number at the start:  "1. \Device\NPF_Loopback ..."
            iface = line.split(".")[0].strip()
            print(f"[capture] Selected loopback interface: {iface}")
            return iface

    # Fallback: pick interface 1 and warn
    print("[capture] WARNING: could not identify loopback interface; defaulting to '1'.")
    return "1"


# ---------------------------------------------------------------------- #
#  Step 1 — Certificate                                                    #
# ---------------------------------------------------------------------- #
def ensure_cert():
    cert = os.path.join(HERE, "server.crt")
    key  = os.path.join(HERE, "server.key")
    if not os.path.exists(cert) or not os.path.exists(key):
        print("[setup] Generating self-signed TLS certificate ...")
        import gen_cert
        gen_cert.generate()
    else:
        print("[setup] Certificate already present, skipping generation.")


# ---------------------------------------------------------------------- #
#  Main                                                                    #
# ---------------------------------------------------------------------- #
def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    tshark_bin = get_tshark()
    ensure_cert()

    # ------------------------------------------------------------------ #
    #  Find loopback interface                                             #
    # ------------------------------------------------------------------ #
    loopback_iface = find_loopback_interface(tshark_bin)

    # ------------------------------------------------------------------ #
    #  Start tshark capture                                                #
    # ------------------------------------------------------------------ #
    tmp_pcap = tempfile.mktemp(suffix=".pcap")
    tshark_filter = f"host 127.0.0.1 and (tcp port 10025 or tcp port 10026)"
    tshark_cmd = [
        tshark_bin,
        "-i", loopback_iface,
        "-f", tshark_filter,
        "-w", tmp_pcap,
    ]
    print(f"[capture] Starting tshark: {' '.join(tshark_cmd)}")
    tshark_proc = subprocess.Popen(
        tshark_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)   # let tshark initialise before traffic starts

    # ------------------------------------------------------------------ #
    #  Start SMTP server in a background thread                            #
    # ------------------------------------------------------------------ #
    import smtp_server
    import starttls_proxy

    server_stop = threading.Event()
    proxy_stop  = threading.Event()

    server_thread = threading.Thread(
        target=smtp_server.run_server,
        kwargs={"stop_event": server_stop},
        daemon=True,
    )
    proxy_thread = threading.Thread(
        target=starttls_proxy.run_proxy,
        kwargs={"stop_event": proxy_stop},
        daemon=True,
    )

    server_thread.start()
    time.sleep(0.8)
    proxy_thread.start()
    time.sleep(1.5)  # give proxy time to bind before client connects

    # ------------------------------------------------------------------ #
    #  Run the victim client (the attack exchange)                         #
    # ------------------------------------------------------------------ #
    print("\n[capture] === Running STARTTLS-stripping attack exchange ===\n")
    import smtp_client
    try:
        smtp_client.run_client()
    except Exception as exc:
        print(f"[client] Exception during send (may be non-fatal): {exc}")

    # ------------------------------------------------------------------ #
    #  Tear down                                                           #
    # ------------------------------------------------------------------ #
    time.sleep(1.0)   # let remaining packets flush through the socket

    server_stop.set()
    proxy_stop.set()
    server_thread.join(timeout=3)
    proxy_thread.join(timeout=3)

    # Stop tshark
    tshark_proc.terminate()
    try:
        tshark_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        tshark_proc.kill()

    time.sleep(0.5)

    # ------------------------------------------------------------------ #
    #  Move pcap to data/attack.pcap                                       #
    # ------------------------------------------------------------------ #
    if not os.path.exists(tmp_pcap) or os.path.getsize(tmp_pcap) == 0:
        print("[capture] ERROR: capture file is empty or missing!")
        print("          This usually means tshark could not open the loopback interface.")
        print("          Try running this script as Administrator.")
        sys.exit(1)

    shutil.move(tmp_pcap, OUTPUT_PCAP)
    print(f"\n[capture] Saved capture -> {OUTPUT_PCAP}")

    # ------------------------------------------------------------------ #
    #  Sanity-check: count SMTP packets                                    #
    # ------------------------------------------------------------------ #
    verify = subprocess.run(
        [
            tshark_bin,
            "-r", OUTPUT_PCAP,
            "-d", "tcp.port==10025,smtp",
            "-d", "tcp.port==10026,smtp",
            "-Y", "smtp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.stream",
            "-e", "smtp.req.line",
            "-e", "smtp.rsp.line",
        ],
        capture_output=True, text=True
    )
    lines = [l for l in verify.stdout.strip().splitlines() if l.strip()]
    print(f"[verify] {len(lines)} SMTP lines decoded in capture.")

    if lines:
        print("[verify] Sample (first 10 lines):")
        for l in lines[:10]:
            print("  " + l)
    else:
        print("[verify] WARNING: no SMTP lines decoded — check loopback capture permissions.")

    print("\n[capture] Done. Run the analyzer next:")
    print(f'  python analyzer/analyzer.py {OUTPUT_PCAP}')


if __name__ == "__main__":
    main()
