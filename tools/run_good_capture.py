"""
run_good_capture.py — Orchestrator for the healthy STARTTLS demo capture.
"""
import os
import sys
import time
import subprocess
import threading
import shutil
import tempfile

HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
OUTPUT_PCAP  = os.path.join(DATA_DIR, "good.pcap")

sys.path.insert(0, HERE)
sys.path.insert(0, PROJECT_ROOT)

def get_tshark():
    if shutil.which("tshark"):
        return "tshark"
    for p in [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
        if os.path.exists(p):
            return p
    raise FileNotFoundError("tshark not found.")

def find_loopback_interface(tshark_bin):
    res = subprocess.run([tshark_bin, "-D"], capture_output=True, text=True, timeout=10)
    lines = res.stdout.strip().splitlines()
    for line in lines:
        lower = line.lower()
        if "loopback" in lower or "npcap_loopback" in lower or "npf_loopback" in lower:
            return line.split(".")[0].strip()
    return "1"

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    tshark_bin = get_tshark()

    loopback_iface = find_loopback_interface(tshark_bin)
    tmp_pcap = tempfile.mktemp(suffix=".pcap")
    
    tshark_cmd = [
        tshark_bin,
        "-i", loopback_iface,
        "-f", "host 127.0.0.1 and tcp port 10025",
        "-w", tmp_pcap,
    ]
    tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)

    import smtp_server
    server_stop = threading.Event()
    server_thread = threading.Thread(target=smtp_server.run_server, kwargs={"stop_event": server_stop}, daemon=True)
    server_thread.start()
    time.sleep(0.8)

    import smtp_good_client
    try:
        smtp_good_client.run_client()
    except Exception as exc:
        print(f"[client] Exception: {exc}")

    time.sleep(1.0)
    server_stop.set()
    server_thread.join(timeout=3)

    tshark_proc.terminate()
    try:
        tshark_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        tshark_proc.kill()
    time.sleep(0.5)

    shutil.move(tmp_pcap, OUTPUT_PCAP)
    print(f"\n[capture] Saved capture -> {OUTPUT_PCAP}")

if __name__ == "__main__":
    main()
