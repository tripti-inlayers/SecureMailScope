"""
smtp_server.py — Minimal raw-socket SMTP server with STARTTLS support.

Listens on 127.0.0.1:10025.
Advertises STARTTLS in its EHLO response.
Performs a real TLS upgrade when the client sends STARTTLS and the server
sees the 220 response acknowledged (normal path).

In the STARTTLS-stripping scenario the proxy intercepts the client's
STARTTLS command before it ever reaches this server, so the TLS branch
here is never triggered — the session stays in cleartext SMTP.

No third-party dependencies — stdlib only (socket, ssl, threading).
"""
import socket
import ssl
import threading
import os
import sys

SMTP_HOST = "127.0.0.1"
SMTP_PORT = 10025

HERE = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(HERE, "server.crt")
KEY_FILE  = os.path.join(HERE, "server.key")


def handle_client(conn, addr):
    """State-machine SMTP handler — handles one client connection."""
    print(f"[server] Connection from {addr}", flush=True)
    try:
        conn.sendall(b"220 localhost ESMTP SecureMailScope-TestServer\r\n")
        in_data = False
        data_buf = []

        while True:
            raw = conn.recv(4096)
            if not raw:
                break

            # Inside DATA body — buffer until lone dot
            if in_data:
                text = raw.decode(errors="replace")
                data_buf.append(text)
                if "\r\n.\r\n" in text or text.strip() == ".":
                    in_data = False
                    conn.sendall(b"250 OK: message queued\r\n")
                    print(f"[server] Message body received ({sum(len(x) for x in data_buf)} bytes)", flush=True)
                continue

            # Normal command processing — handle multiple pipelined commands
            for raw_line in raw.split(b"\r\n"):
                line = raw_line.decode(errors="replace").strip()
                if not line:
                    continue

                cmd = line.split()[0].upper() if line.split() else ""
                print(f"[server] << {line}", flush=True)

                if cmd in ("EHLO", "HELO"):
                    conn.sendall(
                        b"250-localhost\r\n"
                        b"250-SIZE 10240000\r\n"
                        b"250-AUTH LOGIN PLAIN\r\n"
                        b"250-STARTTLS\r\n"
                        b"250 OK\r\n"
                    )
                elif cmd == "STARTTLS":
                    conn.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
                    conn = ctx.wrap_socket(conn, server_side=True)
                    print("[server] TLS handshake complete", flush=True)
                elif cmd == "AUTH":
                    conn.sendall(b"235 2.7.0 Authentication successful\r\n")
                elif cmd == "MAIL":
                    conn.sendall(b"250 2.1.0 OK\r\n")
                elif cmd == "RCPT":
                    conn.sendall(b"250 2.1.5 OK\r\n")
                elif cmd == "DATA":
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    in_data = True
                elif cmd == "QUIT":
                    conn.sendall(b"221 2.0.0 Bye\r\n")
                    return
                elif cmd == "RSET":
                    conn.sendall(b"250 2.0.0 OK\r\n")
                elif cmd == "NOOP":
                    conn.sendall(b"250 2.0.0 OK\r\n")
                else:
                    conn.sendall(b"502 5.5.2 Error: command not recognized\r\n")
    except Exception as exc:
        print(f"[server] Connection error: {exc}", flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[server] Connection from {addr} closed", flush=True)


def run_server(stop_event=None):
    """Start the SMTP server. Blocks until stop_event is set or timeout."""
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[server] ERROR: server.crt / server.key not found. Run gen_cert.py first.", flush=True)
        sys.exit(1)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SMTP_HOST, SMTP_PORT))
    srv.listen(10)
    srv.settimeout(1.0)
    print(f"[server] Listening on {SMTP_HOST}:{SMTP_PORT}", flush=True)

    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            try:
                conn, addr = srv.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
    finally:
        srv.close()
        print("[server] Stopped.", flush=True)


if __name__ == "__main__":
    run_server()
