"""
smtp_good_client.py — Healthy SMTP client for the good capture.

Connects directly to the SMTP server (10025), issues STARTTLS,
and successfully completes the TLS handshake before sending mail.
"""
import smtplib

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 10025

def run_client():
    print("[client] Connecting to SMTP server directly ...", flush=True)
    smtp = smtplib.SMTP(SERVER_HOST, SERVER_PORT, timeout=10)
    smtp.set_debuglevel(2)

    smtp.ehlo("good-client.local")
    
    print("[client] Sending STARTTLS ...", flush=True)
    smtp.starttls()
    print("[client] STARTTLS succeeded — session is now encrypted.", flush=True)

    smtp.ehlo("good-client.local")
    
    try:
        smtp.login("user@corp.example.com", "Secret123!")
    except smtplib.SMTPException as exc:
        pass

    from_addr = "user@corp.example.com"
    to_addr   = "colleague@corp.example.com"
    body = (
        "From: user@corp.example.com\r\n"
        "To: colleague@corp.example.com\r\n"
        "Subject: Financials\r\n"
        "\r\n"
        "This is a securely encrypted message.\r\n"
    )
    smtp.sendmail(from_addr, [to_addr], body)
    print("[client] Message sent securely over TLS.", flush=True)
    smtp.quit()
    print("[client] Session complete.", flush=True)

if __name__ == "__main__":
    run_client()
