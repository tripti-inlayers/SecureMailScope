"""
smtp_client.py — Victim SMTP client for the STARTTLS-stripping demo.

Behaviour:
  1. Connects to the stripping proxy (127.0.0.1:10026).
  2. Issues EHLO — server responds with capabilities including STARTTLS.
  3. Attempts STARTTLS upgrade.
  4. Proxy returns 502 — smtplib raises SMTPNotSupportedError.
  5. Client catches the exception, re-issues EHLO, and continues the
     session in plaintext — transmitting credentials and message body
     in the clear.  This is the victim behaviour in a real stripping attack.

The debug level is set to 2 so the full SMTP conversation (including
the 502 rejection) is printed to stdout for verification.
"""
import smtplib
import sys

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 10026


def run_client():
    print("[client] Connecting to stripping proxy ...", flush=True)
    smtp = smtplib.SMTP(PROXY_HOST, PROXY_PORT, timeout=10)
    smtp.set_debuglevel(2)   # show every byte sent / received

    # Step 1: initial EHLO — we'll see "250-STARTTLS" in the server banner
    smtp.ehlo("victim-client.local")

    # Step 2: attempt STARTTLS upgrade
    try:
        print("[client] Sending STARTTLS ...", flush=True)
        smtp.starttls()
        # If we somehow reach here, the stripping attack is not in effect.
        print("[client] WARNING: STARTTLS succeeded — proxy is not stripping!", flush=True)
    except (smtplib.SMTPNotSupportedError, smtplib.SMTPException) as exc:
        # ------------------------------------------------------------------ #
        # This is the expected path.                                           #
        # The proxy returned 502 — smtplib raises SMTPNotSupportedError.      #
        # A poorly-coded mail client (or one with enforce_tls=False) will      #
        # silently fall back to plaintext here.                                #
        # ------------------------------------------------------------------ #
        print(f"[client] STARTTLS rejected by proxy ({exc}) — continuing in PLAINTEXT", flush=True)

    # Step 3: re-identify in plaintext and send the message
    smtp.ehlo("victim-client.local")

    # Step 4: authenticate in plaintext (credentials transmitted in the clear)
    try:
        smtp.login("victim@corp.example.com", "P@ssw0rd_SuperSecret!")
    except smtplib.SMTPException as exc:
        print(f"[client] AUTH failed (server may not require it): {exc}", flush=True)

    # Step 5: send a message — subject line makes the plaintext visible in pcap
    from_addr = "victim@corp.example.com"
    to_addr   = "attacker-reads-this@evil.example.com"
    body = (
        "From: victim@corp.example.com\r\n"
        "To: attacker-reads-this@evil.example.com\r\n"
        "Subject: [CONFIDENTIAL] Q3 Financial Report\r\n"
        "\r\n"
        "Hi,\n\n"
        "Please find attached the Q3 financial data.\n"
        "Password: P@ssw0rd_SuperSecret!\n\n"
        "This message is transmitted in PLAINTEXT because STARTTLS was stripped.\n"
    )
    smtp.sendmail(from_addr, [to_addr], body)
    print("[client] Message sent in PLAINTEXT — contents visible to attacker.", flush=True)

    smtp.quit()
    print("[client] Session complete.", flush=True)


if __name__ == "__main__":
    run_client()
