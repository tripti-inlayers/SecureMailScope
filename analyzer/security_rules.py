def grade_tls(tls):
    if not tls or not tls.get("detected"):
        return "HIGH", "No TLS detected — session in plaintext"
    if tls["version"] in ["SSLv3", "TLS 1.0", "TLS 1.1"]:
        return "HIGH", f"Deprecated TLS version: {tls['version']}"
    
    weak_markers = ["RC4", "DES", "EXPORT", "NULL", "MD5"]
    if tls.get("cipher_suite") and any(w in tls["cipher_suite"] for w in weak_markers):
        return "HIGH", f"Weak cipher suite: {tls['cipher_suite']}"
        
    return "LOW", "Modern TLS version and cipher"

def grade_cert(cert):
    if not cert or not cert.get("present"):
        return "MEDIUM", "No certificate found in handshake"
    if cert.get("expired"):
        return "HIGH", "Certificate expired"
    return "LOW", "Certificate present and valid"

def overall_risk(tls_level, cert_level, starttls_level="LOW"):
    levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    worst = max([tls_level, cert_level, starttls_level], key=lambda l: levels.get(l, 1))
    scores = {"LOW": 15, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}
    return worst, scores[worst]
