TLS_VERSION_MAP = {
    "0x0304": "TLS 1.3",
    "772": "TLS 1.3",
    "0x0303": "TLS 1.2",
    "771": "TLS 1.2",
    "0x0302": "TLS 1.1",
    "770": "TLS 1.1",
    "0x0301": "TLS 1.0",
    "769": "TLS 1.0",
    "0x0300": "SSLv3",
    "768": "SSLv3",
    "0x0200": "SSLv2",
    "512": "SSLv2",
}

CIPHER_SUITE_MAP = {
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0x1304": "TLS_AES_128_CCM_SHA256",
    "0x1305": "TLS_AES_128_CCM_8_SHA256",
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
    "0x0004": "TLS_RSA_WITH_RC4_128_MD5",
    "0x0003": "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "0x0000": "TLS_NULL_WITH_NULL_NULL",
}

def normalize_tls_version(raw_ver, raw_cipher=None):
    if not raw_ver:
        return None
    val = str(raw_ver).strip()
    val_lower = val.lower()
    
    if val_lower in ["0x0303", "771"] and raw_cipher:
        c_str = str(raw_cipher).lower()
        if any(c in c_str for c in ["0x1301", "0x1302", "0x1303", "tls_aes", "chacha20"]):
            return "TLS 1.3"
            
    if val_lower in TLS_VERSION_MAP:
        return TLS_VERSION_MAP[val_lower]
        
    if "tls" in val_lower or "ssl" in val_lower:
        return val
        
    return val

def normalize_cipher_suite(raw_cipher):
    if not raw_cipher:
        return None
    val = str(raw_cipher).strip()
    if "," in val:
        val = val.split(",")[0].strip()
    val_lower = val.lower()
    if val_lower in CIPHER_SUITE_MAP:
        return CIPHER_SUITE_MAP[val_lower]
    if val_lower.startswith("0x"):
        return CIPHER_SUITE_MAP.get(val_lower, f"Unknown ({val})")
    return val

def grade_tls(tls):
    if not tls or not tls.get("detected"):
        return "HIGH", "No TLS detected — session in plaintext"
    ver = tls.get("version")
    if ver in ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"]:
        return "HIGH", f"Deprecated TLS version: {ver}"
    
    weak_markers = ["RC4", "3DES", "DES", "EXPORT", "NULL", "MD5"]
    cipher = tls.get("cipher_suite") or ""
    if any(w in cipher.upper() for w in weak_markers):
        return "HIGH", f"Weak cipher suite: {cipher}"
        
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

