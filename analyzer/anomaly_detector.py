from sklearn.ensemble import IsolationForest
import numpy as np

# This module is intentionally isolated — it must NOT import security_rules.py
# and must NOT modify any risk.level or risk.score fields produced by the rule engine.

TLS_VERSION_ORDINAL = {
    None: 0, "SSLv3": 1, "TLS 1.0": 2, "TLS 1.1": 3,
    "TLS 1.2": 4, "TLS 1.3": 5,
}

WEAK_CIPHER_MARKERS = ["RC4", "DES", "EXPORT", "NULL", "MD5"]


def session_to_features(session):
    """Turn one session dict into a fixed-length numeric feature vector.

    Every feature must degrade gracefully to a neutral default if the
    underlying field is null -- never raise, never fabricate meaning.

    Feature vector layout (5 dimensions):
      [0] version_score  — ordinal TLS version rank (0=no TLS, 5=TLS 1.3)
      [1] weak_cipher    — 1 if cipher suite contains a known-weak marker
      [2] cert_present   — 1 if a certificate was observed in the handshake
      [3] cert_expired   — 1 if the certificate has expired
      [4] tls_detected   — 1 if any TLS handshake was detected at all
    """
    tls = session.get("tls") or {}
    cert = session.get("certificate") or {}

    version_score = TLS_VERSION_ORDINAL.get(tls.get("version"), 0)

    cipher = tls.get("cipher_suite") or ""
    weak_cipher = 1 if any(m in cipher for m in WEAK_CIPHER_MARKERS) else 0

    cert_present = 1 if cert.get("present") else 0
    cert_expired = 1 if cert.get("expired") else 0
    tls_detected = 1 if tls.get("detected") else 0

    return [version_score, weak_cipher, cert_present, cert_expired, tls_detected]


def run_anomaly_detection(sessions):
    """Adds an 'anomaly' block to each session dict IN PLACE.

    Requires >= 3 sessions to be statistically meaningful; below that,
    explicitly mark as not-applicable rather than guessing.

    The rule-based 'risk.level' and 'risk.score' fields are NEVER touched.
    The anomaly block is purely additive.
    """
    if len(sessions) < 3:
        for s in sessions:
            s["anomaly"] = {
                "flagged": None,
                "anomaly_score": None,
                "note": "Not enough sessions in this capture for anomaly detection (need >= 3)"
            }
        return sessions

    X = np.array([session_to_features(s) for s in sessions])

    model = IsolationForest(contamination="auto", random_state=42)
    predictions = model.fit_predict(X)   # -1 = anomaly, 1 = normal
    scores = model.decision_function(X)  # lower = more anomalous

    for s, pred, score in zip(sessions, predictions, scores):
        s["anomaly"] = {
            "flagged": bool(pred == -1),
            "anomaly_score": round(float(score), 4),
            "note": None
        }

    return sessions
