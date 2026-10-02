import json

for name in ['attack', 'demo_full', 'good', 'weak']:
    with open(f'sample_results/{name}.json') as f:
        d = json.load(f)
    summary = d['summary']
    sessions = d['sessions']
    total = summary["total_sessions"]
    low = summary["low_risk"]
    med = summary.get("medium_risk", 0)
    high = summary["high_risk"]
    print(f"=== {name}.json === Sessions:{total} Low:{low} Med:{med} High:{high}")
    for s in sessions:
        tls = s.get('tls') or {}
        st = s.get('starttls') or {}
        risk = s.get('risk') or {}
        anom = s.get('anomaly') or {}
        sid = s["session_id"]
        proto = s.get("protocol")
        ver = tls.get("version")
        cipher = tls.get("cipher_suite")
        rlevel = risk.get("level")
        rscore = risk.get("score")
        stripped = st.get("attempted") and not st.get("succeeded")
        flagged = anom.get("flagged")
        findings = [f['title'] for f in s.get('findings', [])]
        print(f"  [{sid}] {proto} {ver} {cipher} {rlevel}({rscore}) stripped={stripped} anomaly={flagged}")
        for fn in findings:
            print(f"    -> {fn}")
    print()
