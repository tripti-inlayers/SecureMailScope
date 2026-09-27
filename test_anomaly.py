import sys
sys.path.insert(0, 'analyzer')
import anomaly_detector

# Three sessions: two healthy TLS 1.3, one plaintext attack
sessions = [
    {
        'session_id': 's1',
        'tls': {'detected': True, 'version': 'TLS 1.3', 'cipher_suite': 'TLS_AES_256_GCM_SHA384'},
        'certificate': {'present': True, 'expired': False},
        'risk': {'level': 'LOW', 'score': 10}
    },
    {
        'session_id': 's2',
        'tls': {'detected': True, 'version': 'TLS 1.3', 'cipher_suite': 'TLS_AES_128_GCM_SHA256'},
        'certificate': {'present': True, 'expired': False},
        'risk': {'level': 'LOW', 'score': 10}
    },
    {
        'session_id': 's3',
        'tls': {'detected': False, 'version': None, 'cipher_suite': None},
        'certificate': {'present': False, 'expired': None},
        'risk': {'level': 'HIGH', 'score': 100}
    },
]

result = anomaly_detector.run_anomaly_detection(sessions)

print('=== Acceptance Criteria Check ===')
all_non_null = True
for s in result:
    a = s['anomaly']
    ok = a['flagged'] is not None and a['anomaly_score'] is not None
    status = 'PASS' if ok else 'FAIL'
    print('  ' + s['session_id'] + ': flagged=' + str(a['flagged']) + ', score=' + str(a['anomaly_score']) + ', risk=' + s['risk']['level'] + ' -- ' + status)
    all_non_null = all_non_null and ok

attack_flagged = result[2]['anomaly']['flagged']
print('  Attack session anomaly flagged: ' + str(attack_flagged) + ' -- ' + ('PASS' if attack_flagged else 'FAIL'))

risk_unchanged = result[0]['risk']['level'] == 'LOW' and result[2]['risk']['level'] == 'HIGH'
print('  risk.level unchanged: ' + str(risk_unchanged) + ' -- ' + ('PASS' if risk_unchanged else 'FAIL'))

print()
final = all_non_null and attack_flagged and risk_unchanged
print('ALL PASS' if final else 'SOME CHECKS FAILED')
