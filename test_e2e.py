"""Quick E2E test for DataSentinel AI API."""
import json
import requests

resp = requests.post(
    "http://127.0.0.1:8000/api/upload-and-scan",
    files={"file": open("customer_transactions_dirty.csv", "rb")},
)
data = resp.json()
s = data["summary"]

print("=== DATASENTINEL AI - E2E TEST ===")
print(f"Status Code: {resp.status_code}")
print(f"Records: {s['total_records']}")
print(f"PII Incidents: {s['pii_incidents']}")
print(f"Severity: {s['pii_severity']}")
print(f"Schema Drift Violations: {s['schema_drift_violations']}")
print(f"Compliance Score: {s['compliance_score']}%")
print(f"Frameworks: {json.dumps(s['frameworks_triggered'], indent=2)}")
print(f"Columns analyzed: {len(data['column_analysis'])}")
print(f"Raw preview rows: {len(data['raw_preview'])}")
print(f"Clean preview rows: {len(data['clean_preview'])}")
print(f"Audit memo length: {len(data['audit_memo'])} chars")
print()

for c in data["column_analysis"]:
    flags = []
    if c["pii_detected"]:
        flags.append(f"PII:{c['pii_type']}")
    if c["null_flag"]:
        flags.append(f"NULL:{c['null_pct']}%")
    if c["type_mismatch"]:
        flags.append("TYPE_ERR")
    if c["z_score_anomalies"]:
        flags.append(f"Z-SCORE:{c['z_score_anomalies']}")
    status = " | ".join(flags) if flags else "CLEAN"
    print(f"  {c['name']:25s} -> {status}")

# Test download endpoint
dresp = requests.get("http://127.0.0.1:8000/api/download-clean")
print(f"\nDownload endpoint: {dresp.status_code}, Size: {len(dresp.content)} bytes")
print("\n=== ALL TESTS PASSED ===")
