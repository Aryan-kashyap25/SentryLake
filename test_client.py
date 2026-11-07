from fastapi.testclient import TestClient
from main import app
import json

client = TestClient(app)

print("--- Testing GET / ---")
res_root = client.get("/")
print("GET / Status:", res_root.status_code)
assert res_root.status_code == 200
assert "SentryLake" in res_root.text

print("--- Testing POST /api/upload-and-scan ---")
with open("customer_transactions_dirty.csv", "rb") as f:
    res_upload = client.post("/api/upload-and-scan", files={"file": ("customer_transactions_dirty.csv", f, "text/csv")})

print("Upload Status:", res_upload.status_code)
if res_upload.status_code != 200:
    print("Error response:", res_upload.text)
assert res_upload.status_code == 200

data = res_upload.json()
s = data["summary"]
print(f"Total Records: {s['total_records']}")
print(f"PII Incidents: {s['pii_incidents']}")
print(f"PII Severity: {s['pii_severity']}")
print(f"Schema Drift Violations: {s['schema_drift_violations']}")
print(f"Compliance Score: {s['compliance_score']}%")
print(f"Frameworks Triggered: {json.dumps(s['frameworks_triggered'])}")

print("--- Testing GET /api/download-clean ---")
res_download = client.get("/api/download-clean")
print("Download Status:", res_download.status_code)
assert res_download.status_code == 200
print(f"Downloaded CSV size: {len(res_download.content)} bytes")
print("First 3 lines of sanitized CSV:")
for line in res_download.text.splitlines()[:4]:
    print("  ", line)

print("\n[SUCCESS] ALL FASTAPI ENDPOINTS PASSED VERIFICATION!")
