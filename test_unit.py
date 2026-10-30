import io
import json
import pandas as pd
from main import (
    detect_column_pii,
    check_null_spike,
    check_type_mismatch,
    check_zscore_anomalies,
    sanitize_column,
    compute_compliance_score,
    map_frameworks,
    generate_audit_memo,
    app
)

print("--- Testing Unit Functions on customer_transactions_dirty.csv ---")
df = pd.read_csv("customer_transactions_dirty.csv")
print("Total Rows:", len(df))

col_results = []
clean_df = df.copy()
total_pii_detections = 0
drift_violations = 0

for col in df.columns:
    series = df[col]
    pii = detect_column_pii(series, col)
    null = check_null_spike(series)
    tm = check_type_mismatch(series)
    z = check_zscore_anomalies(series)
    has_drift = null["null_flag"] or tm["type_mismatch"] or z > 0
    if has_drift:
        drift_violations += 1
    
    if pii["pii_detected"]:
        total_pii_detections += pii["detection_count"]
        clean_df[col] = sanitize_column(clean_df[col], pii["pii_type"])
    
    res = {
        "name": col,
        "pii_detected": pii["pii_detected"],
        "pii_type": pii["pii_type"],
        "pii_method": pii["pii_method"],
        "detection_count": pii["detection_count"],
        "null_pct": null["null_pct"],
        "null_flag": null["null_flag"],
        "type_mismatch": tm["type_mismatch"],
        "type_mismatch_detail": tm["type_mismatch_detail"],
        "z_score_anomalies": z,
        "drift_flag": has_drift,
    }
    col_results.append(res)
    print(f"Col: {col:<22} | PII: {str(pii['pii_detected']):<5} ({pii['pii_type']}) | Null: {null['null_pct']}% | Drift: {has_drift}")

score, severity = compute_compliance_score(col_results)
frameworks = map_frameworks(col_results)
print(f"\nCompliance Score: {score}% ({severity})")
print(f"Frameworks Triggered: {frameworks}")

memo = generate_audit_memo(
    total_records=len(df),
    pii_incidents=total_pii_detections,
    pii_columns=col_results,
    drift_violations=drift_violations,
    score=score,
    severity=severity,
    frameworks=frameworks
)
print("Audit memo generated, length:", len(memo))
print("Unit tests completed successfully!")
