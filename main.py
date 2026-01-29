import pandas as pd
from utils.loader import load_alerts
from agents.severity_agent import classify_alert_severity
from agents.threat_agent import analyze_threat_behavior
from agents.mitigation_agent import recommend_mitigation_actions
from ethics.rules import ethical_severity_check

df = load_alerts("data/alertLogs.jsonl")
df_test = df.head(3)

results = []

for _, row in df_test.iterrows():
    severity = classify_alert_severity.run(row["rule_text"])
    threat = analyze_threat_behavior.run(row["rule_text"])
    mitigation = recommend_mitigation_actions.run(row["rule_text"])

    final_severity = ethical_severity_check(
        severity, threat.get("confidence", 0.0)
    )

    results.append({
        "rule_id": row["rule_id"],
        "rule_name": row.get("rule_name"),
        "ai_severity": final_severity,
        "confidence": threat.get("confidence"),
        "recommended_actions": mitigation.get("recommended_actions")
    })

df_results = pd.DataFrame(results)
df_results.to_json("validated_alerts.json", indent=2)
print(df_results)
