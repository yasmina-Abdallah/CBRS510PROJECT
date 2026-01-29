from agents.severity_agent import classify_alert_severity
from agents.threat_agent import analyze_threat_behavior
from agents.mitigation_agent import recommend_mitigation_actions
from ethics.rules import ethical_validator, generate_rationale, ethical_severity_check

CONFIDENCE_MAPPING = {
    "Low": 0.3,
    "Medium": 0.6,
    "High": 0.9
}

# Manual category → OWASP Top 10 mapping
CATEGORY_TO_OWASP = {
    "Malware": "A09: Security Logging & Monitoring Failures",
    "Ransomware": "A08: Software & Data Integrity Failures",
    "Trojan": "A07: Identification & Authentication Failures",
    "RAT": "A10: Server-Side Request Forgery / Misconfig",
    "Banker": "A07: Identification & Authentication Failures",
    "Webshell": "A03: Injection",
    "Botnet": "A05: Security Misconfiguration",
    "Exploit": "A06: Vulnerable & Outdated Components",
    "Cryptominer": "A02: Cryptographic Failures",
    "Benign": None
}

# Optional: specific rule → OWASP mapping
OWASP_MAPPING = {
    # Example: "WebShell_PHP": "A03: Injection"
}

def map_owasp_dynamic(rule_name: str, category: str, rationale: str):
    """Automatically detect OWASP risk based on keywords in rule_name, category, or AI rationale."""
    keywords = {
        "ransomware": "A08: Software & Data Integrity Failures",
        "trojan": "A07: Identification & Authentication Failures",
        "rat": "A10: Server-Side Request Forgery / Misconfig",
        "exploit": "A06: Vulnerable & Outdated Components",
        "webshell": "A03: Injection",
        "botnet": "A05: Security Misconfiguration",
        "malware": "A09: Security Logging & Monitoring Failures",
        "cryptominer": "A02: Cryptographic Failures"
    }
    combined_text = f"{rule_name} {category} {rationale}".lower()
    for k, v in keywords.items():
        if k in combined_text:
            return v
    return None


def process_alerts_with_agents(alerts: list) -> list[dict]:
    results = []

    for alert in alerts:
        rule_text = alert.get("rule_text", "")
        severity_input = alert.get("severity", "Unknown")
        rule_name = alert.get("rule_name", "")
        category = alert.get("category", "")

        # --- Classify severity ---
        severity_result = classify_alert_severity.invoke({
            "alert_text": rule_text,
            "original_severity": severity_input
        })

        raw_conf = severity_result.get("confidence", 0.0)
        confidence = CONFIDENCE_MAPPING.get(raw_conf, raw_conf)
        confidence = float(confidence)

        ai_rationale = severity_result.get("rationale", "No rationale provided")
        final_severity = ethical_severity_check(severity_result, confidence)

        severity_output = {
            "ai_severity": final_severity,
            "rationale": ai_rationale
        }

        # --- Ethical validation ---
        ethics = ethical_validator(
            severity_output,
            {"confidence": confidence},
            recommend_mitigation_actions.invoke({"alert_text": rule_text})
        )

        rationale_summary = generate_rationale(severity_output, confidence)

        # --- Threat intelligence ---
        threat_result = analyze_threat_behavior.invoke({
            "alert_text": rule_text
        })

        # --- Mitigation actions ---
        mitigation_result = recommend_mitigation_actions.invoke({
            "alert_text": rule_text
        })

        # --- OWASP Mapping ---
        owasp_risk = (
            OWASP_MAPPING.get(rule_name)
            or CATEGORY_TO_OWASP.get(category)
            or map_owasp_dynamic(rule_name, category, ai_rationale)
        )

        results.append({
            "rule_id": alert.get("rule_id"),
            "rule_name": rule_name,
            "category": category,
            "ai_severity": final_severity,
            "priority": mitigation_result.get("priority", final_severity),
            "suspicious_processes": ", ".join(threat_result.get("suspicious_processes", [])),
            "network_connections": ", ".join(threat_result.get("network_connections", [])),
            "user_behavior": threat_result.get("user_behavior", "Unknown"),
            "confidence": confidence,
            "recommended_actions": mitigation_result.get("recommended_actions", []),
            "bias": ethics["bias"],
            "transparency": ethics["transparency"],
            "accountability": ethics["accountability"],
            "privacy": ethics["privacy"],
            "rationale_summary": rationale_summary,
            "owasp_risk": owasp_risk
        })

    return results
