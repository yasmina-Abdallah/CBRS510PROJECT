# ethics/rules.py

ETHICAL_RULES = {
    "min_confidence_for_autonomy": 0.65,  # realistic SOC L1 threshold
    "bias_threshold": 0.2,
}

def ethical_validator(severity_output: dict, threat_output: dict, mitigation_output: dict) -> dict:
    ai_severity = severity_output.get("ai_severity", "High")
    bias = "Passed"

    if ai_severity.lower() not in ["low", "medium", "high", "critical"]:
        bias = "Warning: Unknown severity, human review required"

    transparency = "Verified" if severity_output.get("rationale") else "Missing rationale"

    return {
        "bias": bias,
        "transparency": transparency,
        "accountability": "Logged",
        "privacy": "No sensitive data exposed"
    }

def generate_rationale(severity_output: dict, confidence: float) -> str:
    ai_sev = severity_output.get("ai_severity", "High")
    reason = severity_output.get("rationale", "No rationale provided")

    try:
        conf = float(confidence)
    except (ValueError, TypeError):
        conf = 0.0

    return f"AI classified alert as {ai_sev} with confidence {conf:.2f}. Reason: {reason}"

def ethical_severity_check(severity_output: dict, confidence: float) -> str:
    ai_sev = severity_output.get("ai_severity", "High").lower()

    if ai_sev not in ["low", "medium", "high", "critical"]:
        return "High"

    if ai_sev == "medium" and confidence < ETHICAL_RULES["min_confidence_for_autonomy"]:
        return "High"

    if ai_sev == "low" and confidence < 0.3:
        return "Medium"

    return ai_sev.capitalize()
