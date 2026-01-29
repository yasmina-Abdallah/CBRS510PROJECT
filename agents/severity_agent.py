from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from llm.gemini import get_llm
from utils.json_utils import extract_json

llm = get_llm()

@tool(description="Classifies alert severity ethically for SOC Level-1 alerts")
def classify_alert_severity(alert_text: str, original_severity: str = "Unknown") -> dict:
    # Define the prompt with escaped JSON braces
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         "You are a SOC Level 1 cybersecurity analyst.\n"
         "Rules:\n"
         "- Explicit malware execution → High\n"
         "- Malware detection rule only → Medium\n"
         "- Suspicious behavior → Medium\n"
         "- Benign software → Low\n"
         "- ALWAYS explain why\n\n"
         "Return ONLY valid JSON:\n"
         "{{"  # Escaped brace
         "\"ai_severity\":\"Low|Medium|High\","
         "\"confidence\":0.0,"
         "\"rationale\":\"Explain the decision referencing the rule description\""
         "}}"),  # Escaped brace
        ("human",
         "Original severity: {original_severity}\n\n"
         "Alert rule:\n{alert_text}")
    ])

    # Invoke the LLM with only the variables defined in the prompt
    result = (prompt | llm).invoke({
        "alert_text": alert_text[:2000],
        "original_severity": original_severity
    })

    # Extract JSON output safely
    output = extract_json(result.content)
    if output:
        output.setdefault("rationale", "Severity based on rule description.")
        output.setdefault("confidence", 0.6)
        return output

    # Fallback in case of parse failure
    return {
        "ai_severity": "Medium",
        "confidence": 0.5,
        "rationale": "Fallback: unable to parse model output."
    }
