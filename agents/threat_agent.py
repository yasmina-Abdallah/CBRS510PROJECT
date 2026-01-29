from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from llm.gemini import get_llm
import json, re

llm = get_llm()

@tool(description="Analyzes threat behavior ethically for SOC Level-1 alerts")
def analyze_threat_behavior(alert_text: str) -> dict:
    """
    Ethically analyze alert rules and extract observable threat behavior indicators.
    
    Returns dictionary with:
        - observed_indicators: list of factual observations
        - inferred_behavior: brief inferred behavior or None
        - suspicious_processes: list explicitly mentioned
        - network_connections: list explicitly mentioned
        - confidence: float between 0 and 1
        - rationale: explanation of how AI reached this conclusion
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         "You are a SOC Level 1 malware analysis assistant.\n"
         "Ethical constraints:\n"
         "- Distinguish observed indicators from inferred behavior.\n"
         "- Do NOT assume malware execution unless explicitly stated.\n"
         "- Reduce confidence if behavior is inferred.\n"
         "- Do NOT fabricate processes or network connections.\n"
         "- Always provide a rationale explaining your reasoning.\n\n"
         "Return ONLY valid JSON with fields:\n"
         '{{\n'
         '  "observed_indicators": [],\n'
         '  "inferred_behavior": null,\n'
         '  "suspicious_processes": [],\n'
         '  "network_connections": [],\n'
         '  "confidence": 0.0-1.0,\n'
         '  "rationale": "Explain in 1-2 sentences exactly why you chose these indicators"\n'
         '}}'),
        ("human", "Alert rule text:\n{alert_text}")
    ])
    
    chain = prompt | llm
    result = chain.invoke({"alert_text": alert_text[:2000]})

    # Try to parse JSON
    match = re.search(r"\{.*\}", result.content, re.DOTALL)
    if match:
        try:
            output = json.loads(match.group())
            # Ensure rationale exists
            if not output.get("rationale"):
                output["rationale"] = f"No rationale provided – key alert preview: {alert_text[:100]}"
            return output
        except:
            pass

    # Fallback
    return {
        "observed_indicators": [],
        "inferred_behavior": None,
        "suspicious_processes": [],
        "network_connections": [],
        "confidence": 0.0,
        "rationale": f"Parsing failure – key alert preview: {alert_text[:100]}"
    }
