from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from llm.gemini import get_llm
import json, re

llm = get_llm()

@tool(description="Recommends mitigation actions ethically for SOC Level-1 alerts")
def recommend_mitigation_actions(alert_text: str) -> dict:
    """
    Ethically recommend mitigation and response actions for SOC Level-1 alerts.
    
    Returns dictionary with:
        - recommended_actions: list of advisory steps
        - actions_requiring_approval: list of actions needing human authorization
        - priority: High / Medium / Low
        - rationale: short explanation of why these actions were suggested
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system",
         "You are a SOC Level 1 incident response assistant.\n"
         "Ethical constraints:\n"
         "- Advise a human analyst, do not issue commands.\n"
         "- Do NOT recommend irreversible or destructive actions.\n"
         "- Clearly mark actions requiring human approval.\n"
         "- Always provide a rationale for your recommendations.\n\n"
         "Return ONLY valid JSON with fields:\n"
         '{{\n'
         '  "recommended_actions": [],\n'
         '  "actions_requiring_approval": [],\n'
         '  "priority": "High" | "Medium" | "Low",\n'
         '  "rationale": "Explain in 1-2 sentences why these mitigation steps were chosen"\n'
         '}}'),
        ("human", "Alert context:\n{alert_text}")
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
        "recommended_actions": ["Escalate alert to human analyst for review"],
        "actions_requiring_approval": ["Any containment or remediation actions"],
        "priority": "Medium",
        "rationale": f"Parsing failure – key alert preview: {alert_text[:100]}"
    }
