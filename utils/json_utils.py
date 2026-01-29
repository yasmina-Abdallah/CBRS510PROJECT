# utils/json_utils.py
import json, re

def extract_json(text: str) -> dict | None:
    text = re.sub(r"```json|```", "", text)
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return None
