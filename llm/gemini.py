import os
from langchain_google_genai import ChatGoogleGenerativeAI

def get_llm():
    """
    Returns Gemini 2.5 Flash LLM instance.
    Ensure you set GOOGLE_API_KEY in environment variables.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError("Set GOOGLE_API_KEY in your environment before running.")
    
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0
    )
    return llm

#setx GOOGLE_API_KEY "your_key"

