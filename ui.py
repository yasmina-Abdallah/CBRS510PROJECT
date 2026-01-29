import streamlit as st
import pandas as pd
import json
import random

from agents.processor import process_alerts_with_agents



st.set_page_config(page_title="SOC Level-1 AI Alert Analyzer", layout="wide")
st.title("SOC Level-1 AI Alert Analyzer 🚨")

# --- Upload JSONL file ---
uploaded_file = st.file_uploader("Upload your alertLogs.jsonl", type=["jsonl"])

if uploaded_file is not None:
    logs = []
    for line in uploaded_file:
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not logs:
        st.warning("No valid logs found in the file!")
    else:
        # --- Pick 4 random alerts ---
        df_sample = pd.DataFrame(random.sample(logs, k=min(4, len(logs))))
        st.subheader("Randomly Selected Alerts")
        st.dataframe(df_sample)

        alerts = df_sample.to_dict(orient="records")

        # --- Process alerts through AI agents ---
        st.info("Processing alerts with AI agents...")
        results = process_alerts_with_agents(alerts)

        # --- Display results with full rationales ---
        st.subheader("AI-Processed Alert Results")

        for idx, r in enumerate(results, 1):
            st.markdown(f"### Alert {idx}: {r.get('rule_name')} ({r.get('category')})")
            
            # Severity + OWASP
            st.markdown(
                f"**AI Severity:** {r.get('ai_severity')}  |  "
                f"**Confidence:** {r.get('confidence'):.2f}  |  "
                f"**OWASP Risk:** {r.get('owasp_risk') or 'None'}"
            )
            st.markdown(f"**Severity Rationale:** {r.get('rationale_summary')}")
            
            # Threat indicators
            st.markdown("**Threat Intelligence:**")
            st.markdown(f"- Suspicious Processes: {r.get('suspicious_processes') or 'None'}")
            st.markdown(f"- Network Connections: {r.get('network_connections') or 'None'}")
            st.markdown(f"- User Behavior: {r.get('user_behavior') or 'Unknown'}")
            
            # Recommended actions
            st.markdown("**Recommended Mitigation Actions:**")
            for action in r.get('recommended_actions', []):
                st.markdown(f"- {action}")
            
            # Ethics metadata
            st.markdown("**Ethical Check Metadata:**")
            st.markdown(f"- Bias: {r.get('bias')}")
            st.markdown(f"- Transparency: {r.get('transparency')}")
            st.markdown(f"- Accountability: {r.get('accountability')}")
            st.markdown(f"- Privacy: {r.get('privacy')}")

            st.markdown("---")

        # --- Download processed alerts ---
        st.download_button(
            label="Download Results as JSON",
            data=json.dumps(results, indent=2),
            file_name="validated_alerts.json",
            mime="application/json"
        )
else:
    st.info("Please upload a JSONL file to start the analysis.")
