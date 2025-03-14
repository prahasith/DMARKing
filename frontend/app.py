import streamlit as st
import requests
import pandas as pd

# API Endpoint
API_URL = "http://localhost:8000/dmarc/reports/"

st.title("📧 DMarking - DMARC Report Dashboard")

# Fetch data from API
st.subheader("📡 Fetching DMARC Reports...")
try:
    response = requests.get(API_URL)
    data = response.json().get("reports", [])

    if data:
        # Convert data to DataFrame
        df = pd.DataFrame(data)

        # Filter relevant columns
        df_filtered = df[["domain", "spf_result", "dkim_result"]]

        # Display Data Table
        st.dataframe(df_filtered)

        # Count of SPF & DKIM Pass/Fail
        st.subheader("✅ SPF & DKIM Pass Rate")
        spf_pass = df[df["spf_result"] == "pass"].shape[0]
        dkim_pass = df[df["dkim_result"] == "pass"].shape[0]

        st.write(f"✔ **SPF Pass Count:** {spf_pass}")
        st.write(f"✔ **DKIM Pass Count:** {dkim_pass}")

        # Visualization
        st.bar_chart(df_filtered["spf_result"].value_counts())
        st.bar_chart(df_filtered["dkim_result"].value_counts())

    else:
        st.warning("⚠ No DMARC reports found in the database.")

except Exception as e:
    st.error(f"❌ Error fetching data: {e}")
