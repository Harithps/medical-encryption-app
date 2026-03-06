import streamlit as st

st.title("Test - Medical Encryption")
st.write(" App is running!")

try:
    import boto3
    st.success(" boto3 imported")
except:
    st.error(" boto3 failed")

try:
    from pqc import KyberKEM
    st.success(" PQC available")
except:
    st.warning(" PQC not available (Lambda-only mode)")

try:
    from kyber_client import KyberMedicalClient
    st.success(" kyber_client imported")
except Exception as e:
    st.error(f" kyber_client failed: {e}")
