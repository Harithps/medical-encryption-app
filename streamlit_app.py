"""
Streamlit Medical Image Encryption - Cloud Optimized
Ready for Streamlit Community Cloud
"""

import streamlit as st
import boto3
import os
import sys
from datetime import datetime
import base64

# ========== PAGE CONFIG ==========
st.set_page_config(
    page_title="Medical Image Encryption",
    page_icon="🔒",
    layout="wide"
)

# ========== AWS CONFIGURATION ==========
def get_aws_config():
    """Get AWS credentials from Streamlit secrets or environment"""
    try:
        # Try Streamlit Cloud secrets first
        if hasattr(st, 'secrets') and 'aws' in st.secrets:
            return {
                'aws_access_key_id': st.secrets['aws']['access_key_id'],
                'aws_secret_access_key': st.secrets['aws']['secret_access_key'],
                'region_name': st.secrets['aws'].get('region', 'us-east-1')
            }
        # Fall back to environment variables
        else:
            return {
                'aws_access_key_id': os.environ.get('AWS_ACCESS_KEY_ID'),
                'aws_secret_access_key': os.environ.get('AWS_SECRET_ACCESS_KEY'),
                'region_name': os.environ.get('AWS_REGION', 'us-east-1')
            }
    except Exception as e:
        return None

# Initialize AWS
AWS_CONFIG = get_aws_config()
if AWS_CONFIG and AWS_CONFIG['aws_access_key_id']:
    boto3.setup_default_session(**AWS_CONFIG)
    AWS_CONNECTED = True
else:
    AWS_CONNECTED = False

# ========== PQC MODULE CHECK ==========
try:
    from pqc import KyberKEM, DilithiumSignature
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

# ========== CLIENT INITIALIZATION ==========
if AWS_CONNECTED:
    try:
        from kyber_client import KyberMedicalClient
        
        LAMBDA_FUNCTION = 'kyber-medical-encryption'
        REGION = AWS_CONFIG['region_name']
        S3_BUCKET = 'kyber-medical-records-195430305162'
        DYNAMODB_TABLE = 'medical-records-metadata'
        
        if 'client' not in st.session_state:
            st.session_state.client = KyberMedicalClient(
                lambda_function_name=LAMBDA_FUNCTION,
                region=REGION,
                s3_bucket=S3_BUCKET,
                dynamodb_table=DYNAMODB_TABLE
            )
    except Exception as e:
        st.error(f"❌ Failed to initialize client: {e}")
        st.stop()

# ========== SESSION STATE ==========
if 'keypair' not in st.session_state:
    st.session_state.keypair = None
if 'signing_keypair' not in st.session_state:
    st.session_state.signing_keypair = None
if 'encrypted_files' not in st.session_state:
    st.session_state.encrypted_files = []

# ========== MAIN UI ==========
if not AWS_CONNECTED:
    st.error("❌ AWS Credentials Not Configured")
    st.info("""
    **For Streamlit Cloud:**
    1. Go to your app settings
    2. Click "Secrets"
    3. Add:
```toml
    [aws]
    access_key_id = "YOUR_KEY"
    secret_access_key = "YOUR_SECRET"
    region = "us-east-1"
```
    """)
    st.stop()

# ========== SIDEBAR ==========
with st.sidebar:
    st.header("🔑 Key Management")
    
    if AWS_CONNECTED:
        st.success("✅ AWS Connected")
    if PQC_AVAILABLE:
        st.success("✅ Native PQC Available")
    else:
        st.info("ℹ️ Lambda-only mode")
    
    st.divider()
    
    # Keypair generation
    if PQC_AVAILABLE:
        if st.session_state.keypair is None:
            if st.button("🆕 Generate Keypair", use_container_width=True):
                with st.spinner("Generating..."):
                    st.session_state.keypair = st.session_state.client.generate_keypair()
                st.success("✅ Generated!")
                st.rerun()
        else:
            st.success("✅ Keypair loaded")
    
    if PQC_AVAILABLE and st.session_state.keypair:
        if 'signing_keypair' not in st.session_state or st.session_state.signing_keypair is None:
            if st.button("🆕 Generate Signing Key", use_container_width=True):
                with st.spinner("Generating..."):
                    st.session_state.signing_keypair = st.session_state.client.generate_signing_keypair()
                st.success("✅ Generated!")
                st.rerun()
    
    st.divider()
    st.metric("Files Encrypted", len(st.session_state.encrypted_files))

# ========== MAIN CONTENT ==========
st.title("🔒 Medical Image Encryption System")
st.markdown("**Post-Quantum Secure • Cloud Deployed**")

tab1, tab2 = st.tabs(["📤 Upload & Encrypt", "📁 View Files"])

with tab1:
    st.header("Upload Medical Image")
    
    if st.session_state.keypair is None:
        st.warning("⚠️ Generate a keypair first (see sidebar)")
    else:
        col1, col2 = st.columns([1, 1])
        
        with col1:
            patient_id = st.text_input("Patient ID*", placeholder="P-2024-001")
            patient_name = st.text_input("Patient Name", placeholder="John Doe")
            scan_type = st.selectbox("Scan Type", ["Brain MRI", "Chest CT", "X-Ray"])
        
        with col2:
            uploaded_file = st.file_uploader("Choose image", type=['png', 'jpg', 'jpeg'])
            
            if uploaded_file:
                from PIL import Image
                image = Image.open(uploaded_file)
                st.image(image, use_container_width=True)
        
        if uploaded_file and patient_id:
            if st.button("🔒 Encrypt & Upload", type="primary", use_container_width=True):
                try:
                    uploaded_file.seek(0)
                    file_data = uploaded_file.read()
                    
                    metadata = {
                        'patientId': patient_id,
                        'patientName': patient_name,
                        'scanType': scan_type,
                        'originalFileName': uploaded_file.name,
                        'fileSize': len(file_data),
                        'uploadDate': datetime.utcnow().isoformat()
                    }
                    
                    with st.spinner("Encrypting..."):
                        encrypted = st.session_state.client.encrypt_text_local(
                            text=file_data,
                            public_key=st.session_state.keypair['publicKey'],
                            metadata=metadata
                        )
                    
                    if PQC_AVAILABLE and st.session_state.signing_keypair:
                        encrypted['metadata']['signingPublicKey'] = st.session_state.signing_keypair['publicKey']
                        signed = st.session_state.client.sign_package(
                            encrypted, st.session_state.signing_keypair['secretKey']
                        )
                    else:
                        signed = {'encryptedPackage': encrypted}
                    
                    with st.spinner("Uploading..."):
                        result = st.session_state.client.upload_encrypted_file(signed)
                    
                    st.session_state.encrypted_files.append({
                        'recordId': result['recordId'],
                        'metadata': metadata
                    })
                    
                    st.success(f"✅ Uploaded! ID: {result['recordId']}")
                    st.balloons()
                    
                except Exception as e:
                    st.error(f"❌ Error: {e}")

with tab2:
    st.header("Encrypted Files")
    
    if len(st.session_state.encrypted_files) == 0:
        st.info("📭 No files yet")
    else:
        import pandas as pd
        df = pd.DataFrame([{
            'ID': f['recordId'],
            'Patient': f['metadata'].get('patientId'),
            'Type': f['metadata'].get('scanType'),
            'File': f['metadata'].get('originalFileName')
        } for f in st.session_state.encrypted_files])
        st.dataframe(df, use_container_width=True, hide_index=True)

st.divider()
st.markdown("🔒 **ML-KEM-768 + ML-DSA-65** • Deployed on Streamlit Cloud")