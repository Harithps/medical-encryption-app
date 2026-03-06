"""
Kyber Medical Client - Cloud Compatible
Handles missing PQC module gracefully (uses Lambda-only mode)
"""

import boto3
import json
import base64
import secrets
from datetime import datetime
from typing import Dict, Any, Optional
import uuid

from botocore.config import Config

# Try to import PQC libraries (may not exist in Streamlit Cloud)
try:
    from pqc import KyberKEM, DilithiumSignature
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("ℹ️ PQC native module not available - using Lambda-only mode")


class KyberMedicalClient:
    """
    Medical encryption client using ML-KEM-768 (Kyber)
    Works in two modes:
    1. Local PQC mode (if native module available)
    2. Lambda-only mode (for Streamlit Cloud)
    """

    def __init__(
        self,
        lambda_function_name: str,
        region: str,
        s3_bucket: str,
        dynamodb_table: str,
    ):
        """Initialize AWS clients"""

        self.lambda_function_name = lambda_function_name
        self.region = region
        self.s3_bucket = s3_bucket
        self.dynamodb_table = dynamodb_table

        # Prevent Streamlit timeout issues
        config = Config(
            read_timeout=60,
            connect_timeout=60,
            retries={"max_attempts": 3},
        )

        self.lambda_client = boto3.client("lambda", region_name=region, config=config)
        self.s3_client = boto3.client("s3", region_name=region)
        self.dynamodb = boto3.resource("dynamodb", region_name=region)

        # Initialize PQC if available
        if PQC_AVAILABLE:
            self.kyber = KyberKEM()
            self.dilithium = DilithiumSignature()
        else:
            self.kyber = None
            self.dilithium = None

    # -------------------------------------------------------------------
    # KEY GENERATION
    # -------------------------------------------------------------------

    def generate_keypair(self) -> Dict[str, str]:
        """
        Generate ML-KEM keypair
        Uses local PQC if available otherwise Lambda
        """

        if PQC_AVAILABLE:
            pk, sk = self.kyber.generate_keypair()

            return {
                "publicKey": base64.b64encode(pk).decode(),
                "secretKey": base64.b64encode(sk).decode(),
                "algorithm": "ML-KEM-768",
                "mode": "local",
            }

        return self.generate_keypair_on_lambda()

    def generate_keypair_on_lambda(self) -> Dict[str, str]:
        """Generate keypair securely inside Lambda"""

        response = self.lambda_client.invoke(
            FunctionName=self.lambda_function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"operation": "generate_keypair"}),
        )

        result = json.loads(response["Payload"].read())

        if "body" not in result:
            raise Exception(f"Lambda error: {result}")

        body = json.loads(result["body"])

        return {
            "publicKey": body["publicKey"],
            "algorithm": body["algorithm"],
            "keyId": body["keyId"],
            "mode": "lambda",
        }

    def get_public_key_from_lambda(self) -> Dict[str, str]:
        """Retrieve stored public key"""

        response = self.lambda_client.invoke(
            FunctionName=self.lambda_function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"operation": "get_public_key"}),
        )

        result = json.loads(response["Payload"].read())

        if "body" not in result:
            raise Exception(f"Lambda error: {result}")

        return json.loads(result["body"])

    # -------------------------------------------------------------------
    # SIGNATURE
    # -------------------------------------------------------------------

    def generate_signing_keypair(self) -> Optional[Dict[str, str]]:
        """Generate ML-DSA signing keys"""

        if not PQC_AVAILABLE:
            return None

        pk, sk = self.dilithium.generate_keypair()

        return {
            "publicKey": base64.b64encode(pk).decode(),
            "secretKey": base64.b64encode(sk).decode(),
            "algorithm": "ML-DSA-65",
        }

    # -------------------------------------------------------------------
    # ENCRYPTION
    # -------------------------------------------------------------------

    def encrypt_text_local(
        self, text, public_key: str, metadata: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Encrypt locally using Kyber + AES
        """

        if not PQC_AVAILABLE:
            plaintext = text if isinstance(text, bytes) else text.encode()

            return {
                "mode": "lambda-encrypt",
                "plaintext": base64.b64encode(plaintext).decode(),
                "metadata": metadata or {},
                "timestamp": datetime.utcnow().isoformat(),
            }

        pk = base64.b64decode(public_key)

        # Kyber encapsulation
        kyber_ct, shared_secret = self.kyber.encapsulate(pk)

        # Derive AES key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"medical-image-encryption",
        )

        aes_key = hkdf.derive(shared_secret)

        aesgcm = AESGCM(aes_key)

        nonce = secrets.token_bytes(12)

        plaintext = text if isinstance(text, bytes) else text.encode()

        encrypted_data = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "algorithm": "ML-KEM-768 + AES-256-GCM",
            "kyberCiphertext": base64.b64encode(kyber_ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encryptedData": base64.b64encode(encrypted_data).decode(),
            "originalSize": len(plaintext),
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
            "mode": "local",
        }

    # -------------------------------------------------------------------
    # DECRYPTION
    # -------------------------------------------------------------------

    def decrypt_local(self, encrypted_package: Dict, secret_key: str) -> bytes:
        """Local decryption"""

        if not PQC_AVAILABLE:
            raise Exception("Local decryption unavailable")

        sk = base64.b64decode(secret_key)

        kyber_ct = base64.b64decode(encrypted_package["kyberCiphertext"])
        nonce = base64.b64decode(encrypted_package["nonce"])
        encrypted_data = base64.b64decode(encrypted_package["encryptedData"])

        shared_secret = self.kyber.decapsulate(kyber_ct, sk)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"medical-image-encryption",
        )

        aes_key = hkdf.derive(shared_secret)

        aesgcm = AESGCM(aes_key)

        return aesgcm.decrypt(nonce, encrypted_data, None)

    # -------------------------------------------------------------------
    # SIGN PACKAGE
    # -------------------------------------------------------------------

    def sign_package(self, encrypted_package: Dict, signing_secret_key: str):

        if not PQC_AVAILABLE:
            return {"encryptedPackage": encrypted_package}

        sk = base64.b64decode(signing_secret_key)

        message = json.dumps(
            encrypted_package, separators=(",", ":"), sort_keys=True
        ).encode()

        signature = self.dilithium.sign(message, sk)

        return {
            "encryptedPackage": encrypted_package,
            "signature": base64.b64encode(signature).decode(),
            "algorithm": "ML-DSA-65",
        }

    # -------------------------------------------------------------------
    # S3 STORAGE
    # -------------------------------------------------------------------

    def upload_encrypted_file(self, signed_package: Dict):

        record_id = f"rec-{uuid.uuid4().hex}"
        timestamp = datetime.utcnow()

        s3_key = f"encrypted/{timestamp.strftime('%Y-%m-%d')}/{record_id}.json"

        self.s3_client.put_object(
            Bucket=self.s3_bucket,
            Key=s3_key,
            Body=json.dumps(signed_package),
            ContentType="application/json",
        )

        table = self.dynamodb.Table(self.dynamodb_table)

        metadata = signed_package.get("encryptedPackage", {}).get("metadata", {})

        table.put_item(
            Item={
                "recordId": record_id,
                "uploadTimestamp": timestamp.isoformat(),
                "s3Key": s3_key,
                "status": "uploaded",
                "patientId": metadata.get("patientId", "unknown"),
                "scanType": metadata.get("scanType", "unknown"),
                "originalFileName": metadata.get("originalFileName", "unknown"),
            }
        )

        return {
            "recordId": record_id,
            "s3Uri": f"s3://{self.s3_bucket}/{s3_key}",
        }

    # -------------------------------------------------------------------
    # LAMBDA DECRYPT
    # -------------------------------------------------------------------

    def decrypt_via_lambda(self, encrypted_package: Dict):

        response = self.lambda_client.invoke(
            FunctionName=self.lambda_function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(
                {
                    "operation": "decrypt",
                    "body": json.dumps({"encryptedPackage": encrypted_package}),
                }
            ),
        )

        result = json.loads(response["Payload"].read())

        if "body" not in result:
            raise Exception(f"Lambda error: {result}")

        body = json.loads(result["body"])

        return base64.b64decode(body["decryptedData"])

    # -------------------------------------------------------------------
    # DOWNLOAD AND DECRYPT
    # -------------------------------------------------------------------

    def download_and_decrypt(self, record_id: str):

        table = self.dynamodb.Table(self.dynamodb_table)

        response = table.get_item(Key={"recordId": record_id})

        if "Item" not in response:
            raise Exception("Record not found")

        item = response["Item"]

        obj = self.s3_client.get_object(
            Bucket=self.s3_bucket,
            Key=item["s3Key"],
        )

        signed_package = json.loads(obj["Body"].read())

        encrypted_package = signed_package.get("encryptedPackage", signed_package)

        return self.decrypt_via_lambda(encrypted_package)
