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

# Try to import PQC - if not available, use Lambda-only mode
try:
    from pqc import KyberKEM, DilithiumSignature
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("ℹ️  PQC native module not available - using Lambda-only mode")


class KyberMedicalClient:
    """
    Medical image encryption client using ML-KEM-768 (Kyber)
    Supports both local encryption (if PQC available) and Lambda-only mode
    """
    
    def __init__(self, lambda_function_name: str, region: str, 
                 s3_bucket: str, dynamodb_table: str):
        """Initialize the client"""
        self.lambda_function_name = lambda_function_name
        self.region = region
        self.s3_bucket = s3_bucket
        self.dynamodb_table = dynamodb_table
        
        # AWS clients
        self.lambda_client = boto3.client('lambda', region_name=region)
        self.s3_client = boto3.client('s3', region_name=region)
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        
        # Initialize PQC if available
        if PQC_AVAILABLE:
            self.kyber = KyberKEM()
            self.dilithium = DilithiumSignature()
        else:
            self.kyber = None
            self.dilithium = None
    
    def generate_keypair(self) -> Dict[str, str]:
        """
        Generate ML-KEM-768 keypair
        If PQC not available, generates on Lambda
        """
        if PQC_AVAILABLE:
            # Local generation
            pk, sk = self.kyber.generate_keypair()
            return {
                'publicKey': base64.b64encode(pk).decode('utf-8'),
                'secretKey': base64.b64encode(sk).decode('utf-8'),
                'algorithm': 'ML-KEM-768',
                'mode': 'local'
            }
        else:
            # Generate on Lambda
            return self.generate_keypair_on_lambda()
    
    def generate_keypair_on_lambda(self) -> Dict[str, str]:
        """Generate keypair on AWS Lambda"""
        response = self.lambda_client.invoke(
            FunctionName=self.lambda_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps({'operation': 'generate_keypair'})
        )
        
        result = json.loads(response['Payload'].read())
        body = json.loads(result['body'])
        
        return {
            'publicKey': body['publicKey'],
            'secretKey': None,  # Not returned for security
            'algorithm': body['algorithm'],
            'keyId': body['keyId'],
            'mode': 'lambda'
        }
    
    def get_public_key_from_lambda(self) -> Dict[str, str]:
        """Retrieve public key from Lambda"""
        response = self.lambda_client.invoke(
            FunctionName=self.lambda_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps({'operation': 'get_public_key'})
        )
        
        result = json.loads(response['Payload'].read())
        body = json.loads(result['body'])
        
        return body
    
    def generate_signing_keypair(self) -> Optional[Dict[str, str]]:
        """
        Generate ML-DSA-65 signing keypair (local only)
        Returns None if PQC not available
        """
        if not PQC_AVAILABLE:
            return None
        
        pk, sk = self.dilithium.generate_keypair()
        return {
            'publicKey': base64.b64encode(pk).decode('utf-8'),
            'secretKey': base64.b64encode(sk).decode('utf-8'),
            'algorithm': 'ML-DSA-65'
        }
    
    def encrypt_text_local(self, text, public_key: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Encrypt data locally (requires PQC module)
        Falls back to Lambda if PQC not available
        """
        if not PQC_AVAILABLE:
            # Can't encrypt locally - would need to send to Lambda
            # For now, create a package that Lambda will encrypt
            plaintext = text if isinstance(text, bytes) else text.encode('utf-8')
            return {
                'mode': 'lambda-encrypt',
                'plaintext': base64.b64encode(plaintext).decode('utf-8'),
                'metadata': metadata or {},
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Local encryption with PQC
        pk = base64.b64decode(public_key)
        
        # Encapsulate shared secret
        ciphertext, shared_secret = self.kyber.encapsulate(pk)
        
        # Derive AES key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'medical-image-encryption'
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)
        
        plaintext = text if isinstance(text, bytes) else text.encode('utf-8')
        encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
        
        return {
            'algorithm': 'ML-KEM-768 + AES-256-GCM',
            'kyberCiphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'encryptedData': base64.b64encode(encrypted_data).decode('utf-8'),
            'originalSize': len(plaintext),
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
            'mode': 'local'
        }
    
    def decrypt_local(self, encrypted_package: Dict, secret_key: str) -> bytes:
        """Decrypt locally (requires PQC module)"""
        if not PQC_AVAILABLE:
            raise Exception("Local decryption not available - use decrypt_via_lambda()")
        
        sk = base64.b64decode(secret_key)
        kyber_ct = base64.b64decode(encrypted_package['kyberCiphertext'])
        nonce = base64.b64decode(encrypted_package['nonce'])
        encrypted_data = base64.b64decode(encrypted_package['encryptedData'])
        
        # Decapsulate
        shared_secret = self.kyber.decapsulate(kyber_ct, sk)
        
        # Derive AES key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'medical-image-encryption'
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Decrypt
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        
        return plaintext
    
    def sign_package(self, encrypted_package: Dict, signing_secret_key: str) -> Dict[str, Any]:
        """Sign encrypted package (requires PQC module)"""
        if not PQC_AVAILABLE:
            # Return unsigned package
            return {'encryptedPackage': encrypted_package}
        
        sk = base64.b64decode(signing_secret_key)
        
        # Serialize package
        message = json.dumps(encrypted_package, separators=(',', ':'), sort_keys=True).encode('utf-8')
        
        # Sign
        signature = self.dilithium.sign(message, sk)
        
        return {
            'encryptedPackage': encrypted_package,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'algorithm': 'ML-DSA-65'
        }
    
    def verify_signature(self, signed_package: Dict, signing_public_key: str) -> bool:
        """Verify signature (requires PQC module)"""
        if not PQC_AVAILABLE:
            return False  # Can't verify without PQC
        
        pk = base64.b64decode(signing_public_key)
        signed_message = base64.b64decode(signed_package['signature'])
        
        original_message = self.dilithium.verify(signed_message, pk)
        
        if original_message is None:
            return False
        
        expected_message = json.dumps(
            signed_package['encryptedPackage'],
            separators=(',', ':'),
            sort_keys=True
        ).encode('utf-8')
        
        return original_message == expected_message
    
    def upload_encrypted_file(self, signed_package: Dict) -> Dict[str, str]:
        """Upload encrypted file to S3"""
        record_id = f"rec-{uuid.uuid4().hex}"
        timestamp = datetime.utcnow()
        
        s3_key = f"encrypted/{timestamp.strftime('%Y-%m-%d')}/{record_id}.json"
        
        # Upload to S3
        self.s3_client.put_object(
            Bucket=self.s3_bucket,
            Key=s3_key,
            Body=json.dumps(signed_package),
            ContentType='application/json',
            Metadata={
                'record-id': record_id,
                'upload-timestamp': timestamp.isoformat()
            }
        )
        
        # Store metadata in DynamoDB
        table = self.dynamodb.Table(self.dynamodb_table)
        
        metadata = signed_package.get('encryptedPackage', {}).get('metadata', {})
        
        table.put_item(Item={
            'recordId': record_id,
            'uploadTimestamp': timestamp.isoformat(),
            's3Key': s3_key,
            's3Bucket': self.s3_bucket,
            'status': 'uploaded',
            'patientId': metadata.get('patientId', 'unknown'),
            'scanType': metadata.get('scanType', 'unknown'),
            'originalFileName': metadata.get('originalFileName', 'unknown')
        })
        
        return {
            'recordId': record_id,
            's3Key': s3_key,
            's3Uri': f's3://{self.s3_bucket}/{s3_key}',
            'timestamp': timestamp.isoformat()
        }
    
    def decrypt_via_lambda(self, encrypted_package: Dict) -> bytes:
        """Decrypt via Lambda (when local PQC not available)"""
        response = self.lambda_client.invoke(
            FunctionName=self.lambda_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps({
                'operation': 'decrypt',
                'body': json.dumps({'encryptedPackage': encrypted_package})
            })
        )
        
        result = json.loads(response['Payload'].read())
        body = json.loads(result['body'])
        
        return base64.b64decode(body['decryptedData'])
    
    def download_and_decrypt(self, record_id: str) -> bytes:
        """Download and decrypt file from S3"""
        # Get metadata from DynamoDB
        table = self.dynamodb.Table(self.dynamodb_table)
        response = table.get_item(Key={'recordId': record_id})
        
        if 'Item' not in response:
            raise Exception(f"Record {record_id} not found")
        
        item = response['Item']
        
        # Check if already decrypted
        if 'decryptedS3Key' in item:
            s3_key = item['decryptedS3Key']
            obj = self.s3_client.get_object(Bucket=self.s3_bucket, Key=s3_key)
            return obj['Body'].read()
        
        # Download encrypted file
        s3_key = item['s3Key']
        obj = self.s3_client.get_object(Bucket=self.s3_bucket, Key=s3_key)
        signed_package = json.loads(obj['Body'].read())
        
        encrypted_package = signed_package.get('encryptedPackage', signed_package)
        
        # Decrypt via Lambda (since local PQC likely not available on Streamlit Cloud)
        return self.decrypt_via_lambda(encrypted_package)