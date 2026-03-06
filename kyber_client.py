"""
Medical Image Encryption Client - Production Version
Updated for ML-KEM-768 and ML-DSA-65 (NIST standardized PQC)
Integrates with AWS Lambda for key management and decryption
"""

import sys
import os

# Import PQC modules
try:
    from pqc import KyberKEM, DilithiumSignature, KeyManager
except ImportError:
    print("ERROR: PQC module not found. Make sure you've run 'python setup.py install'")
    sys.exit(1)

import boto3
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
import uuid
from typing import Dict, Any, Optional


class KyberMedicalClient:
    """
    Client for medical image encryption using ML-KEM-768 and ML-DSA-65
    
    Architecture:
    - Client encrypts data locally using public key
    - AWS Lambda manages private keys securely
    - S3 stores encrypted and decrypted files
    - DynamoDB tracks metadata
    """
    
    def __init__(self, lambda_function_name: str, region: str, s3_bucket: str, dynamodb_table: str):
        """
        Initialize the medical encryption client
        
        Args:
            lambda_function_name: Name of AWS Lambda function
            region: AWS region (e.g., 'us-east-1')
            s3_bucket: S3 bucket for storing files
            dynamodb_table: DynamoDB table for metadata
        """
        self.lambda_function_name = lambda_function_name
        self.region = region
        self.s3_bucket = s3_bucket
        self.dynamodb_table = dynamodb_table
        
        # Initialize PQC
        self.kyber = KyberKEM()
        self.dilithium = DilithiumSignature()
        
        # AWS clients
        self.lambda_client = boto3.client('lambda', region_name=region)
        self.s3_client = boto3.client('s3', region_name=region)
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        
        try:
            self.table = self.dynamodb.Table(dynamodb_table)
        except Exception as e:
            print(f"Warning: Could not connect to DynamoDB table {dynamodb_table}: {e}")
            self.table = None
    
    def generate_keypair(self) -> Dict[str, Any]:
        """
        Generate ML-KEM-768 keypair locally (for offline use)
        
        For production, use generate_keypair_on_lambda() instead
        
        Returns:
            Dict containing keyId, publicKey, secretKey, etc.
        """
        pk, sk = self.kyber.generate_keypair()
        
        key_id = f"mlkem-{uuid.uuid4().hex[:8]}"
        
        return {
            'keyId': key_id,
            'publicKey': base64.b64encode(pk).decode('utf-8'),
            'secretKey': base64.b64encode(sk).decode('utf-8'),
            'publicKeyLength': len(pk),
            'secretKeyLength': len(sk),
            'algorithm': 'ML-KEM-768',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def generate_keypair_on_lambda(self) -> Dict[str, Any]:
        """
        Generate ML-KEM-768 keypair on AWS Lambda
        Private key is stored securely in AWS Secrets Manager
        
        Returns:
            Dict containing keyId, publicKey (no secretKey for security)
        """
        try:
            response = self.lambda_client.invoke(
                FunctionName=self.lambda_function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps({'operation': 'generate_keypair'})
            )
            
            result = json.loads(response['Payload'].read())
            
            if result['statusCode'] != 200:
                raise Exception(f"Lambda error: {result.get('body', 'Unknown error')}")
            
            body = json.loads(result['body'])
            return body
        
        except Exception as e:
            raise Exception(f"Failed to generate keypair on Lambda: {str(e)}")
    
    def get_public_key_from_lambda(self) -> Dict[str, Any]:
        """
        Fetch public key from AWS Lambda
        
        Returns:
            Dict containing keyId, publicKey, algorithm, createdAt
        """
        try:
            response = self.lambda_client.invoke(
                FunctionName=self.lambda_function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps({'operation': 'get_public_key'})
            )
            
            result = json.loads(response['Payload'].read())
            
            if result['statusCode'] != 200:
                raise Exception(f"Lambda error: {result.get('body', 'Unknown error')}")
            
            body = json.loads(result['body'])
            return body
        
        except Exception as e:
            raise Exception(f"Failed to get public key from Lambda: {str(e)}")
    
    def generate_signing_keypair(self) -> Dict[str, Any]:
        """
        Generate ML-DSA-65 signing keypair locally
        
        Returns:
            Dict containing keyId, publicKey, secretKey
        """
        pk, sk = self.dilithium.generate_keypair()
        
        key_id = f"mldsa-{uuid.uuid4().hex[:8]}"
        
        return {
            'keyId': key_id,
            'publicKey': base64.b64encode(pk).decode('utf-8'),
            'secretKey': base64.b64encode(sk).decode('utf-8'),
            'publicKeyLength': len(pk),
            'algorithm': 'ML-DSA-65',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def encrypt_text_local(self, text: str, public_key: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Encrypt data locally using ML-KEM-768 + AES-256-GCM
        This happens BEFORE sending to AWS - data never leaves unencrypted
        
        Args:
            text: Data to encrypt (string or base64-encoded binary)
            public_key: Base64-encoded ML-KEM-768 public key
            metadata: Optional metadata to include
        
        Returns:
            Dict containing encrypted package
        """
        # Decode public key
        pk = base64.b64decode(public_key)
        
        # Encapsulate shared secret using ML-KEM-768
        ciphertext, shared_secret = self.kyber.encapsulate(pk)
        
        # Derive AES key from shared secret using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=None,
            info=b'medical-image-encryption'
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Encrypt data with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        
        # Convert to bytes if needed
        if isinstance(text, str):
            plaintext = text.encode('utf-8')
        elif isinstance(text, bytes):
            plaintext = text  # Already bytes - use as is
        else:
            raise TypeError("text must be str or bytes")
        encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
        
        # Package everything
        package = {
            'algorithm': 'ML-KEM-768 + AES-256-GCM',
            'kyberCiphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'encryptedData': base64.b64encode(encrypted_data).decode('utf-8'),
            'originalSize': len(plaintext),
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        
        return package
    
    def decrypt_local(self, encrypted_package: Dict[str, Any], secret_key: str) -> bytes:
        """
        Decrypt data locally using ML-KEM-768 + AES-256-GCM
        
        Args:
            encrypted_package: Encrypted package from encrypt_text_local()
            secret_key: Base64-encoded ML-KEM-768 secret key
        
        Returns:
            Decrypted plaintext bytes
        """
        # Decode secret key
        sk = base64.b64decode(secret_key)
        
        # Decode encrypted package
        kyber_ct = base64.b64decode(encrypted_package['kyberCiphertext'])
        nonce = base64.b64decode(encrypted_package['nonce'])
        encrypted_data = base64.b64decode(encrypted_package['encryptedData'])
        
        # Decapsulate shared secret
        shared_secret = self.kyber.decapsulate(kyber_ct, sk)
        
        # Derive AES key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'medical-image-encryption'
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Decrypt with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        
        return plaintext
    
    def sign_package(self, encrypted_package: Dict[str, Any], signing_secret_key: str) -> Dict[str, Any]:
        """
        Sign the encrypted package with ML-DSA-65
        
        Args:
            encrypted_package: Encrypted package to sign
            signing_secret_key: Base64-encoded ML-DSA-65 secret key
        
        Returns:
            Signed package with signature
        """
        # Decode signing key
        sk = base64.b64decode(signing_secret_key)
        
        # Create message to sign (use compact JSON for consistency)
        message = json.dumps(encrypted_package, separators=(',', ':'), sort_keys=True).encode('utf-8')
        
        # Sign with Dilithium (old API - returns combined signed_message)
        signed_message = self.dilithium.sign(message, sk)
        
        # Return signed package
        return {
            'encryptedPackage': encrypted_package,
            'signature': base64.b64encode(signed_message).decode('utf-8'),
            'signatureAlgorithm': 'ML-DSA-65',
            'signedAt': datetime.utcnow().isoformat()
        }
    
    def verify_signature(self, signed_package: Dict[str, Any], signing_public_key: str) -> bool:
        """
        Verify ML-DSA-65 signature
        
        Args:
            signed_package: Signed package from sign_package()
            signing_public_key: Base64-encoded ML-DSA-65 public key
        
        Returns:
            True if signature is valid
        
        Raises:
            ValueError if signature is invalid
        """
        try:
            # Decode public key and signed message
            pk = base64.b64decode(signing_public_key)
            signed_message = base64.b64decode(signed_package['signature'])
            
            # Verify signature using old Dilithium API
            # verify(signed_message, public_key) -> returns original message or None
            recovered_message = self.dilithium.verify(signed_message, pk)
            
            if recovered_message is None:
                raise ValueError("Signature verification failed - invalid signature!")
            
            # Reconstruct expected message (must match exactly what was signed)
            expected_message = json.dumps(
                signed_package['encryptedPackage'], 
                separators=(',', ':'),
                sort_keys=True
            ).encode('utf-8')
            
            # Compare messages
            if recovered_message != expected_message:
                raise ValueError("Signature verification failed - message mismatch!")
            
            return True
            
        except Exception as e:
            raise ValueError(f"Signature verification failed: {str(e)}")
    
    def upload_encrypted_file(self, signed_package: Dict[str, Any]) -> Dict[str, Any]:
        """
        Upload encrypted and signed package to S3
        Triggers Lambda auto-decryption
        
        Args:
            signed_package: Signed package from sign_package()
        
        Returns:
            Dict with recordId, s3Uri, s3Key, uploadTimestamp
        """
        record_id = f"rec-{uuid.uuid4().hex}"
        timestamp = datetime.utcnow().isoformat()
        
        # S3 key
        s3_key = f"encrypted/{timestamp[:10]}/{record_id}.json"
        
        # Upload to S3
        self.s3_client.put_object(
            Bucket=self.s3_bucket,
            Key=s3_key,
            Body=json.dumps(signed_package, indent=2),
            ContentType='application/json',
            Metadata={
                'record-id': record_id,
                'upload-timestamp': timestamp,
                'encryption-algorithm': 'ML-KEM-768',
                'signature-algorithm': 'ML-DSA-65'
            }
        )
        
        # Store metadata in DynamoDB
        if self.table:
            try:
                self.table.put_item(
                    Item={
                        'recordId': record_id,
                        'uploadTimestamp': timestamp,
                        's3Bucket': self.s3_bucket,
                        's3Key': s3_key,
                        'algorithm': 'ML-KEM-768 + AES-256-GCM',
                        'signatureAlgorithm': 'ML-DSA-65',
                        'status': 'encrypted',
                        'metadata': signed_package['encryptedPackage'].get('metadata', {})
                    }
                )
            except Exception as e:
                print(f"Warning: DynamoDB write failed: {e}")
        
        return {
            'recordId': record_id,
            's3Uri': f"s3://{self.s3_bucket}/{s3_key}",
            's3Key': s3_key,
            'uploadTimestamp': timestamp
        }
    
    def decrypt_via_lambda(self, encrypted_package: Dict[str, Any], secret_key: str = None) -> str:
        """
        Decrypt via AWS Lambda using stored private key
        
        Note: For local testing, pass secret_key. In production, Lambda uses
        its own stored key from Secrets Manager.
        
        Args:
            encrypted_package: Encrypted package
            secret_key: Optional - for local testing only
        
        Returns:
            Decrypted data as base64 string
        """
        if secret_key:
            # Local decryption for testing
            plaintext = self.decrypt_local(encrypted_package, secret_key)
            return base64.b64encode(plaintext).decode('utf-8')
        
        # Decrypt via Lambda
        try:
            response = self.lambda_client.invoke(
                FunctionName=self.lambda_function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps({
                    'operation': 'decrypt',
                    'body': json.dumps({
                        'encryptedPackage': encrypted_package
                    })
                })
            )
            
            result = json.loads(response['Payload'].read())
            
            if result['statusCode'] != 200:
                raise Exception(f"Lambda error: {result.get('body', 'Unknown error')}")
            
            body = json.loads(result['body'])
            return body['decryptedData']
        
        except Exception as e:
            raise Exception(f"Decryption via Lambda failed: {str(e)}")
    
    def download_and_decrypt(self, record_id: str, secret_key: str = None, 
                           signing_public_key: str = None) -> Dict[str, Any]:
        """
        Download from S3, verify signature, and decrypt
        
        Args:
            record_id: Record ID to download
            secret_key: Optional - ML-KEM-768 secret key for local decryption
            signing_public_key: Optional - ML-DSA-65 public key for signature verification
        
        Returns:
            Dict with data, metadata, recordId
        """
        # Get metadata from DynamoDB
        if self.table:
            try:
                response = self.table.get_item(Key={'recordId': record_id})
                
                if 'Item' not in response:
                    raise ValueError(f"Record {record_id} not found")
                
                item = response['Item']
            except Exception as e:
                raise Exception(f"Failed to get record from DynamoDB: {str(e)}")
        else:
            # Fallback: try to find file in S3
            raise NotImplementedError("DynamoDB table not available")
        
        # Download from S3
        s3_response = self.s3_client.get_object(
            Bucket=item['s3Bucket'],
            Key=item['s3Key']
        )
        
        signed_package = json.loads(s3_response['Body'].read())
        
        # Verify signature if public key provided
        if signing_public_key:
            self.verify_signature(signed_package, signing_public_key)
        
        # Decrypt
        if secret_key:
            plaintext = self.decrypt_local(
                signed_package['encryptedPackage'], 
                secret_key
            )
        else:
            # Use Lambda
            plaintext_b64 = self.decrypt_via_lambda(signed_package['encryptedPackage'])
            plaintext = base64.b64decode(plaintext_b64)
        
        return {
            'data': plaintext,
            'metadata': signed_package['encryptedPackage'].get('metadata', {}),
            'recordId': record_id
        }
    
    def get_decrypted_file_url(self, record_id: str, expiration: int = 3600) -> str:
        """
        Get presigned URL for decrypted file
        
        Args:
            record_id: Record ID
            expiration: URL expiration in seconds (default 1 hour)
        
        Returns:
            Presigned S3 URL
        """
        # Get metadata from DynamoDB
        if not self.table:
            raise Exception("DynamoDB table not available")
        
        response = self.table.get_item(Key={'recordId': record_id})
        
        if 'Item' not in response:
            raise ValueError(f"Record {record_id} not found")
        
        item = response['Item']
        
        if 'decryptedS3Key' not in item:
            raise ValueError(f"Record {record_id} has not been decrypted yet")
        
        # Generate presigned URL
        url = self.s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': self.s3_bucket,
                'Key': item['decryptedS3Key']
            },
            ExpiresIn=expiration
        )
        
        return url