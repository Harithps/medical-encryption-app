"""
AWS Storage Integration for Post-Quantum Keys
Handles storage of large PQC keys that exceed Secrets Manager limits
"""

import boto3
import base64
import json
from typing import Dict, Optional, Tuple
from botocore.exceptions import ClientError


class AWSKeyStorage:
    """
    Store PQC keys in AWS S3 with KMS encryption
    For keys too large for Secrets Manager (>64KB)
    """
    
    def __init__(self, bucket_name: str, kms_key_id: Optional[str] = None,
                 region: str = 'us-east-1'):
        """
        Initialize AWS Key Storage
        
        Args:
            bucket_name: S3 bucket for key storage
            kms_key_id: KMS key ID for encryption (optional, uses default if None)
            region: AWS region
        """
        self.bucket_name = bucket_name
        self.kms_key_id = kms_key_id
        self.region = region
        
        self.s3 = boto3.client('s3', region_name=region)
        self.kms = boto3.client('kms', region_name=region)
    
    def store_keypair(self, key_id: str, public_key: bytes, 
                     secret_key: bytes, algorithm: str,
                     metadata: Optional[Dict] = None) -> Dict:
        """
        Store a keypair in S3 with KMS encryption
        
        Args:
            key_id: Unique identifier for this keypair
            public_key: Public key bytes
            secret_key: Secret key bytes
            algorithm: "kyber" or "dilithium"
            metadata: Optional metadata to store with keys
        
        Returns:
            Dict: Storage result with S3 paths
        """
        keypair_data = {
            'algorithm': algorithm,
            'public_key': base64.b64encode(public_key).decode('ascii'),
            'secret_key': base64.b64encode(secret_key).decode('ascii'),
            'metadata': metadata or {}
        }
        
        json_data = json.dumps(keypair_data, indent=2)
        
        # Store in S3 with KMS encryption
        s3_key = f"pqc-keys/{algorithm}/{key_id}.json"
        
        put_args = {
            'Bucket': self.bucket_name,
            'Key': s3_key,
            'Body': json_data.encode('utf-8'),
            'ServerSideEncryption': 'aws:kms',
            'ContentType': 'application/json',
        }
        
        if self.kms_key_id:
            put_args['SSEKMSKeyId'] = self.kms_key_id
        
        try:
            self.s3.put_object(**put_args)
            
            return {
                'status': 'success',
                'key_id': key_id,
                's3_path': f's3://{self.bucket_name}/{s3_key}',
                'algorithm': algorithm
            }
        except ClientError as e:
            return {
                'status': 'error',
                'error': str(e),
                'key_id': key_id
            }
    
    def retrieve_keypair(self, key_id: str, 
                        algorithm: str) -> Optional[Tuple[bytes, bytes, Dict]]:
        """
        Retrieve a keypair from S3
        
        Args:
            key_id: Unique identifier for keypair
            algorithm: "kyber" or "dilithium"
        
        Returns:
            Optional[Tuple]: (public_key, secret_key, metadata) or None if not found
        """
        s3_key = f"pqc-keys/{algorithm}/{key_id}.json"
        
        try:
            response = self.s3.get_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            
            json_data = response['Body'].read().decode('utf-8')
            keypair_data = json.loads(json_data)
            
            public_key = base64.b64decode(keypair_data['public_key'])
            secret_key = base64.b64decode(keypair_data['secret_key'])
            metadata = keypair_data.get('metadata', {})
            
            return (public_key, secret_key, metadata)
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return None
            raise
    
    def retrieve_public_key(self, key_id: str, algorithm: str) -> Optional[bytes]:
        """
        Retrieve only the public key
        
        Args:
            key_id: Unique identifier for keypair
            algorithm: "kyber" or "dilithium"
        
        Returns:
            Optional[bytes]: Public key or None if not found
        """
        result = self.retrieve_keypair(key_id, algorithm)
        return result[0] if result else None
    
    def delete_keypair(self, key_id: str, algorithm: str) -> bool:
        """
        Delete a keypair from S3
        
        Args:
            key_id: Unique identifier for keypair
            algorithm: "kyber" or "dilithium"
        
        Returns:
            bool: True if deleted, False otherwise
        """
        s3_key = f"pqc-keys/{algorithm}/{key_id}.json"
        
        try:
            self.s3.delete_object(
                Bucket=self.bucket_name,
                Key=s3_key
            )
            return True
        except ClientError:
            return False
    
    def list_keys(self, algorithm: Optional[str] = None) -> list:
        """
        List all stored keys
        
        Args:
            algorithm: Filter by algorithm (optional)
        
        Returns:
            list: List of key IDs
        """
        prefix = f"pqc-keys/{algorithm}/" if algorithm else "pqc-keys/"
        
        try:
            response = self.s3.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            if 'Contents' not in response:
                return []
            
            key_ids = []
            for obj in response['Contents']:
                # Extract key_id from path: pqc-keys/algorithm/key_id.json
                parts = obj['Key'].split('/')
                if len(parts) == 3:
                    key_id = parts[2].replace('.json', '')
                    key_ids.append(key_id)
            
            return key_ids
        
        except ClientError:
            return []


class AWSSecretsManagerStorage:
    """
    Store smaller keys or metadata in AWS Secrets Manager
    Use for keys < 64KB or for storing references to S3 keys
    """
    
    def __init__(self, region: str = 'us-east-1'):
        """
        Initialize Secrets Manager storage
        
        Args:
            region: AWS region
        """
        self.region = region
        self.client = boto3.client('secretsmanager', region_name=region)
    
    def store_metadata(self, key_id: str, metadata: Dict) -> Dict:
        """
        Store key metadata in Secrets Manager
        
        Args:
            key_id: Unique identifier
            metadata: Metadata to store (must be < 64KB when serialized)
        
        Returns:
            Dict: Storage result
        """
        secret_name = f"pqc-metadata/{key_id}"
        secret_value = json.dumps(metadata)
        
        if len(secret_value) > 65536:
            return {
                'status': 'error',
                'error': 'Metadata exceeds 64KB limit'
            }
        
        try:
            # Try to create new secret
            self.client.create_secret(
                Name=secret_name,
                SecretString=secret_value
            )
            return {
                'status': 'success',
                'key_id': key_id,
                'action': 'created'
            }
        except self.client.exceptions.ResourceExistsException:
            # Update existing secret
            self.client.update_secret(
                SecretId=secret_name,
                SecretString=secret_value
            )
            return {
                'status': 'success',
                'key_id': key_id,
                'action': 'updated'
            }
        except ClientError as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def retrieve_metadata(self, key_id: str) -> Optional[Dict]:
        """
        Retrieve key metadata
        
        Args:
            key_id: Unique identifier
        
        Returns:
            Optional[Dict]: Metadata or None if not found
        """
        secret_name = f"pqc-metadata/{key_id}"
        
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            return json.loads(response['SecretString'])
        except self.client.exceptions.ResourceNotFoundException:
            return None
        except ClientError:
            return None
    
    def delete_metadata(self, key_id: str) -> bool:
        """
        Delete key metadata
        
        Args:
            key_id: Unique identifier
        
        Returns:
            bool: True if deleted, False otherwise
        """
        secret_name = f"pqc-metadata/{key_id}"
        
        try:
            self.client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )
            return True
        except ClientError:
            return False