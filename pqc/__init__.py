"""
Post-Quantum Cryptography Module
Implements Kyber768 KEM and Dilithium3 Digital Signatures
"""

import pqc_native
from typing import Tuple, Optional
import base64
import json

__version__ = "1.0.0"
__all__ = ['KyberKEM', 'DilithiumSignature', 'KeyManager']


class KyberKEM:
    """
    Kyber768 Key Encapsulation Mechanism
    
    Security Level: NIST Level 3 (equivalent to AES-192)
    """
    
    def __init__(self):
        self.params = pqc_native.get_kyber_params()
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Kyber768 keypair
        
        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
        """
        return pqc_native.kyber_keypair()
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret
        
        Args:
            public_key: Kyber768 public key (1184 bytes)
        
        Returns:
            Tuple[bytes, bytes]: (ciphertext, shared_secret)
        """
        return pqc_native.kyber_encapsulate(public_key)
    
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate a shared secret
        
        Args:
            ciphertext: Kyber768 ciphertext (1088 bytes)
            secret_key: Kyber768 secret key (2400 bytes)
        
        Returns:
            bytes: shared_secret (32 bytes)
        """
        return pqc_native.kyber_decapsulate(ciphertext, secret_key)
    
    def get_params(self) -> dict:
        """Get Kyber768 parameters"""
        return self.params


class DilithiumSignature:
    """
    Dilithium3 Digital Signature Scheme
    
    Security Level: NIST Level 3 (equivalent to AES-192)
    """
    
    def __init__(self):
        self.params = pqc_native.get_dilithium_params()
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Dilithium3 keypair
        
        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
        """
        return pqc_native.dilithium_keypair()
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message
        
        Args:
            message: Message to sign
            secret_key: Dilithium3 secret key (4016 bytes)
        
        Returns:
            bytes: Signed message (message + signature)
        """
        return pqc_native.dilithium_sign(message, secret_key)
    
    def verify(self, signed_message: bytes, public_key: bytes) -> Optional[bytes]:
        """
        Verify a signed message
        
        Args:
            signed_message: Message with signature attached
            public_key: Dilithium3 public key (1952 bytes)
        
        Returns:
            Optional[bytes]: Original message if valid, None if invalid
        """
        result = pqc_native.dilithium_verify(signed_message, public_key)
        return result if result else None
    
    def get_params(self) -> dict:
        """Get Dilithium3 parameters"""
        return self.params


class KeyManager:
    """
    Utility class for key management and serialization
    """
    
    @staticmethod
    def export_public_key(key: bytes, algorithm: str) -> str:
        """
        Export public key to PEM-like format
        
        Args:
            key: Raw public key bytes
            algorithm: "kyber" or "dilithium"
        
        Returns:
            str: Base64-encoded key with headers
        """
        b64_key = base64.b64encode(key).decode('ascii')
        header = f"-----BEGIN {algorithm.upper()} PUBLIC KEY-----"
        footer = f"-----END {algorithm.upper()} PUBLIC KEY-----"
        
        # Split into 64-character lines
        lines = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]
        
        return f"{header}\n" + "\n".join(lines) + f"\n{footer}"
    
    @staticmethod
    def import_public_key(pem_key: str) -> bytes:
        """
        Import public key from PEM-like format
        
        Args:
            pem_key: PEM-formatted key string
        
        Returns:
            bytes: Raw public key bytes
        """
        lines = pem_key.strip().split('\n')
        b64_key = ''.join(line for line in lines if not line.startswith('-----'))
        return base64.b64decode(b64_key)
    
    @staticmethod
    def serialize_keypair(public_key: bytes, secret_key: bytes, 
                         algorithm: str) -> dict:
        """
        Serialize keypair to JSON-compatible dict
        
        Args:
            public_key: Public key bytes
            secret_key: Secret key bytes
            algorithm: "kyber" or "dilithium"
        
        Returns:
            dict: Serialized keypair
        """
        return {
            'algorithm': algorithm,
            'public_key': base64.b64encode(public_key).decode('ascii'),
            'secret_key': base64.b64encode(secret_key).decode('ascii'),
        }
    
    @staticmethod
    def deserialize_keypair(data: dict) -> Tuple[bytes, bytes, str]:
        """
        Deserialize keypair from dict
        
        Args:
            data: Serialized keypair dict
        
        Returns:
            Tuple[bytes, bytes, str]: (public_key, secret_key, algorithm)
        """
        return (
            base64.b64decode(data['public_key']),
            base64.b64decode(data['secret_key']),
            data['algorithm']
        )
    
    @staticmethod
    def split_large_data(data: bytes, chunk_size: int = 60000) -> list:
        """
        Split large data into chunks for storage
        
        Args:
            data: Data to split
            chunk_size: Maximum chunk size in bytes
        
        Returns:
            list: List of base64-encoded chunks
        """
        b64_data = base64.b64encode(data).decode('ascii')
        return [b64_data[i:i+chunk_size] 
                for i in range(0, len(b64_data), chunk_size)]
    
    @staticmethod
    def join_chunks(chunks: list) -> bytes:
        """
        Join data chunks back together
        
        Args:
            chunks: List of base64-encoded chunks
        
        Returns:
            bytes: Reconstructed data
        """
        b64_data = ''.join(chunks)
        return base64.b64decode(b64_data)