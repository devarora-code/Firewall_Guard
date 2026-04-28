"""
🔐 Firewall Guard - Secrets Management System
Enterprise-grade credential management for API keys and sensitive data
"""

import os
import json
import hashlib
import secrets
from cryptography.fernet import Fernet
from pathlib import Path
from typing import Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)

class SecretsManager:
    """Enterprise-grade secrets management for Firewall Guard"""
    
    def __init__(self, secrets_file: str = "firewall_secrets.enc"):
        self.secrets_file = Path(secrets_file)
        self.master_key = None
        self.cipher_suite = None
        self.secrets_cache = {}
        self.init_secrets_manager()
    
    def init_secrets_manager(self):
        """Initialize the secrets manager with encryption"""
        try:
            # Try to load existing master key
            master_key_file = Path("master_key.key")
            if master_key_file.exists():
                with open(master_key_file, 'rb') as f:
                    self.master_key = f.read()
            else:
                # Generate new master key
                self.master_key = Fernet.generate_key()
                with open(master_key_file, 'wb') as f:
                    f.write(self.master_key)
                logger.info("Generated new master key - store securely!")
            
            self.cipher_suite = Fernet(self.master_key)
            self.load_secrets()
            
        except Exception as e:
            logger.error(f"Failed to initialize secrets manager: {e}")
            raise
    
    def load_secrets(self):
        """Load encrypted secrets from file"""
        try:
            if self.secrets_file.exists():
                with open(self.secrets_file, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                self.secrets_cache = json.loads(decrypted_data.decode())
                logger.info(f"Loaded {len(self.secrets_cache)} encrypted secrets")
            else:
                self.secrets_cache = {}
                self.save_secrets()
                
        except Exception as e:
            logger.error(f"Failed to load secrets: {e}")
            self.secrets_cache = {}
    
    def save_secrets(self):
        """Save encrypted secrets to file"""
        try:
            secrets_data = json.dumps(self.secrets_cache).encode()
            encrypted_data = self.cipher_suite.encrypt(secrets_data)
            
            with open(self.secrets_file, 'wb') as f:
                f.write(encrypted_data)
                
            logger.info("Secrets saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save secrets: {e}")
            raise
    
    def store_secret(self, key: str, value: str, description: str = ""):
        """Store a new secret with metadata"""
        try:
            secret_data = {
                "value": value,
                "description": description,
                "created_at": str(Path().resolve()),
                "version": 1,
                "checksum": hashlib.sha256(value.encode()).hexdigest()
            }
            
            self.secrets_cache[key] = secret_data
            self.save_secrets()
            
            logger.info(f"Stored secret: {key}")
            
        except Exception as e:
            logger.error(f"Failed to store secret {key}: {e}")
            raise
    
    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret by key"""
        try:
            if key in self.secrets_cache:
                secret_data = self.secrets_cache[key]
                value = secret_data["value"]
                
                # Verify checksum
                checksum = hashlib.sha256(value.encode()).hexdigest()
                if checksum != secret_data["checksum"]:
                    logger.error(f"Checksum mismatch for secret: {key}")
                    return None
                
                return value
            else:
                logger.warning(f"Secret not found: {key}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to retrieve secret {key}: {e}")
            return None
    
    def rotate_secret(self, key: str, new_value: str):
        """Rotate an existing secret"""
        try:
            if key in self.secrets_cache:
                old_data = self.secrets_cache[key]
                old_data["old_value"] = old_data["value"]
                old_data["rotated_at"] = str(Path().resolve())
                old_data["version"] += 1
                
                old_data["value"] = new_value
                old_data["checksum"] = hashlib.sha256(new_value.encode()).hexdigest()
                
                self.save_secrets()
                logger.info(f"Rotated secret: {key}")
            else:
                raise ValueError(f"Secret not found: {key}")
                
        except Exception as e:
            logger.error(f"Failed to rotate secret {key}: {e}")
            raise
    
    def set_openai_api_key(self, api_key: str) -> bool:
        """Set the OpenAI API key."""
        try:
            self.store_secret("openai_api_key", api_key, "OpenAI API Key for AI Analysis")
            return True
        except Exception as e:
            logger.error(f"Failed to set OpenAI API key: {e}")
            return False
    
    def get_openai_api_key(self) -> Optional[str]:
        """Get the OpenAI API key."""
        return self.get_secret("openai_api_key")
    
    def list_secrets(self) -> Dict[str, Dict[str, Any]]:
        """List all secrets (without values)"""
        try:
            secret_list = {}
            for key, data in self.secrets_cache.items():
                secret_list[key] = {
                    "description": data.get("description", ""),
                    "created_at": data.get("created_at", ""),
                    "version": data.get("version", 1),
                    "has_rotated": "old_value" in data
                }
            return secret_list
            
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return {}
    
    def delete_secret(self, key: str):
        """Delete a secret"""
        try:
            if key in self.secrets_cache:
                del self.secrets_cache[key]
                self.save_secrets()
                logger.info(f"Deleted secret: {key}")
            else:
                logger.warning(f"Secret not found for deletion: {key}")
                
        except Exception as e:
            logger.error(f"Failed to delete secret {key}: {e}")
            raise

# Initialize global secrets manager
secrets_manager = SecretsManager()

# Store default secrets
def initialize_default_secrets():
    """Initialize default secrets for Firewall Guard"""
    
    # OpenAI API Key (move from hardcoded)
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        secrets_manager.store_secret(
            "openai_api_key", 
            openai_key,
            "OpenAI GPT API key for threat analysis"
        )
    
    # Database credentials
    db_password = os.getenv("DB_PASSWORD") or secrets.token_urlsafe(32)
    secrets_manager.store_secret(
        "database_password",
        db_password,
        "Database connection password"
    )
    
    # JWT secret for authentication
    jwt_secret = os.getenv("JWT_SECRET") or secrets.token_urlsafe(64)
    secrets_manager.store_secret(
        "jwt_secret",
        jwt_secret,
        "JWT token signing secret"
    )
    
    # Encryption key for data at rest
    encryption_key = os.getenv("ENCRYPTION_KEY") or secrets.token_urlsafe(32)
    secrets_manager.store_secret(
        "encryption_key",
        encryption_key,
        "Data encryption key for storage"
    )

if __name__ == "__main__":
    # Initialize secrets on first run
    initialize_default_secrets()
    
    # Example usage
    print("🔐 Firewall Guard Secrets Manager")
    print("=" * 50)
    
    # List all secrets
    secrets = secrets_manager.list_secrets()
    for key, info in secrets.items():
        print(f"🔑 {key}")
        print(f"   Description: {info['description']}")
        print(f"   Version: {info['version']}")
        print(f"   Created: {info['created_at']}")
        print()
