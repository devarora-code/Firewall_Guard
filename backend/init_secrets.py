#!/usr/bin/env python3
"""
🔐 Initialize Firewall Guard Secrets Manager
Sets up the OpenAI API key and other required secrets
"""

import sys
import os
from pathlib import Path

# Add the backend directory to the path
sys.path.append(str(Path(__file__).parent))

from secrets_manager import SecretsManager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def initialize_secrets():
    """Initialize the secrets manager with required API keys"""
    try:
        # Initialize secrets manager
        sm = SecretsManager()
        logger.info("Secrets Manager initialized")
        
        # Set OpenAI API key
        openai_api_key = "api key"
        
        if sm.set_openai_api_key(openai_api_key):
            logger.info("OpenAI API key stored successfully")
        else:
            logger.error("Failed to store OpenAI API key")
            return False
        
        # Verify the key was stored
        stored_key = sm.get_openai_api_key()
        if stored_key and stored_key.startswith("sk-svc"):
            logger.info("OpenAI API key verification successful")
        else:
            logger.error("OpenAI API key verification failed")
            return False
        
        # List all secrets
        secrets = sm.list_secrets()
        logger.info(f"Total secrets stored: {len(secrets)}")
        for secret_name in secrets.keys():
            logger.info(f"   - {secret_name}")
        
        logger.info("Secrets initialization completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize secrets: {e}")
        return False

if __name__ == "__main__":
    print("Firewall Guard - Secrets Initialization")
    print("=" * 50)
    
    success = initialize_secrets()
    
    if success:
        print("\nSecrets initialized successfully!")
        print("OpenAI API key is now stored securely")
        print("You can now start the backend server")
    else:
        print("\nSecrets initialization failed!")
        print("Please check the logs above and try again")
        sys.exit(1)
