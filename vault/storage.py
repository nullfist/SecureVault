"""
Encrypted local storage for the credential vault.
Author: Syed
"""

import json
import os
from typing import List, Dict, Any
from .crypto import VaultCrypto


class VaultStorage:
    """Manages reading/writing the encrypted vault file."""

    def __init__(self, storage_file: str = "data/vault.enc"):
        self.storage_file = storage_file
        os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)

    def save_vault(self, data: List[Dict[str, Any]], key: bytes):
        """Encrypt and persist the credential list."""
        json_data = json.dumps(data)
        encrypted = VaultCrypto.encrypt_data(json_data, key)
        with open(self.storage_file, "w") as f:
            f.write(encrypted)

    def load_vault(self, key: bytes) -> List[Dict[str, Any]]:
        """Load and decrypt the credential list. Returns [] if file missing."""
        if not os.path.exists(self.storage_file):
            return []
        with open(self.storage_file, "r") as f:
            encrypted = f.read()
        decrypted = VaultCrypto.decrypt_data(encrypted, key)
        if decrypted is None:
            raise ValueError("Decryption failed — invalid key or tampered data.")
        return json.loads(decrypted)
