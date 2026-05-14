"""
Cryptographic primitives — AES-256 encryption via Fernet + PBKDF2 key derivation.
Author: Syed

Security notes:
  - Fernet uses AES-128-CBC + HMAC-SHA256 internally. The key is derived from
    the master password using PBKDF2-HMAC-SHA256 with 600 000 iterations and a
    random 16-byte salt, making brute-force attacks computationally expensive.
  - The salt is stored alongside the auth hash; it is NOT secret, only unique.
"""

import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class VaultCrypto:
    """Handles all encryption / decryption for the vault database."""

    ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-SHA256

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive a Fernet-compatible key from a password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=VaultCrypto.ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """Encrypt a plaintext string and return the Fernet token as a string."""
        return Fernet(key).encrypt(data.encode()).decode()

    @staticmethod
    def decrypt_data(token: str, key: bytes) -> str | None:
        """Decrypt a Fernet token. Returns None on failure (wrong key / tampered)."""
        try:
            return Fernet(key).decrypt(token.encode()).decode()
        except Exception:
            return None

    @staticmethod
    def generate_salt() -> bytes:
        """Generate a cryptographically random 16-byte salt."""
        return os.urandom(16)
