"""
Master-password authentication using Argon2id.
Author: Syed

Security notes:
  - Argon2id is the winner of the Password Hashing Competition and is
    recommended by OWASP for password storage. It is resistant to both
    GPU and side-channel attacks.
  - A failed-attempt counter locks the vault after 5 consecutive failures
    to slow down online brute-force attempts.
"""

import json
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .crypto import VaultCrypto


class AuthManager:
    """Handles master password setup, verification, and lockout logic."""

    MAX_ATTEMPTS = 5

    def __init__(self, auth_file: str = "data/auth.json"):
        self.auth_file = auth_file
        self.ph = PasswordHasher()
        os.makedirs(os.path.dirname(self.auth_file), exist_ok=True)

    # ── Setup ─────────────────────────────────────────────
    def setup_master_password(self, password: str) -> bytes:
        """Hash the master password, generate a salt, and persist both."""
        hash_val = self.ph.hash(password)
        salt = VaultCrypto.generate_salt()
        data = {
            "master_hash": hash_val,
            "salt": salt.hex(),
            "failed_attempts": 0,
        }
        with open(self.auth_file, "w") as f:
            json.dump(data, f)
        return salt

    # ── Verification ──────────────────────────────────────
    def verify_password(self, password: str) -> tuple[bool, bytes | None]:
        """
        Verify the master password.
        Returns (True, salt) on success, (False, None) on failure.
        Increments the failed-attempt counter on each failure.
        """
        if not os.path.exists(self.auth_file):
            return False, None

        with open(self.auth_file, "r") as f:
            data = json.load(f)

        if data.get("failed_attempts", 0) >= self.MAX_ATTEMPTS:
            return False, None  # locked out

        try:
            self.ph.verify(data["master_hash"], password)
            # Reset counter on success
            data["failed_attempts"] = 0
            with open(self.auth_file, "w") as f:
                json.dump(data, f)
            return True, bytes.fromhex(data["salt"])
        except VerifyMismatchError:
            data["failed_attempts"] = data.get("failed_attempts", 0) + 1
            with open(self.auth_file, "w") as f:
                json.dump(data, f)
            return False, None

    # ── Helpers ───────────────────────────────────────────
    def is_setup(self) -> bool:
        return os.path.exists(self.auth_file)

    def is_locked(self) -> bool:
        if not os.path.exists(self.auth_file):
            return False
        with open(self.auth_file, "r") as f:
            data = json.load(f)
        return data.get("failed_attempts", 0) >= self.MAX_ATTEMPTS

    def remaining_attempts(self) -> int:
        if not os.path.exists(self.auth_file):
            return self.MAX_ATTEMPTS
        with open(self.auth_file, "r") as f:
            data = json.load(f)
        return max(0, self.MAX_ATTEMPTS - data.get("failed_attempts", 0))
