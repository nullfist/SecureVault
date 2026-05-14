"""
Secure password generator with entropy scoring.
Author: Syed
"""

import math
import secrets
import string


class PasswordGenerator:
    """Generates cryptographically secure passwords and scores their strength."""

    @staticmethod
    def generate(
        length: int = 20,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> str:
        """Build a random password from the selected character pools."""
        pool = ""
        if use_lower:
            pool += string.ascii_lowercase
        if use_upper:
            pool += string.ascii_uppercase
        if use_digits:
            pool += string.digits
        if use_symbols:
            pool += string.punctuation
        if not pool:
            pool = string.ascii_letters + string.digits

        # Guarantee at least one char from each requested pool
        password_chars = []
        if use_lower:
            password_chars.append(secrets.choice(string.ascii_lowercase))
        if use_upper:
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password_chars.append(secrets.choice(string.digits))
        if use_symbols:
            password_chars.append(secrets.choice(string.punctuation))

        remaining = length - len(password_chars)
        password_chars.extend(secrets.choice(pool) for _ in range(max(0, remaining)))

        # Shuffle to avoid predictable prefix
        password_list = list(password_chars)
        # Fisher–Yates shuffle with secure randomness
        for i in range(len(password_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_list[i], password_list[j] = password_list[j], password_list[i]

        return "".join(password_list)

    @staticmethod
    def estimate_entropy(password: str) -> float:
        """Estimate Shannon entropy in bits based on detected character classes."""
        if not password:
            return 0.0
        charset = 0
        if any(c in string.ascii_lowercase for c in password):
            charset += 26
        if any(c in string.ascii_uppercase for c in password):
            charset += 26
        if any(c in string.digits for c in password):
            charset += 10
        if any(c in string.punctuation for c in password):
            charset += 32
        charset = max(charset, 1)
        return round(len(password) * math.log2(charset), 2)

    @staticmethod
    def strength_label(entropy: float) -> str:
        if entropy < 40:
            return "Weak"
        if entropy < 60:
            return "Moderate"
        if entropy < 80:
            return "Strong"
        return "Excellent"
