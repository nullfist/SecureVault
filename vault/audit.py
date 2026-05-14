"""
Audit logger — tracks security events without exposing sensitive data.
Author: Syed
"""

import os
import logging
from datetime import datetime


class AuditLogger:
    """File-based security audit trail."""

    def __init__(self, log_file: str = "logs/audit.log"):
        self.log_file = log_file
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        self.logger = logging.getLogger("vault_audit")
        if not self.logger.handlers:
            handler = logging.FileHandler(self.log_file)
            handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s"))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log(self, message: str, level: str = "INFO"):
        getattr(self.logger, level.lower(), self.logger.info)(message)

    def get_recent(self, n: int = 20) -> list[str]:
        """Return the last *n* log lines."""
        if not os.path.exists(self.log_file):
            return []
        with open(self.log_file, "r") as f:
            return f.readlines()[-n:]
