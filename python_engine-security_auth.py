"""
Automa Shield - Administrative Authentication Subsystem (security_auth.py)
Secures administrative settings with PBKDF2 hashing against master password 'automa@123'.
"""

import hashlib
import hmac
import time
import logging
from typing import Tuple

logger = logging.getLogger("AutomaShield.SecurityAuth")

class SecurityManager:
    MASTER_SALT = b"AutomaShieldEnterpriseSecuritySalt_2026_x86"
    # PBKDF2 hash of 'automa@123'
    MASTER_PBKDF2_HEX = hashlib.pbkdf2_hmac("sha256", b"automa@123", MASTER_SALT, 100_000).hex()

    def __init__(self):
        self._is_authenticated = False
        self._last_auth_time = 0.0
        self._failed_attempts = 0
        self._lockout_until = 0.0

    @property
    def is_authenticated(self) -> bool:
        # 15-minute session timeout
        if self._is_authenticated and (time.time() - self._last_auth_time < 900):
            return True
        self._is_authenticated = False
        return False

    def verify_password(self, candidate_password: str) -> Tuple[bool, str]:
        now = time.time()
        if now < self._lockout_until:
            wait_sec = int(self._lockout_until - now)
            return False, f"Access denied. 3 consecutive failed attempts. Locked out for {wait_sec} seconds."

        candidate_hash = hashlib.pbkdf2_hmac("sha256", candidate_password.encode("utf-8"), self.MASTER_SALT, 100_000).hex()

        if hmac.compare_digest(candidate_hash, self.MASTER_PBKDF2_HEX):
            self._is_authenticated = True
            self._last_auth_time = now
            self._failed_attempts = 0
            logger.info("Administrative authorization granted. Settings unlocked.")
            return True, "Authorization successful. Settings unlocked."
        else:
            self._failed_attempts += 1
            logger.warning(f"Invalid master password attempt. Failure count: {self._failed_attempts}")
            if self._failed_attempts >= 3:
                self._lockout_until = now + 30.0
                self._failed_attempts = 0
                logger.error("Three consecutive failed authentication attempts. 30s lockout engaged.")
                return False, "Access denied. 3 consecutive failed attempts. Locked out for 30 seconds."

            rem = 3 - self._failed_attempts
            return False, f"Invalid master password. {rem} attempt(s) remaining before lockout."

    def lock_session(self):
        self._is_authenticated = False
        self._last_auth_time = 0.0
        logger.info("Administrative session manually locked.")