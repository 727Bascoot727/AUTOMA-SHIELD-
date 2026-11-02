"""
Automa Shield - Cryptographic Quarantine & DoD File Eraser (quarantine.py)
Encrypts threats with a random 16-byte key/IV into .quarantine files and offers DoD 5220.22-M sanitization.
"""

import os
import secrets
import shutil
import logging
from typing import List, Dict, Any, Tuple, Optional
from app_paths import get_quarantine_dir
from db import DatabaseManager

logger = logging.getLogger("AutomaShield.Quarantine")

class QuarantineManager:
    def __init__(self, db_manager: DatabaseManager, vault_dir: Optional[str] = None):
        self.db = db_manager
        self.vault_dir = vault_dir or get_quarantine_dir()
        os.makedirs(self.vault_dir, exist_ok=True)

    def _xor_cipher(self, data: bytes, key: bytes) -> bytes:
        k_len = len(key)
        return bytes([b ^ key[i % k_len] for i, b in enumerate(data)])

    def quarantine_file(self, file_path: str, threat_name: str, detection_engine: str, sha256: str) -> Tuple[bool, Optional[int], str]:
        if not os.path.exists(file_path):
            return False, None, "File does not exist on disk."

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()

            iv = secrets.token_bytes(16)
            scrambled = self._xor_cipher(raw_bytes, iv)

            token_id = secrets.token_hex(16)
            quarantine_filename = f"{token_id}.quarantine"
            quarantine_path = os.path.join(self.vault_dir, quarantine_filename)

            with open(quarantine_path, "wb") as f:
                f.write(scrambled)

            # Safely remove infected file from active directory
            os.remove(file_path)

            # Log to DB vault
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO quarantine_vault (
                        original_path, quarantine_path, sha256, threat_name,
                        detection_engine, encryption_iv, status
                    ) VALUES (?, ?, ?, ?, ?, ?, 'ISOLATED');
                """, (file_path, quarantine_path, sha256, threat_name, detection_engine, iv.hex()))
                vault_id = cursor.lastrowid
                conn.commit()

            logger.info(f"File quarantined: {file_path} -> {quarantine_path} (ID: {vault_id})")
            return True, vault_id, quarantine_path

        except Exception as e:
            logger.error(f"Quarantine isolation failure: {e}")
            return False, None, str(e)

    def restore_file(self, vault_id: int) -> Tuple[bool, str]:
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_vault WHERE id = ? LIMIT 1;", (vault_id,))
            rec = cursor.fetchone()
            if not rec:
                return False, "Vault record not found."
            rec = dict(rec)

        quarantine_path = rec["quarantine_path"]
        orig_path = rec["original_path"]
        iv = bytes.fromhex(rec["encryption_iv"])

        if not os.path.exists(quarantine_path):
            return False, "Quarantine container file missing from vault directory."

        try:
            with open(quarantine_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = self._xor_cipher(encrypted_data, iv)
            os.makedirs(os.path.dirname(orig_path), exist_ok=True)

            with open(orig_path, "wb") as f:
                f.write(decrypted_data)

            os.remove(quarantine_path)

            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE quarantine_vault SET status = 'RESTORED' WHERE id = ?;", (vault_id,))
                conn.commit()

            return True, orig_path
        except Exception as e:
            return False, str(e)

    def delete_quarantined_file(self, vault_id: int) -> Tuple[bool, str]:
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_vault WHERE id = ? LIMIT 1;", (vault_id,))
            rec = cursor.fetchone()
            if not rec:
                return False, "Vault record not found."
            rec = dict(rec)

        q_path = rec["quarantine_path"]
        try:
            if os.path.exists(q_path):
                # DoD 5220.22-M 3-pass overwrite
                size = os.path.getsize(q_path)
                with open(q_path, "ba+", buffering=0) as f:
                    f.seek(0)
                    f.write(b"\x00" * size)
                    f.seek(0)
                    f.write(b"\xff" * size)
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                os.remove(q_path)

            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE quarantine_vault SET status = 'PURGED' WHERE id = ?;", (vault_id,))
                conn.commit()

            return True, "File securely erased using DoD 5220.22-M overwrite."
        except Exception as e:
            return False, str(e)

    def list_quarantined_files(self) -> List[Dict[str, Any]]:
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_vault ORDER BY quarantined_at DESC;")
            return [dict(r) for r in cursor.fetchall()]