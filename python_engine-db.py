"""
Automa Shield - Enterprise SQLite Database Manager (db.py)
Provides indexed threat signatures, scan audit logs, and quarantine records.
"""

import sqlite3
import os
import logging
from typing import List, Dict, Any, Optional
from app_paths import get_db_path

logger = logging.getLogger("AutomaShield.Database")

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_db_path()
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    malware_name TEXT NOT NULL,
                    sha256 TEXT UNIQUE NOT NULL,
                    threat_type TEXT DEFAULT 'Malware',
                    severity TEXT DEFAULT 'HIGH',
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sig_sha256 ON signatures(sha256);")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    threat_name TEXT NOT NULL,
                    detection_engine TEXT NOT NULL,
                    encryption_iv TEXT NOT NULL,
                    quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'ISOLATED'
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    total_scanned INTEGER NOT NULL,
                    threats_found INTEGER NOT NULL,
                    duration_seconds REAL NOT NULL,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    def seed_default_signatures(self):
        default_threats = [
            ("EICAR-Test-Signature", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "TestFile", "CRITICAL"),
            ("WannaCry.Ransomware.Dropper", "ed01ef2632ff1eab03e169e467069829e0785f030d458d081b16884189e95edc", "Ransomware", "CRITICAL"),
            ("Emotet.Banker.Trojan", "4a5a4e51240c0c666578701979b908bc17887556a3349d63c5a0ca97ef52a5c4", "Trojan", "HIGH"),
            ("CobaltStrike.Beacon.Stage", "7b52009b64fd0a2a49e6d8a939753077792b0554351edd0ac85a2ee2917e2712", "C2", "CRITICAL"),
            ("Mimikatz.LsassDump.Payload", "8a8f1025a7593c6753a795e1e1a067096d2745a5f64b4c7be44558e806c9cf1c", "CredentialTheft", "HIGH")
        ]
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for name, h, ttype, sev in default_threats:
                cursor.execute("""
                    INSERT OR IGNORE INTO signatures (malware_name, sha256, threat_type, severity)
                    VALUES (?, ?, ?, ?);
                """, (name, h.lower(), ttype, sev))
            conn.commit()

    def query_signature(self, sha256_hash: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM signatures WHERE sha256 = ? LIMIT 1;", (sha256_hash.lower(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def insert_signature(self, name: str, sha256_hash: str, threat_type: str = "Malware", severity: str = "HIGH") -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO signatures (malware_name, sha256, threat_type, severity)
                    VALUES (?, ?, ?, ?);
                """, (name, sha256_hash.lower(), threat_type, severity))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Database signature insert error: {e}")
            return False

    def get_all_signatures(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM signatures ORDER BY added_date DESC;")
            return [dict(r) for r in cursor.fetchall()]

    def log_scan_audit(self, scan_type: str, target_path: str, total_scanned: int, threats_found: int, duration_sec: float):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs (scan_type, target_path, total_scanned, threats_found, duration_seconds)
                VALUES (?, ?, ?, ?, ?);
            """, (scan_type, target_path, total_scanned, threats_found, duration_sec))
            conn.commit()

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_logs ORDER BY started_at DESC LIMIT ?;", (limit,))
            return [dict(r) for r in cursor.fetchall()]