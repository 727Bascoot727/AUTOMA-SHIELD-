"""
Automa Shield - Multi-Engine Core Scanner (scanner_core.py)
Combines SHA-256 hash lookup, Shannon entropy analysis, YARA inspection, and behavioral heuristics.
"""

import os
import hashlib
import math
import logging
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass
from db import DatabaseManager
from yara_engine import YaraRuleMatcher, HeuristicAnalyzer

logger = logging.getLogger("AutomaShield.ScannerCore")

@dataclass
class ScanResult:
    file_path: str
    sha256: str
    is_threat: bool
    threat_name: Optional[str]
    detection_engine: str
    severity: str
    entropy: float
    file_size_bytes: int
    status: str
    quarantine_id: Optional[int] = None

class ScannerCore:
    def __init__(self, db_manager: DatabaseManager, yara_matcher: Optional[YaraRuleMatcher] = None, heuristic_analyzer: Optional[HeuristicAnalyzer] = None):
        self.db = db_manager
        self.yara_matcher = yara_matcher or YaraRuleMatcher()
        self.heuristic = heuristic_analyzer or HeuristicAnalyzer()
        self._is_cancelled = False

    def cancel_scan(self):
        self._is_cancelled = True

    def calculate_sha256(self, file_path: str, chunk_size: int = 65536) -> str:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    def calculate_shannon_entropy(self, file_path: str, max_bytes: int = 1048576) -> float:
        try:
            with open(file_path, "rb") as f:
                data = f.read(max_bytes)
            if not data:
                return 0.0
            length = len(data)
            counts = [0] * 256
            for b in data:
                counts[b] += 1
            entropy = 0.0
            for count in counts:
                if count == 0:
                    continue
                p = count / length
                entropy -= p * math.log2(p)
            return round(entropy, 4)
        except Exception:
            return 0.0

    def scan_file(self, file_path: str) -> ScanResult:
        if not os.path.exists(file_path):
            return ScanResult(
                file_path=file_path, sha256="", is_threat=False, threat_name=None,
                detection_engine="FILE_IO", severity="NONE", entropy=0.0,
                file_size_bytes=0, status="FILE_NOT_FOUND"
            )

        try:
            file_size = os.path.getsize(file_path)
            sha256_hash = self.calculate_sha256(file_path)
            entropy = self.calculate_shannon_entropy(file_path)

            # 1. Signature Database Lookup O(1)
            sig_match = self.db.query_signature(sha256_hash)
            if sig_match:
                logger.warning(f"[DB THREAT] Match: {sig_match['malware_name']} | Target: {file_path}")
                return ScanResult(
                    file_path=file_path, sha256=sha256_hash, is_threat=True,
                    threat_name=sig_match["malware_name"], detection_engine="LOCAL_DB",
                    severity=sig_match.get("severity", "HIGH"), entropy=entropy,
                    file_size_bytes=file_size, status="INFECTED"
                )

            # 2. YARA Rule Matcher
            yara_hit = self.yara_matcher.scan_file(file_path)
            if yara_hit.get("is_threat"):
                return ScanResult(
                    file_path=file_path, sha256=sha256_hash, is_threat=True,
                    threat_name=yara_hit.get("rule_name", "YARA.Threat.Pattern"),
                    detection_engine="YARA_RULES", severity=yara_hit.get("severity", "HIGH"),
                    entropy=entropy, file_size_bytes=file_size, status="SUSPICIOUS"
                )

            # 3. Heuristic & Entropy Verification
            heur_hit = self.heuristic.inspect_file(file_path, entropy=entropy)
            if heur_hit.get("is_threat"):
                return ScanResult(
                    file_path=file_path, sha256=sha256_hash, is_threat=True,
                    threat_name=heur_hit.get("threat_name", "Heuristic.Anomaly"),
                    detection_engine="HEURISTIC", severity=heur_hit.get("severity", "MEDIUM"),
                    entropy=entropy, file_size_bytes=file_size, status="SUSPICIOUS"
                )

            return ScanResult(
                file_path=file_path, sha256=sha256_hash, is_threat=False,
                threat_name=None, detection_engine="CLEAN", severity="NONE",
                entropy=entropy, file_size_bytes=file_size, status="CLEAN"
            )

        except Exception as e:
            logger.error(f"Error inspecting {file_path}: {e}")
            return ScanResult(
                file_path=file_path, sha256="", is_threat=False, threat_name=None,
                detection_engine="ERROR", severity="NONE", entropy=0.0,
                file_size_bytes=0, status=f"ERROR: {str(e)}"
            )

    def scan_directory_sync(self, root_dir: str, progress_callback: Optional[Callable[[str, int], None]] = None) -> List[ScanResult]:
        self._is_cancelled = False
        results = []
        count = 0

        for root, _, files in os.walk(root_dir):
            for file_name in files:
                if self._is_cancelled:
                    logger.info("Scan cancelled by user.")
                    return results

                full_path = os.path.join(root, file_name)
                res = self.scan_file(full_path)
                results.append(res)
                count += 1

                if progress_callback:
                    progress_callback(full_path, count)

        return results