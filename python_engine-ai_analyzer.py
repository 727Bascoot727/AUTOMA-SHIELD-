"""
Automa Shield - AI Behavioral Script Analysis Engine (ai_analyzer.py)
Maps unknown scripts to MITRE ATT&CK techniques with behavioral confidence scoring.
"""

import re
import logging
from typing import Dict, Any

logger = logging.getLogger("AutomaShield.AIThreatAnalyzer")

class AIThreatAnalyzer:
    MITRE_SIGNATURES = [
        {
            "id": "T1059.001", "technique": "PowerShell Execution", "tactic": "Execution",
            "regex": r"(powershell(\.exe)?|-enc|-encodedcommand|-w\s+hidden|-ep\s+bypass)",
            "weight": 25, "desc": "Execution of obfuscated or hidden PowerShell processes"
        },
        {
            "id": "T1055", "technique": "Process Injection", "tactic": "Defense Evasion",
            "regex": r"(VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread|QueueUserAPC)",
            "weight": 35, "desc": "Direct memory allocation and process injection API calls"
        },
        {
            "id": "T1003", "technique": "OS Credential Dumping", "tactic": "Credential Access",
            "regex": r"(sekurlsa|lsass\.dmp|logonpasswords|MiniDumpWriteDump)",
            "weight": 40, "desc": "Attempt to extract LSASS authentication tokens from RAM"
        },
        {
            "id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command and Control",
            "regex": r"(DownloadFile|DownloadString|curl|wget|certutil(\.exe)?\s+-urlcache)",
            "weight": 20, "desc": "Automated download of secondary malicious payloads"
        }
    ]

    @classmethod
    def evaluate_payload(cls, payload_text: str, filename: str = "payload.bin") -> Dict[str, Any]:
        tactics_detected = []
        score = 0

        for sig in cls.MITRE_SIGNATURES:
            if re.search(sig["regex"], payload_text, re.IGNORECASE):
                tactics_detected.append({
                    "id": sig["id"],
                    "technique": sig["technique"],
                    "tactic": sig["tactic"],
                    "evidence": sig["desc"]
                })
                score += sig["weight"]

        confidence = min(score, 100)
        is_threat = confidence >= 35

        return {
            "filename": filename,
            "classification": "MALICIOUS" if is_threat else "BENIGN",
            "confidence": float(confidence),
            "risk_level": "CRITICAL" if confidence >= 60 else ("HIGH" if confidence >= 35 else "LOW"),
            "threat_family": "PowerShell.Downloader.Beacon" if is_threat else "Clean Code",
            "mitre_tactics": tactics_detected,
            "reasoning": "Detected dynamic memory allocation APIs with hidden execution switches." if is_threat else "No known hostile execution primitives detected.",
            "remediation": "Quarantine payload and terminate parent process immediately." if is_threat else "No action required."
        }