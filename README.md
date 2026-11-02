# AUTOMA-SHIELD-
#  Automa Shield | Enterprise-Grade Endpoint Protection & Threat Isolation System

**Automa Shield** is a lightweight, modern, and high-performance local antivirus and endpoint protection system designed for enterprise environments. It combines high-speed multi-threaded core scanning, advanced heuristics, YARA rule pattern matching, cloud intelligence (VirusTotal API), and real-time behavioral AI analysis into a clean, modern user interface.

---

##  Key Features

* **Multi-Threaded Core Scanner:** Fast and efficient file scanning powered by chunked SHA-256 hashing and SQLite WAL management.
* **Heuristic & Behavioral Engine:** Detects zero-day and polymorphic malware using Shannon Entropy analysis and process injection pattern detection.
* **YARA Rule Inspection:** Compiles and evaluates custom binaries and script patterns to uncover suspicious strings.
* **Cloud Intelligence:** Asynchronous non-blocking lookups via VirusTotal v3 API to cross-reference 70+ global engine verdicts.
* **Encrypted Quarantine Vault:** Safely isolates malicious threats into an encrypted 12-byte IV container with full false-positive restoration and secure DOD wipe capabilities.
* **Real-Time File System Observer:** Background daemon actively monitoring critical directories for instant payload interception.
* **Enterprise Security Controls:** Master password-protected settings (`automa@123`) and seamless system tray integration.
* **Standalone Executable Ready:** Fully configured for single-file packaging using PyInstaller (`AutomaShield.exe`).

---

##  Project Structure

```text
AutomaShield/
├── main_gui.py          # Main application graphical interface & dashboard
├── scanner_core.py      # Multi-threaded file scanner and local database manager
├── yara_engine.py       # Heuristic analysis and YARA rule compilation engine
├── cloud_check.py       # Asynchronous VirusTotal cloud threat intelligence client
├── quarantine.py        # Secure encrypted quarantine vault and restoration manager
├── AutomaShield.spec    # PyInstaller compilation configuration file
└── requirements.txt     # Python dependencies list
