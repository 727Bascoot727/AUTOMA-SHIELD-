"""
Automa Shield - Dynamic Application Paths Resolver (app_paths.py)
Supports PyInstaller sys._MEIPASS runtime unpacking and standard OS paths.
"""

import os
import sys
from typing import List

def get_base_dir() -> str:
    """Return runtime base directory (bundled or raw source)."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

def get_data_dir() -> str:
    """Return persistent directory for local database and quarantine vault."""
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
    elif sys.platform.startswith("darwin"):
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")

    data_dir = os.path.join(base, "AutomaShield")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir

def get_db_path() -> str:
    """Return database file path."""
    return os.path.join(get_data_dir(), "antivirus.db")

def get_quarantine_dir() -> str:
    """Return quarantine directory."""
    q_dir = os.path.join(get_data_dir(), "quarantine_vault")
    os.makedirs(q_dir, exist_ok=True)
    return q_dir

def get_default_scan_paths() -> List[str]:
    """Return platform-specific default scan paths."""
    paths = []
    if sys.platform.startswith("win"):
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        paths.extend([
            os.path.join(user_profile, "Downloads"),
            os.path.join(user_profile, "Desktop"),
            os.environ.get("TEMP", "C:\\Windows\\Temp")
        ])
    else:
        home = os.path.expanduser("~")
        paths.extend([
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            "/tmp"
        ])
    return [p for p in paths if os.path.exists(p)]