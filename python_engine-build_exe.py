"""
Automa Shield - Automated PyInstaller Builder (build_exe.py)
===========================================================
Executes pre-build validation, installs build prerequisites, and invokes PyInstaller.
"""

import os
import sys
import subprocess
import shutil
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AutomaShield.Builder")

def build_standalone_executable():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    spec_path = os.path.join(base_dir, "AutomaShield.spec")

    if not os.path.exists(spec_path):
        logger.error(f"AutomaShield.spec not found at: {spec_path}")
        return False

    logger.info("Executing PyInstaller compilation for AutomaShield.exe...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        spec_path
    ]

    try:
        proc = subprocess.run(cmd, cwd=base_dir, check=True)
        dist_dir = os.path.join(base_dir, "dist")
        logger.info(f"Compilation finished successfully. Artifacts available in: {dist_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"PyInstaller execution failed with error code: {e.returncode}")
        return False
    except Exception as ex:
        logger.error(f"Unexpected build error: {ex}")
        return False

if __name__ == "__main__":
    success = build_standalone_executable()
    sys.exit(0 if success else 1)