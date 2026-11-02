# -*- mode: python ; coding: utf-8 -*-
"""
Automa Shield - Enterprise PyInstaller Specification File (AutomaShield.spec)
=============================================================================
Builds a single, standalone executable (AutomaShield.exe) for corporate endpoint deployment.

Build Command:
    pyinstaller AutomaShield.spec
"""

import sys
import os

block_cipher = None

BASE_DIR = os.path.dirname(os.path.abspath(SPEC)) if 'SPEC' in locals() else os.path.abspath('.')

a = Analysis(
    ['main_gui.py'],
    pathex=[BASE_DIR],
    binaries=[],
    datas=[
        ('app_paths.py', '.'),
        ('db.py', '.'),
        ('scanner_core.py', '.'),
        ('yara_engine.py', '.'),
        ('quarantine.py', '.'),
        ('cloud_check.py', '.'),
        ('ai_analyzer.py', '.'),
        ('realtime_monitor.py', '.'),
        ('scheduler.py', '.'),
        ('signature_updater.py', '.'),
        ('security_auth.py', '.'),
        ('tray_manager.py', '.'),
        ('network_monitor.py', '.')
    ],
    hiddenimports=[
        'sqlite3',
        'hashlib',
        'hmac',
        'secrets',
        'uuid',
        'json',
        'urllib.request',
        'concurrent.futures',
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'customtkinter',
        'pystray',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
        'psutil'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['unittest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AutomaShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None
)