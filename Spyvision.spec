# -*- mode: python ; coding: utf-8 -*-
"""Сборка Spyvision.exe (PyInstaller)."""

block_cipher = None

a = Analysis(
    ['scan.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('webscan/landing.html', 'webscan'),
        ('webscan/bg.jfif', 'webscan'),
    ],
    hiddenimports=[
        'webscan',
        'webscan.cli',
        'webscan.ui_server',
        'webscan.landing',
        'webscan.report',
        'webscan.scanner',
        'webscan.knowledge',
        'webscan.knowledge_fix',
        'webscan.checks.active',
        'webscan.checks.headers',
        'webscan.checks.cookies',
        'webscan.checks.cors',
        'webscan.checks.tls',
        'webscan.checks.exposed',
        'webscan.checks.forms',
        'webscan.checks.methods',
        'webscan.checks.infoleak',
        'webscan.checks.clientside',
        'bs4',
        'requests',
        'certifi',
        'charset_normalizer',
        'urllib3',
        'idna',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='Spyvision',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
