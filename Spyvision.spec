# -*- mode: python ; coding: utf-8 -*-
"""Сборка Spyvision.exe (PyInstaller)."""

import os

block_cipher = None

# Фон главного экрана необязателен: landing.py работает и без него.
datas = [('webscan/landing.html', 'webscan')]
if os.path.exists('webscan/bg.jfif'):
    datas.append(('webscan/bg.jfif', 'webscan'))

# Базы уязвимостей (KEV, ExploitDB, ответы NVD) в exe НЕ вшиваются:
# они скачиваются в кэш пользователя ~/.spyvision/cache.

a = Analysis(
    ['scan.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'webscan',
        'webscan.cli',
        'webscan.ui_server',
        'webscan.landing',
        'webscan.report',
        'webscan.scanner',
        'webscan.fingerprint',
        'webscan.vulndb',
        'webscan.vulndb.cache',
        'webscan.vulndb.catalog_http',
        'webscan.vulndb.exploitdb',
        'webscan.vulndb.kev',
        'webscan.vulndb.nvd',
        'webscan.vulndb.scoring',
        'webscan.vulndb.versions',
        'webscan.report_vulns',
        'webscan.knowledge',
        'webscan.fixes',
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
        'webscan.checks.sast',
        'webscan.checks.access_control',
        'webscan.checks.waf_bypass',
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
