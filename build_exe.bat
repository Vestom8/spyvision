@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo === Spyvision: сборка .exe ===
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 exit /b 1

python -m PyInstaller --noconfirm --clean Spyvision.spec
if errorlevel 1 exit /b 1

echo.
echo Готово: dist\Spyvision.exe
echo Запуск: dist\Spyvision.exe
echo (откроется главный экран в браузере; окно консоли не закрывайте)
exit /b 0
