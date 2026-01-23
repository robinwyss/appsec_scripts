@echo off
REM Build ASTRA for Windows (must run on Windows)

echo Building ASTRA for Windows...

pip install -r requirements.txt pyinstaller

cd ASTRA

pyinstaller --onefile ^
  --name astra-windows ^
  --add-data "config.example.yaml;." ^
  --hidden-import=dynatrace_api ^
  --collect-all reportlab ^
  astra_report.py

echo ✓ Windows build complete: dist\astra-windows.exe
