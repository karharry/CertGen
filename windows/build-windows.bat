@echo off
python -m pip install -r requirements.txt pyinstaller
rem free-threaded/abi3t Pythons: cryptography needs python3t.dll bundled (harmless otherwise)
for /f "delims=" %%i in ('python -c "import sys,os,glob;g=glob.glob(os.path.join(sys.base_prefix,'**','python3t.dll'),recursive=True);print(g[0] if g else '')"') do set P3T=%%i
if defined P3T (set EXTRA=--add-binary "%P3T%;.") else (set EXTRA=)
python -m PyInstaller --onefile --noconsole --name CertGen --icon icon.ico %EXTRA% --add-data "static;static" app.py
