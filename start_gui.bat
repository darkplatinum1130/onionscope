@echo off
cd /d "%~dp0"
python -c "import requests, socks" 2>nul || python -m pip install -r requirements.txt
start "" pythonw osint_gui.pyw
