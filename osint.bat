@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>nul || (
    echo [!] Nie znaleziono Pythona. Zainstaluj Python 3.10+ z python.org i zaznacz "Add python.exe to PATH".
    pause
    exit /b 1
)
python -c "import requests, socks" 2>nul || (
    echo [i] Instaluje brakujace biblioteki...
    python -m pip install -r requirements.txt || ( pause & exit /b 1 )
)
python osint.py %*
if errorlevel 1 if "%~1"=="" pause
