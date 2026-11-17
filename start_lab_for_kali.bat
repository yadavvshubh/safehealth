@echo off
setlocal EnableExtensions
REM SafeHealth lab launcher for the Kali VAPT run (vapt\kali\kali_vapt.py). LAB USE ONLY.
REM Starts the HARDENED build (https, port 5443) and the deliberately VULNERABLE baseline
REM (http, port 5444, from ..\SafeHealth-baseline) in two windows. Close those windows to stop them.
REM Usage: double-click, or   start_lab_for_kali.bat [address-to-listen-on]
cd /d "%~dp0"
set "HERE=%CD%"
set "BASELINE=%HERE%\..\SafeHealth-baseline"
if not exist "%BASELINE%\run.py" set "BASELINE="

REM ---- a Python that already has the packages: project venv, baseline venv, then the installed Python
set "PY="
set "NEED=import flask, argon2, pyotp, cryptography, flask_limiter, qrcode"
for %%P in ("%HERE%\.venv\Scripts\python.exe" "%HERE%\..\SafeHealth-baseline\.venv\Scripts\python.exe") do (
  if not defined PY if exist "%%~P" "%%~P" -c "%NEED%" >nul 2>nul && set "PY=%%~P"
)
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY for %%P in (py.exe python.exe) do if not defined PY where %%P >nul 2>nul && set "PY=%%P"
if not defined PY (
  echo Python was not found. Install Python 3.12 from python.org ^(tick "Add python.exe to PATH"^), then run this again.
  pause
  exit /b 1
)
"%PY%" -c "%NEED%" >nul 2>nul
if errorlevel 1 (
  echo Installing SafeHealth's Python packages ^(one time^)...
  "%PY%" -m pip install -r requirements.txt
  if errorlevel 1 ( echo Package install failed. & pause & exit /b 1 )
)
echo Python: %PY%

REM ---- demo accounts (kept if they already exist)
if not exist "instance\demo_credentials.txt" (
  echo Creating demo accounts for the HARDENED build...
  "%PY%" manage.py seed
  if errorlevel 1 ( pause & exit /b 1 )
)
if defined BASELINE if not exist "%BASELINE%\instance\demo_credentials.txt" (
  echo Creating demo accounts for the BASELINE build...
  pushd "%BASELINE%"
  "%PY%" manage.py seed
  popd
)

REM ---- listen only on the VirtualBox host-only network when there is one
set "BIND=%~1"
if not defined BIND for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%\vapt\kali\host_only_ip.ps1"`) do set "BIND=%%I"
if not defined BIND (
  set "BIND=0.0.0.0"
  echo.
  echo WARNING: no VirtualBox host-only adapter found, so both builds listen on ALL networks.
  echo          Devices on your Wi-Fi can reach the vulnerable baseline while it runs. Close it when done.
)

set "SAFEHEALTH_HOST=%BIND%"
set "SAFEHEALTH_CERT_HOSTS=%BIND%"
start "SafeHealth HARDENED - https://%BIND%:5443" /D "%HERE%" cmd /k call "%PY%" run.py
if defined BASELINE (
  set "SAFEHEALTH_I_UNDERSTAND_THIS_IS_VULNERABLE=1"
  start "SafeHealth BASELINE - VULNERABLE - http://%BIND%:5444" /D "%BASELINE%" cmd /k call "%PY%" run.py
)

set "CHECK=%BIND%"
if "%BIND%"=="0.0.0.0" set "CHECK=127.0.0.1"
echo Waiting for the servers to start...
timeout /t 6 /nobreak >nul
curl.exe -sk -o NUL -w "  hardened answers HTTP %%{http_code}\n" "https://%CHECK%:5443/login"
if defined BASELINE curl.exe -s -o NUL -w "  baseline answers HTTP %%{http_code}\n" "http://%CHECK%:5444/login"

set "TARGET=%BIND%"
if "%BIND%"=="0.0.0.0" set "TARGET=THIS-PC-IP"
echo.
echo ==== Ready. On Kali run: ====
echo   git clone https://github.com/yadavvshubh/safehealth.git   ^(already cloned: cd safehealth ^&^& git pull^)
echo   python3 safehealth/vapt/kali/kali_vapt.py --baseline http://%TARGET%:5444 --hardened https://%TARGET%:5443
echo.
echo It asks for passwords from each build's instance\demo_credentials.txt (opening them in Notepad now).
echo If Windows Firewall asks about Python: click Allow and tick BOTH Private and Public.
if "%BIND%"=="0.0.0.0" (
  echo.
  echo This PC's addresses - use the one on the network Kali is connected to:
  ipconfig | findstr /c:"IPv4"
)
start "" notepad "%HERE%\instance\demo_credentials.txt"
if defined BASELINE start "" notepad "%BASELINE%\instance\demo_credentials.txt"
echo.
pause
