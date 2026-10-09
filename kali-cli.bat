@echo off
REM ==============================================================================
REM Kali Linux VirtualBox Helper Script
REM Runs commands inside Kali Linux VM directly from Windows PowerShell / CMD
REM ==============================================================================

set VBOX_EXE="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
set VM_NAME="kali-linux-2026.2-virtualbox-amd64"
set VM_USER=kali
set VM_PASS=kali

if "%1"=="" goto help
if "%1"=="stats" goto stats
if "%1"=="import" goto import
if "%1"=="export" goto export
if "%1"=="logs" goto logs
if "%1"=="status" goto status
if "%1"=="ui" goto ui
if "%1"=="dashboard" goto ui
if "%1"=="test" goto test
if "%1"=="restart" goto restart
if "%1"=="tools" goto tools
if "%1"=="ssh" goto ssh

:ui
echo [*] Opening Sentinel AI Security Dashboard in your default browser...
start http://localhost:8000
goto end

:tools
echo [*] Checking Linux Security Tools in Kali VM...
%VBOX_EXE% guestcontrol %VM_NAME% run --username %VM_USER% --password %VM_PASS% --exe "/bin/bash" -- -c "yara --version; clamscan --version; tshark --version"
goto end

:test
echo [*] Running End-to-End Live Security Layer Tests...
python test_live_server.py
goto end

:restart
echo [*] Restarting Sentinel AI Gateway inside Kali VM...
%VBOX_EXE% guestcontrol %VM_NAME% run --username %VM_USER% --password %VM_PASS% --exe "/bin/bash" -- -c "/home/kali/llm_platform/start.sh"
echo [*] Server restarted successfully.
goto end

:stats
echo [*] Fetching Dataset Inventory from Kali VM...
%VBOX_EXE% guestcontrol %VM_NAME% run --username %VM_USER% --password %VM_PASS% --exe "/bin/bash" -- -c "cd /home/kali/llm_platform && python3 -m backend.cli stats"
goto end

:import
echo [*] Running Dataset Ingestion inside Kali VM...
%VBOX_EXE% guestcontrol %VM_NAME% run --username %VM_USER% --password %VM_PASS% --exe "/bin/bash" -- -c "cd /home/kali/llm_platform && python3 -m backend.cli import --dataset all"
goto end

:export
echo [*] Exporting Normalized CSVs inside Kali VM...
%VBOX_EXE% guestcontrol %VM_NAME% run --username %VM_USER% --password %VM_PASS% --exe "/bin/bash" -- -c "cd /home/kali/llm_platform && python3 -m backend.cli export-csv"
goto end

:logs
echo [*] Viewing live Server Logs from Kali VM...
%VBOX_EXE% guestcontrol %VM_NAME% run --username %VM_USER% --password %VM_PASS% --exe "/usr/bin/cat" -- /home/kali/llm_platform/server.log
goto end

:status
echo [*] Checking API Health via Host port 8000 (Forwarded to Kali VM)...
curl -s http://localhost:8000/health
echo.
goto end

:ssh
echo [*] Connecting to Kali Linux terminal via SSH...
ssh -p 2222 kali@127.0.0.1
goto end

:help
echo =======================================================
echo Sentinel AI - Kali Linux VirtualBox CLI Controller
echo =======================================================
echo Usage:
echo   kali-cli.bat ui        - Web UI Dashboard browser me open karna (http://localhost:8000)
echo   kali-cli.bat test      - Live Security & YARA/ClamAV tests run karna
echo   kali-cli.bat tools     - Linux tools version check karna (yara, clamav, tshark)
echo   kali-cli.bat restart   - Gateway server restart karna
echo   kali-cli.bat status    - API health check karna
echo   kali-cli.bat logs      - Server log check karna
echo   kali-cli.bat stats     - Dataset records count check karna
echo   kali-cli.bat import    - Datasets re-import karna
echo   kali-cli.bat export    - CSV files re-export karna
echo   kali-cli.bat ssh       - Direct Kali VM terminal me login karna
echo =======================================================

:end
