@echo off
:: ================================================================
:: run_server.bat — start the ShodanSnipe FastAPI server
:: Run this FIRST, in its own terminal. Then run crewai.bat.
:: ================================================================
setlocal
set HERE=%~dp0
set CORE=%HERE%..\core

echo Starting ShodanSnipe server from %CORE% ...
cd /d "%CORE%"

:: Make sibling core modules importable (db, scope, etc. live here)
python server.py

pause
