@echo off
REM ============================================================
REM  setup_crewai.bat — One-time setup for ShodanSnipe Crew
REM  Run from: launchers\ folder
REM  Requires: Python 3.12
REM ============================================================

echo.
echo  ============================================================
echo   ShodanSnipe Crew — Setup
echo  ============================================================
echo.

REM ── Check Python 3.12 ──────────────────────────────────────
where py >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python launcher (py.exe) not found.
    echo          Install Python 3.12 from https://python.org/downloads/
    echo          Check "Add to PATH" during install.
    pause
    exit /b 1
)

py -3.12 --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python 3.12 not installed.
    echo          You have:
    py -0
    echo.
    echo          Install Python 3.12 from:
    echo          https://www.python.org/downloads/release/python-3120/
    echo          (Use the standard installer, NOT Microsoft Store)
    pause
    exit /b 1
)

echo  [OK] Python 3.12 found
py -3.12 --version

REM ── Create virtual environment ──────────────────────────────
if not exist "crewai_env\" (
    echo.
    echo  [SETUP] Creating Python 3.12 virtual environment...
    py -3.12 -m venv crewai_env
    if errorlevel 1 (
        echo  [ERROR] Failed to create venv.
        pause
        exit /b 1
    )
    echo  [OK] venv created
) else (
    echo  [OK] venv already exists
)

REM ── Activate ────────────────────────────────────────────────
call crewai_env\Scripts\activate.bat
if errorlevel 1 (
    echo  [ERROR] Could not activate venv.
    echo          Try running PowerShell as Administrator and:
    echo          Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
    pause
    exit /b 1
)

echo  [OK] venv activated

REM ── Upgrade pip ─────────────────────────────────────────────
echo.
echo  [SETUP] Upgrading pip...
python -m pip install --upgrade pip --quiet

REM ── Install CrewAI with Anthropic native provider ───────────
echo  [SETUP] Installing crewai[anthropic]...
pip install "crewai[anthropic]" --quiet
if errorlevel 1 (
    echo  [ERROR] Failed to install crewai[anthropic]
    echo          Try manually: pip install "crewai[anthropic]"
    pause
    exit /b 1
)
echo  [OK] crewai[anthropic] installed

REM ── Install CrewAI tools ────────────────────────────────────
echo  [SETUP] Installing crewai[tools]...
pip install "crewai[tools]" --quiet

REM ── Install python-nmap (wrapper for nmap binary) ───────────
echo  [SETUP] Installing python-nmap...
pip install python-nmap --quiet
if errorlevel 1 (
    echo  [WARN] python-nmap install failed — nmap features may be limited
) else (
    echo  [OK] python-nmap installed
)

REM ── Install other dependencies ──────────────────────────────
echo  [SETUP] Installing other dependencies...
pip install requests python-dotenv aiohttp dnspython --quiet
echo  [OK] Core dependencies installed

REM ── Check nmap binary ───────────────────────────────────────
echo.
where nmap >nul 2>&1
if errorlevel 1 (
    echo  [WARN] nmap binary NOT found on PATH.
    echo.
    echo         To enable active scanning (optional):
    echo         Option A: choco install nmap
    echo         Option B: https://nmap.org/download.html
    echo                   (Install to default path, it adds to PATH automatically)
    echo.
    echo         After installing nmap:
    echo         1. Close and reopen this window
    echo         2. Run as Administrator for SYN scans
    echo.
    echo         To run without nmap (passive Shodan only):
    echo         set ENABLE_NMAP=0 before running crewai.bat
) else (
    echo  [OK] nmap found:
    nmap --version | findstr "Nmap version"
    echo.
    echo  NOTE: nmap SYN scans require Administrator privileges on Windows.
    echo        Right-click PowerShell -> Run as Administrator before running the crew.
)

REM ── Summary ─────────────────────────────────────────────────
echo.
echo  ============================================================
echo   Setup complete!
echo  ============================================================
echo.
echo   Next steps:
echo.
echo   1. Start the server (Terminal 1):
echo      cd ..\
echo      set SHODANSNIPE_PASSPHRASE=your-passphrase
echo      python -m uvicorn server:app --host 127.0.0.1 --port 8000
echo.
echo   2. Set your scope in the UI:
echo      http://127.0.0.1:8000
echo.
echo   3. Set your API key (Terminal 2):
echo      set ANTHROPIC_API_KEY=sk-ant-...
echo.
echo   4. Run the crew:
echo      crewai.bat anthropic
echo      crewai.bat anthropic scoped
echo      crewai.bat anthropic full
echo.
echo   Model options:
echo      claude-sonnet-4-6   (default, recommended)
echo      claude-opus-4-5     (most capable)
echo      claude-haiku-4-5    (fastest/cheapest)
echo.
pause
