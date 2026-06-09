@echo off
REM ============================================================
REM  crewai.bat — Run the ShodanSnipe Crew
REM
REM  Usage:
REM    crewai.bat anthropic           (mode from UI)
REM    crewai.bat anthropic scoped    (override to scoped)
REM    crewai.bat anthropic full      (override to full auto)
REM    crewai.bat openai
REM    crewai.bat ollama
REM ============================================================

set PROVIDER=%1
set MODE=%2

if "%PROVIDER%"=="" (
    echo  [ERROR] Specify a provider: anthropic, openai, or ollama
    echo  Usage: crewai.bat anthropic
    exit /b 1
)

REM ── Activate venv ───────────────────────────────────────────
if not exist "crewai_env\Scripts\activate.bat" (
    echo  [ERROR] venv not found. Run setup_crewai.bat first.
    exit /b 1
)

call crewai_env\Scripts\activate.bat

echo.
echo  ============================================================
echo   Mode: %MODE%  ^|  Scope: %TARGET_SCOPE%
echo  ============================================================
echo.

if "%MODE%"=="full" (
    echo  [WARNING] FULL AUTONOMOUS mode - no confirmations.
    set /p CONFIRM="  Proceed? (yes/no): "
    if /i not "%CONFIRM%"=="yes" (
        echo  Aborted.
        exit /b 0
    )
)

REM ── Check API key ────────────────────────────────────────────
if "%PROVIDER%"=="anthropic" (
    if "%ANTHROPIC_API_KEY%"=="" (
        echo  [ERROR] ANTHROPIC_API_KEY not set.
        echo          Run: set ANTHROPIC_API_KEY=sk-ant-...
        exit /b 1
    )
    echo  [OK] Anthropic key set
)

if "%PROVIDER%"=="openai" (
    if "%OPENAI_API_KEY%"=="" (
        echo  [ERROR] OPENAI_API_KEY not set.
        echo          Run: set OPENAI_API_KEY=sk-...
        exit /b 1
    )
    echo  [OK] OpenAI key set
)

REM ── Set autonomy mode ────────────────────────────────────────
if not "%MODE%"=="" (
    set MCP_AUTONOMY_MODE=%MODE%
)

echo  [OK] venv active

REM ── Run ─────────────────────────────────────────────────────
echo  ============================================================
echo   Running CrewAI crew...
echo  ============================================================

python poc_crew.py %PROVIDER% %MODE%
