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

REM ── Report output budget ────────────────────────────────────
REM  Raise this if reports look truncated; lower it to cut token spend.
REM  This is the SAME knob the Control Center "Report max tokens" slider sets,
REM  and poc_crew.py reads it (REPORT_MAX_TOKENS) with a sane per-provider floor.
if "%REPORT_MAX_TOKENS%"=="" (
    set REPORT_MAX_TOKENS=8000
)

REM ── Global result-depth override (scales EVERY hardcoded cap) ────────────────
REM  GLOBAL_LIMIT_MULTIPLIER=2  -> twice as many hosts/findings everywhere.
REM  GLOBAL_NO_LIMITS=1         -> remove caps entirely (exhaustive, slower).
REM  Or target one: set LIMIT_RECON_HOSTS=200 / LIMIT_VULN_DETECT_HOSTS=100 etc.
if "%GLOBAL_LIMIT_MULTIPLIER%"=="" (
    set GLOBAL_LIMIT_MULTIPLIER=1
)

REM ── Crew stages (which agents run, incl. nmap) ──────────────
REM By default the crew uses the stage selection you saved in the Control Center
REM (poc_crew fetches it from the running server). To drive stages straight from
REM here instead — e.g. the server isn't running, or you want to FORCE nmap on —
REM uncomment the next line. CREW_STAGES set here takes precedence over the server:
REM set CREW_STAGES=osint,recon,nmap,auth,vuln,threat,report
REM
REM For nmap to ACTUALLY run, all of these must also be true (the bat can't fake them):
REM   1. nmap binary on PATH        (test in THIS window: nmap --version)
REM   2. tools\nmap_tool.py present AND agents\nmap_recon_agent.py present
REM   3. "nmap" in the active stages (Control Center toggle, or CREW_STAGES above)
REM Windows: stealth SYN needs Npcap + Administrator; without admin, set the Control
REM Center "nmap intensity" to normal (-sV) — it needs no raw socket.

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
