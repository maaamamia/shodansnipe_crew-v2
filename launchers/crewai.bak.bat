@echo off
:: ================================================================
:: crewai.bat — ShodanSnipe + CrewAI
::
:: Usage:
::   crewai.bat anthropic               (Claude, mode from UI)
::   crewai.bat openai                  (OpenAI, mode from UI)
::   crewai.bat anthropic scoped        (override mode)
::   crewai.bat anthropic full          (override mode)
::   crewai.bat ollama                  (local Ollama)
::
:: NOTE: do NOT include a leading dash — use: crewai.bat anthropic
::       NOT: crewai.bat -anthropic
:: ================================================================
setlocal enabledelayedexpansion

set SNIPE_DIR=%~dp0
set VENV_DIR=%SNIPE_DIR%crewai_env
set SNIPE_URL=http://127.0.0.1:8000

:: Strip any leading dash from provider argument (common mistake)
set _RAW_PROV=%~1
if defined _RAW_PROV set LLM_PROVIDER=%_RAW_PROV:-=%
if "%LLM_PROVIDER%"=="" set LLM_PROVIDER=openai

set MODE_OVERRIDE=%~2

echo.
echo  =========================================================
echo   ShodanSnipe + CrewAI
echo   LLM: %LLM_PROVIDER%
echo   ShodanSnipe: %SNIPE_URL%
echo  =========================================================
echo.

:: ── Python 3.12 check ────────────────────────────────────────────────────
py -3.12 --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python 3.12 not found.
    echo  Install: winget install Python.Python.3.12
    pause & exit /b 1
)
echo  [OK] Python 3.12

:: ── Check ShodanSnipe is reachable ───────────────────────────────────────
powershell -Command "try{Invoke-WebRequest -Uri '%SNIPE_URL%/api/health' -TimeoutSec 3 -UseBasicParsing|Out-Null;exit 0}catch{exit 1}" >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Cannot reach ShodanSnipe at %SNIPE_URL%
    echo  Start server.py in another terminal first.
    pause & exit /b 1
)
echo  [OK] ShodanSnipe is running at %SNIPE_URL%

:: ── MCP endpoint check ───────────────────────────────────────────────────
powershell -Command "try{$b='{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}';$r=(Invoke-WebRequest -Uri '%SNIPE_URL%/mcp' -Method POST -Body $b -ContentType 'application/json' -TimeoutSec 5 -UseBasicParsing).Content|ConvertFrom-Json;Write-Host(' [OK] MCP: '+$r.result.tools.Count+' tools')}catch{Write-Host ' [WARN] MCP check failed'}"

:: ── Read autonomy mode from server ───────────────────────────────────────
if not "%MODE_OVERRIDE%"=="" (
    set MCP_AUTONOMY_MODE=%MODE_OVERRIDE%
    echo  [OK] Autonomy mode overridden to: %MODE_OVERRIDE%
) else (
    set MCP_AUTONOMY_MODE=hitl
    for /f "usebackq delims=" %%M in (`powershell -Command "try{((Invoke-WebRequest -Uri '%SNIPE_URL%/api/config/autonomy' -TimeoutSec 3 -UseBasicParsing).Content|ConvertFrom-Json).mode}catch{'hitl'}"`) do set MCP_AUTONOMY_MODE=%%M
    echo  [OK] Autonomy mode from UI: !MCP_AUTONOMY_MODE!
)

:: ── Read full scope from server and build query string ───────────────────
:: Use a temp file to avoid for/f multiline issues
set SCOPE_TMP=%TEMP%\snipe_scope_%RANDOM%.txt
powershell -Command ^
  "try{" ^
  "  $s=(Invoke-WebRequest -Uri '%SNIPE_URL%/api/scope' -TimeoutSec 3 -UseBasicParsing).Content|ConvertFrom-Json;" ^
  "  if($s.is_empty -eq $true -or $s.name -eq '(none)'){" ^
  "    'SCOPE_EMPTY=1'|Out-File '%SCOPE_TMP%' -Encoding utf8" ^
  "  } else {" ^
  "    $parts=@();" ^
  "    foreach($o in $s.orgs){$parts+='org:\"'+$o+'\"'};" ^
  "    foreach($c in $s.cidrs){$parts+='net:'+$c};" ^
  "    foreach($a in $s.asns){$parts+=$a};" ^
  "    foreach($d in $s.domains){$parts+='hostname:'+$d};" ^
  "    $q=if($parts.Count -gt 0){$parts -join ' '}else{$s.name};" ^
  "    ('SCOPE_NAME='+$s.name)|Out-File '%SCOPE_TMP%' -Encoding utf8;" ^
  "    ('SCOPE_QUERY='+$q)|Add-Content '%SCOPE_TMP%' -Encoding utf8" ^
  "  }" ^
  "}catch{'SCOPE_EMPTY=1'|Out-File '%SCOPE_TMP%' -Encoding utf8}"

:: Parse the temp file
set SCOPE_NAME=
set SCOPE_QUERY=
set SCOPE_EMPTY=
if exist "%SCOPE_TMP%" (
    for /f "usebackq tokens=1* delims==" %%K in ("%SCOPE_TMP%") do (
        if "%%K"=="SCOPE_EMPTY"  set SCOPE_EMPTY=1
        if "%%K"=="SCOPE_NAME"   set SCOPE_NAME=%%L
        if "%%K"=="SCOPE_QUERY"  set SCOPE_QUERY=%%L
    )
    del "%SCOPE_TMP%" >nul 2>&1
)

if defined SCOPE_EMPTY (
    echo  [INFO] No scope set in UI - crew will prompt for target
) else (
    echo  [OK] Scope name:  !SCOPE_NAME!
    echo  [OK] Scope query: !SCOPE_QUERY!
    set TARGET_ORG=!SCOPE_NAME!
    set TARGET_SCOPE=!SCOPE_QUERY!
)

echo.
echo  =========================================================
echo   Mode: !MCP_AUTONOMY_MODE!  ^|  Scope: !SCOPE_NAME!
echo  =========================================================
echo.

:: ── Warn on full autonomous mode ─────────────────────────────────────────
if /i "!MCP_AUTONOMY_MODE!"=="full" (
    echo  [WARNING] FULL AUTONOMOUS mode - no confirmations.
    set /p "CONFIRM=  Proceed? (yes/no): "
    if /i not "!CONFIRM!"=="yes" ( echo  Aborted. & exit /b 0 )
    echo.
)

:: ── API key check ────────────────────────────────────────────────────────
if /i "%LLM_PROVIDER%"=="openai" (
    if "%OPENAI_API_KEY%"=="" (
        echo  [ERROR] OPENAI_API_KEY not set. Run: set OPENAI_API_KEY=sk-...
        pause & exit /b 1
    )
    echo  [OK] OpenAI key set
)
if /i "%LLM_PROVIDER%"=="anthropic" (
    if "%ANTHROPIC_API_KEY%"=="" (
        echo  [ERROR] ANTHROPIC_API_KEY not set. Run: set ANTHROPIC_API_KEY=sk-ant-...
        pause & exit /b 1
    )
    echo  [OK] Anthropic key set
)

:: ── venv setup ───────────────────────────────────────────────────────────
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo  [SETUP] Creating Python 3.12 venv...
    py -3.12 -m venv "%VENV_DIR%"
    call "%VENV_DIR%\Scripts\activate.bat"
    echo  [SETUP] Installing crewai and requests...
    pip install --quiet --upgrade pip
    pip install crewai requests
    if errorlevel 1 ( echo  [ERROR] pip install failed. & pause & exit /b 1 )
    echo  [OK] Installed
) else (
    call "%VENV_DIR%\Scripts\activate.bat"
    echo  [OK] venv active
)

:: ── Run the crew ─────────────────────────────────────────────────────────
echo.
echo  =========================================================
echo   Running CrewAI crew...
echo  =========================================================
echo.

set SHODANSNIPE_URL=%SNIPE_URL%
set LLM_PROVIDER=%LLM_PROVIDER%
set MCP_AUTONOMY_MODE=!MCP_AUTONOMY_MODE!
if defined TARGET_ORG   set TARGET_ORG=!TARGET_ORG!
if defined TARGET_SCOPE set TARGET_SCOPE=!TARGET_SCOPE!

REM NMAP active-recon stage: 1=on (default), 0=passive Shodan only
if "%ENABLE_NMAP%"=="" set ENABLE_NMAP=1

REM Make tools/ and agents/ importable (folder structure layout)
set PYTHONPATH=%SNIPE_DIR%..\tools;%SNIPE_DIR%..\agents;%SNIPE_DIR%..\core;%SNIPE_DIR%;%PYTHONPATH%

python "%SNIPE_DIR%poc_crew.py"

echo.
echo  =========================================================
echo  Done.
pause
