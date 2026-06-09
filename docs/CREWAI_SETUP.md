# crewai.bat — Setup & Usage Guide

Step-by-step instructions for running the ShodanSnipe CrewAI crew locally on Windows.

---

## Prerequisites Checklist

Before running `crewai.bat` for the first time, confirm each of these:

```
[ ] Python 3.12 installed  (not 3.11, not 3.13 — CrewAI has wheel issues on other versions)
[ ] server.py is running   (must be started first in a separate terminal)
[ ] API key set            (Anthropic, OpenAI, or Ollama running locally)
[ ] Scope set in UI        (optional — crew will prompt if missing)
[ ] Autonomy mode set      (optional — defaults to HITL if not set)
```

---

## Step 1 — Install Python 3.12

Check what you have:

```powershell
py --list
```

If 3.12 is not listed:

```powershell
winget install Python.Python.3.12
```

After install, confirm:

```powershell
py -3.12 --version
# Python 3.12.x
```

---

## Step 2 — Start the ShodanSnipe Server

Open a terminal and run:

```powershell
cd C:\path\to\shodansnipeAI
python server.py
```

You will be prompted for a **passphrase** on the first run. This encrypts the local database — write it down. Use the same passphrase every time.

```
Enter passphrase to unlock database:
```

Leave this terminal open. The server must be running before `crewai.bat` will work.

Verify it is up:

```powershell
curl http://127.0.0.1:8000/api/health
```

---

## Step 3 — Set Your API Key

Open a **new** PowerShell terminal (the one you will use for `crewai.bat`).

### Option A — Anthropic Claude (recommended)

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."
```

### Option B — OpenAI

```powershell
$env:OPENAI_API_KEY = "sk-proj-..."
```

### Option C — Ollama (local, no key needed)

Install Ollama from https://ollama.com, then:

```powershell
ollama pull llama3.2
ollama serve
```

No API key needed. The bat defaults to `http://localhost:11434/v1`.

---

## Step 4 — Set Scope and Autonomy Mode in the UI

Open **http://localhost:8000** in your browser.

1. Click **⚙ Config** (top right)
2. In the **◈ Scope** tab, add your target:
   - Type an org name and press Enter → becomes `org:"Acme Corp"`
   - Type a domain → becomes `hostname:acme.com`
   - Type a CIDR → becomes `net:203.0.113.0/24`
   - Type `AS12345` → becomes `AS12345`
   - Use the free-form textarea at the bottom for raw Shodan syntax
3. Click **Apply Scope**

4. Click **⚙ MCP Config** in the nav bar
5. Under **Settings → MCP Autonomy Mode**, select:
   - **HITL** — crew asks you to approve every action (safest, default)
   - **Scoped** — crew runs automatically within the defined scope
   - **Full Auto** — crew runs with no prompts (asks for written confirmation at startup)

The bat reads both scope and autonomy mode from the server automatically.

---

## Step 5 — Run crewai.bat

From the same terminal where you set the API key:

```powershell
cd C:\path\to\shodansnipeAI
.\crewai.bat anthropic
```

### All valid usage patterns

```powershell
# Use mode and scope from UI (recommended)
.\crewai.bat anthropic
.\crewai.bat openai
.\crewai.bat ollama

# Override autonomy mode (ignores UI setting for this run only)
.\crewai.bat anthropic scoped
.\crewai.bat anthropic full
.\crewai.bat anthropic hitl
.\crewai.bat openai scoped

# Override mode with Ollama
.\crewai.bat ollama scoped
```

> ⚠ **Common mistake:** Do NOT include a leading dash.
> Wrong: `.\crewai.bat -anthropic`
> Right: `.\crewai.bat anthropic`

---

## What the bat Does — Step by Step

When you run `.\crewai.bat anthropic`, here is exactly what happens:

```
1. Strips leading dash from argument (safety)
2. Checks Python 3.12 is installed
3. Checks server.py is reachable at http://127.0.0.1:8000
4. Checks MCP endpoint returns 6 tools
5. Reads autonomy mode from server (/api/config/autonomy)
      → uses UI setting unless you passed a second argument
6. Reads full scope from server (/api/scope)
      → builds Shodan query: org:"SANS Institute" hostname:sans.org
      → sets TARGET_ORG and TARGET_SCOPE environment variables
7. If mode = FULL AUTO → prints warning, asks "Proceed? (yes/no)"
8. Checks ANTHROPIC_API_KEY (or OPENAI_API_KEY) is set
9. Creates Python 3.12 venv in .\crewai_env\ (first run only)
      → installs crewai and requests
10. Activates venv
11. Sets environment variables for poc_crew.py
12. Runs: python poc_crew.py
```

---

## First-Run Output (What to Expect)

```
=========================================================
  ShodanSnipe + CrewAI
  LLM: anthropic
  ShodanSnipe: http://127.0.0.1:8000
=========================================================

 [OK] Python 3.12
 [OK] ShodanSnipe is running at http://127.0.0.1:8000
 [OK] MCP: 6 tools
 [OK] Autonomy mode from UI: scoped
 [OK] Scope name:  SANS Institute
 [OK] Scope query: org:"SANS Institute" hostname:sans.org

=========================================================
  Mode: scoped  |  Scope: SANS Institute
=========================================================

 [SETUP] Creating Python 3.12 venv...       ← first run only
 [SETUP] Installing crewai and requests...  ← first run only, takes ~2 min
 [OK] Installed

=========================================================
  Running CrewAI crew...
=========================================================

============================================================
  ShodanSnipe + CrewAI — Dynamic Threat-Hunting Crew
  LLM provider: anthropic
  Autonomy mode: SCOPED
  Target org:    SANS Institute
  Scope query:   org:"SANS Institute" hostname:sans.org
============================================================
  ShodanSnipe: READY at http://127.0.0.1:8000
============================================================
  [Credits] 847/1000 (85%) → limit=200
```

---

## Environment Variables — Complete Reference

### Variables You Must Set

| Variable | How to set | Example |
|----------|-----------|---------|
| `ANTHROPIC_API_KEY` | PowerShell, before running bat | `$env:ANTHROPIC_API_KEY = "sk-ant-..."` |
| `OPENAI_API_KEY` | PowerShell, before running bat | `$env:OPENAI_API_KEY = "sk-proj-..."` |

Only one is required — whichever provider you pass to the bat.

### Variables Set Automatically by crewai.bat

You do not set these manually. The bat reads them from the server and passes them to `poc_crew.py`.

| Variable | Source | What it contains |
|----------|--------|-----------------|
| `TARGET_ORG` | `/api/scope` → `name` field | `SANS Institute` |
| `TARGET_SCOPE` | `/api/scope` → built from orgs/cidrs/asns/domains | `org:"SANS Institute" hostname:sans.org` |
| `MCP_AUTONOMY_MODE` | `/api/config/autonomy` → `mode` field | `hitl` / `scoped` / `full` |
| `LLM_PROVIDER` | First argument to bat | `anthropic` / `openai` / `ollama` |
| `SHODANSNIPE_URL` | Hardcoded in bat | `http://127.0.0.1:8000` |

### Variables You Can Override Manually

Set these before running the bat to override defaults:

| Variable | Default | Override example | Effect |
|----------|---------|-----------------|--------|
| `SHODANSNIPE_PASSPHRASE` | *(prompt on startup)* | `$env:SHODANSNIPE_PASSPHRASE = "mypassword"` | Skips the interactive passphrase prompt — useful for automation |
| `SHODANSNIPE_URL` | `http://127.0.0.1:8000` | `$env:SHODANSNIPE_URL = "http://192.168.1.5:8000"` | Point crew at a remote server |
| `OLLAMA_URL` | `http://localhost:11434/v1` | `$env:OLLAMA_URL = "http://192.168.1.10:11434/v1"` | Use Ollama on another machine |
| `CVE_ADVISORY` | *(empty)* | `$env:CVE_ADVISORY = "CVE-2024-38475 affects Apache..."` | Analyst will assess CVE exposure against findings |
| `TARGET_ORG` | *(from server)* | `$env:TARGET_ORG = "Acme Corp"` | Override scope without using the UI |
| `TARGET_SCOPE` | *(from server)* | `$env:TARGET_SCOPE = 'org:"Acme Corp" net:203.0.113.0/24'` | Override full scope query |

### Setting Variables Permanently (Session vs Permanent)

**Current session only** (gone when you close the terminal):
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

**Permanent for your user** (survives terminal restarts):
```powershell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...", "User")
```

**Permanent system-wide** (all users, needs admin):
```powershell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...", "Machine")
```

Verify a variable is set:
```powershell
echo $env:ANTHROPIC_API_KEY
```

---

## Recommended Local Test Setup

This is the exact sequence for a clean local test run:

### Terminal 1 — Server

```powershell
cd C:\Users\migue\Downloads\shodansnipeAI
python server.py
# Enter your passphrase when prompted
# Leave this terminal open
```

### Terminal 2 — Crew

```powershell
cd C:\Users\migue\Downloads\shodansnipeAI

# Set your API key (Anthropic example)
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."

# Optional: skip passphrase prompt on server restart
$env:SHODANSNIPE_PASSPHRASE = "yourpassphrase"

# Run the crew
.\crewai.bat anthropic
```

### Browser

1. Open **http://localhost:8000**
2. Set scope: `SANS Institute, sans.org` in ⚙ Config → ◈ Scope
3. Set Shodan API key in ⚙ Config → ⬡ API Key
4. Set AI model in ⚙ Config → ✦ AI Model (choose Anthropic, enter `claude-sonnet-4-6`)
5. Set autonomy mode in ⚙ MCP Config → Settings (choose Scoped for testing)
6. Switch back to Terminal 2 and run the bat

---

## Troubleshooting

**`[ERROR] Python 3.12 not found`**
```powershell
winget install Python.Python.3.12
# After install, open a new terminal and try again
```

**`[ERROR] Cannot reach ShodanSnipe at http://127.0.0.1:8000`**  
`server.py` is not running. Start it in Terminal 1 first.

**`[ERROR] ANTHROPIC_API_KEY not set`**  
You set the variable in a different terminal, or used `set` instead of `$env:`. In PowerShell always use:
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```
Note: if you use the old `cmd.exe` syntax (`set ANTHROPIC_API_KEY=...`) in PowerShell it will appear to work but the variable won't actually be set.

**`LLM: -anthropic` in the header**  
You typed `.\crewai.bat -anthropic`. Remove the dash: `.\crewai.bat anthropic`.

**`[INFO] No scope set in UI - crew will prompt for target`**  
No scope is saved on the server. Either set it in the browser UI, or the crew will ask you interactively:
```
Enter target scope: org:"SANS Institute" hostname:sans.org
```

**Autonomy shows HITL even though you selected Scoped in the UI**  
The server needs the updated `server.py` with the `/api/config/autonomy` endpoint. Confirm by running:
```powershell
curl http://127.0.0.1:8000/api/config/autonomy
# Should return: {"mode":"scoped"}
```

**Venv install fails / pip errors**  
Delete the venv and let it recreate:
```powershell
Remove-Item -Recurse -Force .\crewai_env
.\crewai.bat anthropic
```

**`litellm: could not pre-load bedrock-runtime` warnings**  
These are harmless. LiteLLM prints them because `botocore` (AWS SDK) is not installed. The crew still runs fine — it just cannot use Bedrock models, which you are not using.

**Crew starts but immediately fails on first Shodan search**  
Your Shodan API key is not saved in the UI. Open the browser, go to ⚙ Config → ⬡ API Key, enter and save it. The server must have the key before the crew can search.

---

## venv Location

The bat creates and manages a Python 3.12 virtual environment at:

```
.\crewai_env\
```

Relative to wherever `crewai.bat` lives. You can delete this folder at any time — the bat will recreate it on the next run (takes ~2 minutes to reinstall packages).

If you need to manually activate the venv to debug or install extra packages:

```powershell
.\crewai_env\Scripts\Activate.ps1
pip install some-package
```

---

## Running Without the bat (Advanced)

If you want to run `poc_crew.py` directly without the bat — for debugging, or on Linux/Mac:

```powershell
# Activate venv
.\crewai_env\Scripts\Activate.ps1

# Set all variables manually
$env:ANTHROPIC_API_KEY   = "sk-ant-..."
$env:SHODANSNIPE_URL     = "http://127.0.0.1:8000"
$env:LLM_PROVIDER        = "anthropic"
$env:MCP_AUTONOMY_MODE   = "scoped"
$env:TARGET_ORG          = "SANS Institute"
$env:TARGET_SCOPE        = 'org:"SANS Institute" hostname:sans.org'

# Run
python poc_crew.py
```

On Linux/Mac (bash):
```bash
source crewai_env/bin/activate

export ANTHROPIC_API_KEY="sk-ant-..."
export SHODANSNIPE_URL="http://127.0.0.1:8000"
export LLM_PROVIDER="anthropic"
export MCP_AUTONOMY_MODE="scoped"
export TARGET_ORG="SANS Institute"
export TARGET_SCOPE='org:"SANS Institute" hostname:sans.org'

python poc_crew.py
```
