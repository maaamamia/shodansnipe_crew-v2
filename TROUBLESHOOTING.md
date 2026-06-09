# ShodanSnipe Crew — Troubleshooting Guide

---

## STEP 1 — Python Version

CrewAI requires **Python 3.12** exactly. Not 3.11, 3.13, or 3.14.

```powershell
# Check installed versions
py -0

# Install Python 3.12 if missing
# https://www.python.org/downloads/release/python-3120/
# ✓ Use the standard installer (NOT Microsoft Store / pythoncore)
# ✓ Check "Add Python to PATH" during install

# Verify
py -3.12 --version   # must print 3.12.x
```

---

## STEP 2 — One-Time Setup (run once per machine)

```powershell
cd C:\Users\migue\Downloads\shodansnipe_crew-main\shodansnipe_crew-main\launchers
setup_crewai.bat
```

**If setup_crewai.bat fails, run manually:**

```powershell
cd C:\...\launchers

# Create venv with Python 3.12
py -3.12 -m venv crewai_env

# Activate
crewai_env\Scripts\activate

# Install everything
pip install --upgrade pip
pip install "crewai[anthropic]"
pip install "crewai[tools]"
pip install requests python-dotenv
```

**If Activate.ps1 is blocked:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then activate again
crewai_env\Scripts\activate
```

---

## STEP 3 — Activate Venv (every session)

Every time you open a new PowerShell window:

```powershell
cd C:\Users\migue\Downloads\shodansnipe_crew-main\shodansnipe_crew-main\launchers
crewai_env\Scripts\activate
```

Your prompt should show `(crewai_env)` prefix:
```
(crewai_env) PS C:\...\launchers>
```

---

## STEP 4 — Set API Key (every session or permanently)

```powershell
# This session only
$env:ANTHROPIC_API_KEY = 'sk-ant-api03-...'

# Verify it's set
echo $env:ANTHROPIC_API_KEY

# Permanently (survives reboots — run once)
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY","sk-ant-api03-...","User")
# Close and reopen PowerShell after this
```

> Use **single quotes** `'...'` in PowerShell if your key contains special characters.
> Double quotes can mangle `!`, `$`, `#`, `@`.

---

## STEP 5 — Correct Model Strings

### The error you saw:
```
404 - model: anthropic/claude-sonnet-4-6
```

### Why it fails:
`anthropic/claude-sonnet-4-6` is a LiteLLM routing prefix format.
It does **not** work when `provider="anthropic"` is set — the native
Anthropic SDK strips the prefix and sends `anthropic/claude-sonnet-4-6`
literally to the API, which doesn't exist.

### Fix in `poc_crew.py` around line 414:

```python
# ❌ WRONG — causes 404
return LLM(model="claude-opus-4-6",              api_key=key, provider="anthropic")
return LLM(model="anthropic/claude-sonnet-4-6",  api_key=key, provider="anthropic")

# ✅ CORRECT — native provider (recommended)
return LLM(model="claude-sonnet-4-6", api_key=key, provider="anthropic")
return LLM(model="claude-opus-4-5",   api_key=key, provider="anthropic")
return LLM(model="claude-haiku-4-5",  api_key=key, provider="anthropic")

# ✅ CORRECT — LiteLLM routing (no provider= argument)
return LLM(model="anthropic/claude-sonnet-4-5")   # note: 4-5 not 4-6 for LiteLLM
```

### Model string reference:

| Provider | Model String | Notes |
|----------|-------------|-------|
| Anthropic | `claude-sonnet-4-6` | Best balance, use this |
| Anthropic | `claude-opus-4-5` | Most capable |
| Anthropic | `claude-haiku-4-5` | Fastest/cheapest |
| OpenAI | `gpt-4o-mini` | Cheap, fast |
| OpenAI | `gpt-4o` | Most capable |
| Ollama | `ollama/llama3.2` | Local, no key needed |

---

## STEP 6 — Tool Limit Error

### The error you saw:
```
Tool 'shodan_search' arguments validation failed:
limit: Input should be less than or equal to 100 [input_value=200]
```

### Why it fails:
The crew's `ShodanSearchInput` model caps `limit` at 100.
When the LLM tries to pass `limit=200`, Pydantic rejects it.

### Fix in `tools/shodansnipe_tools.py`:

Find the `ShodanSearchInput` class and change:
```python
# ❌ WRONG
limit: int = Field(25, ge=1, le=100, description="Max results (1-100)")

# ✅ CORRECT
limit: int = Field(25, ge=1, le=500, description="Max results (1-500)")
```

Or tell the LLM in the agent prompt never to exceed 100:
Add to the agent's backstory or task description:
```
"Always use limit=25 for initial searches. Never exceed limit=100."
```

---

## STEP 7 — Nmap Not Working

### Check 1 — Is nmap installed?
```powershell
nmap --version
```

If not found, install it:
```powershell
# Option A — Chocolatey (recommended)
choco install nmap

# Option B — Manual installer
# https://nmap.org/download.html
# Install to default path, the installer adds nmap to PATH
```

After install, **close and reopen PowerShell**, then `nmap --version` again.

### Check 2 — Run as Administrator

Nmap SYN scans need raw socket access. On Windows this requires admin rights.

```
Right-click PowerShell → "Run as Administrator"
```

Then activate venv and run crew again.

### Check 3 — Windows Defender blocking raw packets

Windows Defender SmartScreen or Firewall may block nmap's raw sockets.
Test: temporarily disable Defender real-time protection → run nmap again.
If it works, add nmap to Defender exclusions permanently.

### Check 4 — Verify nmap can scan anything

```powershell
# Simple ping scan — no root/admin needed
nmap -sn 8.8.8.8

# SYN scan — needs admin
nmap -sS -T2 --top-ports 100 8.8.8.8
```

### Check 5 — Disable nmap and run passive only

If you can't get nmap working, skip it:
```powershell
$env:ENABLE_NMAP = "0"
crewai.bat anthropic
```
The crew skips the Nmap Recon stage and continues Recon → Vuln → Report.

---

## STEP 8 — Running the Full Stack (Correct Order)

### Terminal 1 — Server (runs on Python 3.14, your machine)

```powershell
cd C:\Users\migue\Downloads\shodansnipeAI
$env:SHODANSNIPE_PASSPHRASE = 'your-db-passphrase'
& C:/Users/migue/AppData/Local/Python/pythoncore-3.14-64/python.exe -m uvicorn server:app --host 127.0.0.1 --port 8000
```

Wait for:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

Open **http://127.0.0.1:8000** → set your scope in the UI.

### Terminal 2 — Crew (runs on Python 3.12 venv)

```powershell
cd C:\Users\migue\Downloads\shodansnipe_crew-main\shodansnipe_crew-main\launchers

$env:ANTHROPIC_API_KEY = 'sk-ant-...'

crewai_env\Scripts\activate

# Run with your chosen autonomy mode:
crewai.bat anthropic           # uses mode set in UI (default: HITL)
crewai.bat anthropic scoped    # auto within scope, confirm outside
crewai.bat anthropic full      # no confirmations (type "yes" when prompted)
```

---

## STEP 9 — Health Checks

Run these before starting the crew:

```powershell
# Server alive?
curl http://127.0.0.1:8000/api/health

# Scope set?
curl http://127.0.0.1:8000/api/scope

# MCP endpoint working?
curl http://127.0.0.1:8000/mcp

# nmap on PATH?
nmap --version
```

---

## Quick Error Reference

| Error | Fix |
|-------|-----|
| `404 model: anthropic/claude-sonnet-4-6` | Change model to `claude-sonnet-4-6` (no prefix) in `poc_crew.py` |
| `limit must be <= 100` | Change `le=100` to `le=500` in `tools/shodansnipe_tools.py` |
| `ImportError: Anthropic native provider` | `pip install "crewai[anthropic]"` in crewai_env |
| `ModuleNotFoundError: crewai` | Venv not activated — run `crewai_env\Scripts\activate` |
| `ModuleNotFoundError: db / scope` | Set `PYTHONPATH` to the `core/` folder |
| `Connection refused 127.0.0.1:8000` | Start the server first (Terminal 1) |
| `hmac check failed` / wrong passphrase | Use single quotes: `$env:SHODANSNIPE_PASSPHRASE = 'pass'` |
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `LLM: -anthropic` in bat output | Drop the dash: `crewai.bat anthropic` not `-anthropic` |
| `[NMAP] disabled` | Install nmap, run as Admin, or set `ENABLE_NMAP=0` |
| `litellm: could not pre-load bedrock` | Harmless warning — ignore it |
| Browser: nothing clickable | Hard refresh: `Ctrl+Shift+R` |
| Browser: 404 on API calls | Use `http://127.0.0.1:8000` not file:// or other port |


### `assistant message prefill` error / `This model does not support assistant message prefill`

CrewAI's "force final answer" mechanism appends an assistant turn to the conversation,
which Claude doesn't support. Fix:

```powershell
crewai_env\Scripts\activate
pip install "crewai[anthropic]>=0.80.0"
```

If upgrading isn't possible, switch to OpenAI as the provider:
```powershell
crewai.bat openai
```

### `Maximum iterations reached. Requesting final answer.`

The agent ran out of tool calls before finishing. This often triggers the prefill error above.
Combined fix: upgrade CrewAI AND reduce task complexity — give the agent a narrower goal.

