# Skill — Adding a Capability Module

A **module** is a Control Center toggle that turns one capability on or off for a run. The 28
modules are defined in one place — `MODULE_REGISTRY` in `core/settings.py` — and read by the
crew via the `CREW_MODULES` environment variable.

## 1. Register the module

Add an entry to `MODULE_REGISTRY` in `core/settings.py`. Group it under the agent that owns it.

```python
MODULE_REGISTRY = [
    # … existing entries …
    {
        "key":  "my_capability",          # unique, snake_case — matches what poc_crew checks
        "group": "Vuln",                   # which agent group it shows under in the UI
        "name": "My Capability",           # label in the Control Center
        "desc": "One line the user reads to decide whether to enable it.",
        "default": True,                   # on by default?
        # "always_on": True,               # optional: locked on (core data tools)
        # "stage": "nmap",                 # optional: greys out when this stage is off
    },
]
```

That's all the UI needs — the Control Center renders the toggle automatically, grouped under
its agent, and `GET /api/crew/modules` will include it.

## 2. Gate the behaviour in the crew

A toggle does nothing until the crew **reads** it. `launchers/poc_crew.py` already maps
`CREW_MODULES` onto the agents it builds. Add your key to the relevant set, or add a new check:

```python
# in poc_crew.py main(), where CREW_MODULES is parsed
mods = {m.strip() for m in os.environ.get("CREW_MODULES", "").split(",") if m.strip()}

# example: only attach MyTool to the Vuln agent if the module is enabled
if "my_capability" in mods:
    extra_vuln_tools.append(MyTool())
```

If your module enables/disables a whole agent, map it to that agent's existing flag (the OSINT,
Auth, and Archive module sets are the worked examples already in `poc_crew.py`).

## 3. (Optional) add it to profiles

If a scan profile should include it, add the key to that profile's `modules` list in `PROFILES`
— see `ADDING_A_SCAN_PROFILE.md`.

## How the toggle reaches the crew

```
Control Center toggle → POST /api/crew/modules → saved server-side
        → GUI "Run Crew" (or the env) sets CREW_MODULES=key1,key2,…
        → poc_crew.py reads CREW_MODULES and attaches/skips the capability
```

## Checklist

- [ ] Entry added to `MODULE_REGISTRY` (unique `key`, correct `group`)
- [ ] `default` / `always_on` / `stage` set as appropriate
- [ ] `poc_crew.py` checks the key in `CREW_MODULES` and acts on it
- [ ] (Optional) added to the relevant profile(s)
- [ ] Verified: toggle in the Control Center, Save, run the crew, confirm behaviour changed
