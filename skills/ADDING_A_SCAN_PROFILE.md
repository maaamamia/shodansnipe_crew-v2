# Skill — Adding a Scan Profile

A **profile** is a one-click preset that sets stages, modules, and limits together — like
**Quick**, **Comprehensive**, and **All**. Profiles live in `PROFILES` in `core/settings.py`.

## Add the profile

```python
PROFILES = {
    # … quick / comprehensive / all …
    "stealth": {
        "label": "Stealth",
        "desc":  "Quiet passive recon — minimal queries, no active scanning.",
        "stages":  ["recon", "report"],          # which pipeline stages run
        "modules": [                              # which capability module keys are on
            "shodan_search", "scope_control", "get_results", "get_history",
            "asn_hunt", "cert_transparency",
        ],
        "limits": {                               # overrides applied when the profile is picked
            "max_results_per_query": 25,
            "max_queries_per_run":   4,
            "report_section_chars":  6000,
        },
    },
}
```

- **`stages`** must be valid keys from `STAGE_REGISTRY` (`recon`, `nmap`, `vuln`, `report`).
  Dependencies are auto-added (e.g. `nmap`/`vuln` pull in `recon`).
- **`modules`** are keys from `MODULE_REGISTRY`. Always include the core/`always_on` ones
  (`shodan_search`, `scope_control`, `get_results`, `get_history`).
- **`limits`** only need the keys you want to override; the rest fall back to defaults.

## That's it

`apply_profile(name)` (already in `settings.py`) writes the stages/modules/limits into the saved
settings, and the Control Center renders the new profile card automatically from `PROFILES`.
`GET /api/crew/profiles` will list it; `POST /api/crew/profile {"name": "stealth"}` applies it.

## Guidance

- Keep the **active** capabilities (Nmap scan, sensitive-path probe, cloud-asset discovery) out
  of light profiles. Reserve them for deeper ones, and warn in `desc` that they touch targets.
- Match `limits` to the intent — a "quick" profile with a 1000-result cap isn't quick.
- Test by selecting it in the Control Center → Save → confirm the stages/modules/limits update.

## Checklist

- [ ] Entry added to `PROFILES` with `label`, `desc`, `stages`, `modules`, `limits`
- [ ] `stages` are valid; core modules included in `modules`
- [ ] Active tools only in deeper profiles, flagged in `desc`
- [ ] Verified in the Control Center (card appears, applying it updates everything)
