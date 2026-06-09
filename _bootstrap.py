"""
_bootstrap.py — Single source of truth for import paths.

Drop this import at the top of any entry point (launchers, agents run directly)
and every folder becomes importable regardless of where you launch from:

    import _bootstrap   # noqa: F401  (must be first local import)

It adds core/, tools/, agents/ to sys.path so flat `import shodansnipe_tools`,
`import nmap_tool`, `import nmap_recon_agent`, `import db`, etc. all resolve.

Works for both layouts:
  - Structured:  shodansnipe/{core,tools,agents,launchers}/
  - Flat:        everything in one folder
"""
import os
import sys

# Find the project root. This file lives at the project root.
_ROOT = os.path.dirname(os.path.abspath(__file__))

# Candidate folders to add (structured layout). Flat layout = _ROOT itself.
_SUBDIRS = ("core", "tools", "agents", "launchers", "")

for _sub in _SUBDIRS:
    _path = os.path.join(_ROOT, _sub) if _sub else _ROOT
    if os.path.isdir(_path) and _path not in sys.path:
        sys.path.insert(0, _path)

# Expose the root for anything that needs to locate static/ or docs/
PROJECT_ROOT = _ROOT
