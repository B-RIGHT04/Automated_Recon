# XSS Recon Automation Tool

Automates reconnaissance/information-gathering when hunting for XSS vulnerabilities
(bug bounty + personal research; pentest engagements planned for later).

## Setup

**Important: activate the virtual environment every time you open a new terminal
for this project.** It does NOT stay active across terminal sessions.

```bash
cd ~/Documents/~xss-recon
source venv/bin/activate
```

Your prompt should show `(venv)` at the start when it's active.

Install dependencies (only needed once, or after requirements.txt changes):
```bash
pip install -r requirements.txt
```

## Project Structure

- `config/` — settings (target, scope allowlist, rate limits, tool paths)
- `data/` — scan output, organized per-target and per-phase
- `core/` — pipeline logic (scope, discovery, params, reflect, classify, report)
- `cli.py` — entry point to run individual phases or the full pipeline

## Status

Project skeleton created. Pipeline modules not yet implemented.
