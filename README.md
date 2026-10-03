# Automated Recon

A Python-orchestrated reconnaissance pipeline for gathering information about a target domain — subdomain enumeration, live host filtering, URL/endpoint crawling, and parameter extraction. Built for general-purpose recon (bug bounty, personal research, and eventually pentest engagements), not tied to hunting any specific vulnerability class.

It chains together established, actively-maintained Go-based recon tools (subfinder, httpx, katana) rather than reimplementing that logic in Python, and adds scope enforcement, deduplication, and structured output on top.

## ⚠️ Authorized use only

This tool sends real network requests to real targets. Only point it at domains you are explicitly authorized to test — a bug bounty program you're enrolled in, a pentest engagement with a signed scope, or infrastructure you own. Always configure `scope.rules` in `config/config.yaml` to match the program's actual in-scope/out-of-scope rules before running anything against a live target.

## What it does

The core pipeline runs in order:

1. **Discovery** — enumerates subdomains (`subfinder`), filters to only those currently resolving/live (`httpx`), and crawls them for URLs and endpoints (`katana`)
2. **Scope enforcement** — every stage is checked against `config/config.yaml`'s allow/deny rules, twice over (once right after enumeration, once again defensively right before live requests), so nothing out-of-scope ever gets touched
3. **Parameter extraction** — pulls parameters out of discovered URLs, JS files, and HTML forms
4. **Reporting** — produces a general findings report (interesting parameters, technology signals, etc.) and can diff against a previous run of the same target

## Deferred module (not currently active)

An earlier version of this project was scoped specifically around XSS hunting. That logic — reflection probing (canary-based detection of where input gets echoed back), context classification (what HTML/JS/attribute context a reflection lands in), and lightweight sanitization probing — has been set aside as an optional module rather than deleted. It's not part of the active pipeline, since the project's current purpose is general recon rather than testing for any one vulnerability class. It may get revisited and generalized in the future.

## Requirements

- Python 3.x
- [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx), [katana](https://github.com/projectdiscovery/katana) installed and available on your `PATH`
- Python dependencies in `requirements.txt`

## Setup

```bash
git clone https://github.com/B-RIGHT04/Automated_Recon.git
cd Automated_Recon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The virtual environment does **not** persist between terminal sessions — run `source venv/bin/activate` again at the start of every new session.

## Configuration

Edit `config/config.yaml` before running anything against a target:

- `target.domain` / `target.program_name` — the domain you're testing and a label for its output folder
- `target.headers` — any custom headers a bug bounty program requires (e.g. an identification header)
- `scope.rules` — a list of `pattern` / `status` (`allow`/`deny`) rules; checked against every host and URL before it's touched
- `tools.*` — binary names/paths for subfinder, httpx, katana, in case they're not on your default `PATH`
- `rate_limit.requests_per_second` / `timeout_seconds` — respect whatever rate limit the program you're testing requires; don't raise this without checking the program's actual rules first
- `output.base_dir` — where results get written (defaults to `data/`)

## Usage

```bash
python3 -c "from core.discovery import run_discovery; run_discovery()"
```

Output for a run against program `dell_bounty`, for example, lands in:

```
data/dell_bounty/
├── subdomains/   # raw, scope-filtered, and verified subdomain lists
├── live_hosts/   # hosts confirmed live by httpx
├── urls/         # crawled URLs, filtered to in-scope only
└── responses/    # stored response bodies (HTML/JS) from the crawl
```

## Project structure

```
Automated_Recon/
├── cli.py                  # command-line entry point
├── core/
│   └── discovery.py        # Phase 1 pipeline: subfinder -> httpx -> katana
│   └── scope.py            # scope loading/enforcement
├── config/
│   └── config.yaml         # target, scope, tool, and rate-limit configuration
├── data/                   # per-target output (gitignored)
├── requirements.txt
└── README.md
```

## Notes

- Large targets can genuinely take hours to crawl, especially with a low, program-mandated rate limit — this is expected, not necessarily a bug.
- If a stage returns zero results (0 subdomains, 0 live hosts), the pipeline raises a clear error rather than silently continuing — this usually means a transient network/DNS hiccup worth just re-running, not a configuration problem.
