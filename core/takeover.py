"""
takeover.py
Subdomain takeover detection: resolves CNAME records for in-scope
subdomains and checks any pointing at known third-party services for
the service's "unclaimed resource" fingerprint.

Fingerprint strings verified directly against EdOverflow/can-i-take-over-xyz
(the community-maintained reference list) on 2026-10-03. CNAME target
domains for services where that list leaves the field empty (GitHub Pages,
Heroku, Shopify, Netlify, Zendesk, Tumblr, UserVoice) are each vendor's own
documented custom-domain setup pattern, not from that dataset.

Read-only: DNS lookups (dig) plus, only for genuine candidates, a single
HTTP GET per host. Nothing destructive, no brute forcing.
"""
import json
import os
import subprocess
import time

import requests

from core.discovery import _header_flags
from core.scope import load_config

# confidence: "vulnerable" = fingerprint match is a strong signal something's
# actually takeover-able; "edge_case" = possible but needs more manual digging;
# "not_vulnerable" = this service's own fingerprint match does NOT by itself
# indicate a real takeover (carried through from the source dataset's own
# "Not vulnerable" status) -- included for visibility, not as a real lead.
SERVICES = {
    "Amazon S3": {
        "cname_domains": ["s3.amazonaws.com"],
        "fingerprint": "The specified bucket does not exist",
        "confidence": "vulnerable",
    },
    "GitHub Pages": {
        "cname_domains": ["github.io"],
        "fingerprint": "There isn't a GitHub Pages site here.",
        "confidence": "edge_case",
    },
    "Heroku": {
        "cname_domains": ["herokuapp.com", "herokussl.com"],
        "fingerprint": "No such app",
        "confidence": "edge_case",
    },
    "Shopify": {
        "cname_domains": ["myshopify.com"],
        "fingerprint": "Sorry, this shop is currently unavailable.",
        "confidence": "edge_case",
    },
    "Fastly": {
        "cname_domains": ["fastly.net"],
        "fingerprint": "Fastly error: unknown domain:",
        "confidence": "not_vulnerable",
    },
    "Microsoft Azure": {
        "cname_domains": [
            "cloudapp.net", "cloudapp.azure.com", "azurewebsites.net",
            "blob.core.windows.net", "azure-api.net", "azurehdinsight.net",
            "azureedge.net", "azurecontainer.io", "database.windows.net",
            "azuredatalakestore.net", "search.windows.net", "azurecr.io",
            "redis.cache.windows.net", "servicebus.windows.net", "visualstudio.com",
        ],
        # Special case: the "fingerprint" here is the CNAME failing to resolve
        # at all (NXDOMAIN), not text in an HTTP response -- handled separately
        # in check_candidate() below.
        "fingerprint": "NXDOMAIN",
        "confidence": "vulnerable",
    },
    "Pantheon": {
        "cname_domains": ["pantheonsite.io"],
        "fingerprint": "404 error unknown site!",
        "confidence": "vulnerable",
    },
    "Surge.sh": {
        "cname_domains": ["surge.sh"],
        "fingerprint": "project not found",
        "confidence": "vulnerable",
    },
    "Netlify": {
        "cname_domains": ["netlify.app", "netlify.com"],
        "fingerprint": "Not Found - Request ID:",
        "confidence": "edge_case",
    },
    "Zendesk": {
        "cname_domains": ["zendesk.com"],
        "fingerprint": "Help Center Closed",
        "confidence": "not_vulnerable",
    },
    "UserVoice": {
        "cname_domains": ["uservoice.com"],
        "fingerprint": "This UserVoice subdomain is currently available!",
        "confidence": "not_vulnerable",
    },
    "Tumblr": {
        "cname_domains": ["domains.tumblr.com"],
        "fingerprint": "Whatever you were looking for doesn't currently exist at this address",
        "confidence": "edge_case",
    },
    "WordPress.com": {
        "cname_domains": ["wordpress.com"],
        "fingerprint": "Do you want to register",  # trimmed from the regex in the source list
        "confidence": "vulnerable",
    },
    "Unbounce": {
        "cname_domains": ["unbouncepages.com"],
        "fingerprint": "The requested URL was not found on this server.",
        "confidence": "not_vulnerable",
    },
}


def _get_cname(host):
    """Returns the CNAME target for host, or None if it has none / dig fails
    or times out. Across tens of thousands of hosts, some lookups WILL hang
    or fail -- that must never take down the whole run, so every failure
    mode here is swallowed and treated as "no CNAME found" rather than
    raised. Timeouts/failures are counted by the caller for visibility."""
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", host],
            capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        # dig not found / failed to launch -- shouldn't happen mid-run since
        # run_subfinder etc. already depend on similar tools, but don't crash
        return None
    if result.returncode != 0:
        return None
    lines = [l.strip().rstrip(".") for l in result.stdout.splitlines() if l.strip()]
    return lines[-1] if lines else None  # last line = final CNAME in any chain


def _match_service(cname):
    cname_lower = cname.lower()
    for service, info in SERVICES.items():
        if any(cname_lower.endswith(domain) for domain in info["cname_domains"]):
            return service
    return None


def check_candidate(host, service, config):
    """Makes exactly one GET request for a host whose CNAME already matched
    a known service, and checks the response against that service's
    fingerprint. Returns a result dict."""
    info = SERVICES[service]
    headers_str = _header_flags(config)  # reuse discovery.py's header builder
    headers = {}
    if headers_str:
        # _header_flags returns shell-quoted -H 'k: v' pairs; parse back out
        # for use with requests' headers dict instead of a shell command
        target_headers = config.get("target", {}).get("headers", {})
        headers = dict(target_headers)

    if service == "Microsoft Azure":
        # Azure's signature is the CNAME target itself failing to resolve,
        # not an HTTP response -- a connection error here IS the match.
        try:
            requests.get(f"http://{host}", headers=headers, timeout=10)
            return {"matched": False, "evidence": "CNAME target resolved and responded -- not a match"}
        except requests.exceptions.ConnectionError as e:
            if "Name or service not known" in str(e) or "nodename nor servname" in str(e):
                return {"matched": True, "evidence": "CNAME target failed to resolve (NXDOMAIN)"}
            return {"matched": False, "evidence": f"connection failed for a different reason: {e}"}
        except requests.exceptions.RequestException as e:
            return {"matched": False, "evidence": f"request error, inconclusive: {e}"}

    try:
        resp = requests.get(f"http://{host}", headers=headers, timeout=10)
        if info["fingerprint"].lower() in resp.text.lower():
            return {"matched": True, "evidence": f"fingerprint found in response body (status {resp.status_code})"}
        return {"matched": False, "evidence": f"no fingerprint match (status {resp.status_code})"}
    except requests.exceptions.RequestException as e:
        return {"matched": False, "evidence": f"request failed, inconclusive: {e}"}


def run_takeover_check(subdomains_file=None, config=None):
    """Checks every subdomain in subdomains_file (default: this target's
    subdomains_verified.txt) for a CNAME pointing at a known third-party
    service, and for any match, confirms with a single fingerprint check."""
    if config is None:
        config = load_config()
    program = config["target"]["program_name"]
    base_dir = config["output"]["base_dir"]
    rate = config["rate_limit"]["requests_per_second"]

    if subdomains_file is None:
        subdomains_file = os.path.join(base_dir, program, "subdomains", "subdomains_verified.txt")

    with open(subdomains_file, "r") as f:
        hosts = [line.strip() for line in f if line.strip()]

    candidates = []
    no_cname_count = 0
    total = len(hosts)
    for i, host in enumerate(hosts, 1):
        cname = _get_cname(host)
        if not cname:
            no_cname_count += 1
        else:
            service = _match_service(cname)
            if service:
                candidates.append((host, cname, service))
        if i % 500 == 0 or i == total:
            print(f"[*] CNAME resolution progress: {i}/{total} hosts checked, "
                  f"{len(candidates)} candidate(s) so far")

    print(f"[*] {total} subdomains checked ({no_cname_count} had no resolvable CNAME), "
          f"{len(candidates)} candidate(s) with a matching third-party CNAME")

    results = []
    for host, cname, service in candidates:
        outcome = check_candidate(host, service, config)
        results.append({
            "host": host,
            "cname": cname,
            "matched_service": service,
            "confidence": SERVICES[service]["confidence"],
            "matched": outcome["matched"],
            "evidence": outcome["evidence"],
            "requires_manual_verification": True,
        })
        time.sleep(1 / rate)  # same good-citizen pacing as the rest of the pipeline

    out_dir = os.path.join(base_dir, program, "takeover")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "takeover_report.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    matches = [r for r in results if r["matched"]]
    print(f"[+] Takeover check complete. {len(matches)} potential match(es) written to: {out_file}")
    print("[!] Every match here still needs manual verification before being treated as real.")
    return out_file


if __name__ == "__main__":
    run_takeover_check()
