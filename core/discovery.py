"""
discovery.py
Phase 1: Discovery pipeline.
Chains subfinder -> httpx -> katana to go from a root domain
to a list of crawled URLs, respecting scope and configured rate limits.
"""
import subprocess
import os
import json
import shlex
from core.scope import enforce_scope, is_in_scope, load_config


def _run_command(command, description):
    """Runs a shell command, raises on failure, returns stdout."""
    print(f"[*] {description}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {command}\nSTDERR: {result.stderr.strip()}"
        )
    # Surface stderr even on success -- some tools print warnings (rate limits,
    # source timeouts, etc.) to stderr while still exiting 0. Previously this
    # was silently discarded, which hid the reason for a Session 9 near-zero
    # subfinder result until it crashed three stages later in run_katana().
    if result.stderr.strip():
        print(f"[!] {description} - stderr output:\n{result.stderr.strip()}")
    return result.stdout


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _header_flags(config):
    """Builds -H flags for any custom headers in config (e.g. bug bounty
    program identification header). Returns empty string if none configured."""
    headers = config.get("target", {}).get("headers", {})
    return " ".join(
        f"-H {shlex.quote(f'{k}: {v}')}" for k, v in headers.items()
    )


def run_subfinder(domain, config):
    enforce_scope(domain, config)
    program = config["target"]["program_name"]
    out_dir = os.path.join(config["output"]["base_dir"], program, "subdomains")
    _ensure_dir(out_dir)
    out_file = os.path.join(out_dir, "subdomains.txt")
    tool = config["tools"]["subfinder"]
    rate = config["rate_limit"]["requests_per_second"]
    cmd = (
        f"{shlex.quote(tool)} -d {shlex.quote(domain)} "
        f"-rate-limit {shlex.quote(str(rate))} -silent -o {shlex.quote(out_file)}"
    )
    _run_command(cmd, f"Running subfinder on {domain}")
    with open(out_file, "r") as f:
        count = sum(1 for line in f if line.strip())
    if count == 0:
        raise RuntimeError(
            f"subfinder returned 0 subdomains for {domain}. This can happen from "
            f"a transient network/DNS/source issue -- check your connection and "
            f"try re-running before assuming something is misconfigured."
        )
    return out_file


def _filter_scope(input_file, output_file, config, label):
    """Filters each line of input_file through is_in_scope(), writes survivors
    to output_file, and logs anything dropped."""
    kept = []
    dropped = []
    with open(input_file, "r") as f:
        for line in f:
            target = line.strip()
            if not target:
                continue
            if is_in_scope(target, config):
                kept.append(target)
            else:
                dropped.append(target)
    kept = sorted(set(kept))  # dedupe + stable ordering, fixes the 20,073-duplicate issue
    with open(output_file, "w") as f:
        f.write("\n".join(kept) + "\n")
    if dropped:
        print(f"[!] Dropped {len(dropped)} out-of-scope {label}(s):")
        for item in dropped:
            print(f"    - {item}")
    return output_file


def run_httpx(subdomains_file, config):
    program = config["target"]["program_name"]
    subdomains_dir = os.path.join(config["output"]["base_dir"], program, "subdomains")
    _ensure_dir(subdomains_dir)

    # Layer 1: filter subfinder's raw output against scope rules before
    # anything gets a live request. Subfinder has no concept of our scope
    # config, so it can (and does) return subdomains explicitly excluded
    # by the program (e.g. carve-outs on an otherwise-wildcarded domain).
    scoped_file = os.path.join(subdomains_dir, "subdomains_scoped.txt")
    _filter_scope(subdomains_file, scoped_file, config, "subdomain")

    # Layer 2: defensive per-host re-check. Explicitly re-verifies every
    # remaining host right before it's handed to httpx. This raises hard
    # (ScopeViolation) instead of silently dropping -- it's a belt-and-
    # suspenders check in case anything ever slips past Layer 1 (e.g. a
    # future code change that feeds run_httpx an unfiltered list).
    verified_file = os.path.join(subdomains_dir, "subdomains_verified.txt")
    with open(scoped_file, "r") as f:
        hosts = [line.strip() for line in f if line.strip()]
    with open(verified_file, "w") as vf:
        for host in hosts:
            enforce_scope(host, config)
            vf.write(host + "\n")

    out_dir = os.path.join(config["output"]["base_dir"], program, "live_hosts")
    _ensure_dir(out_dir)
    out_file = os.path.join(out_dir, "live.txt")
    # Session 10 addition: httpx now runs with tech-detection enabled, writing
    # JSON-lines output instead of a plain URL list. This is parsed below into
    # two separate files: `live.txt` stays a plain URL list (unchanged format,
    # so run_katana()'s `-list` input and is_in_scope() keep working exactly
    # as before), and a new `tech_report.json` captures the fingerprinting
    # data for reporting. Field names (`url`, `tech`, `webserver`, etc.)
    # confirmed directly against a live httpx v1.10.0 JSON response rather
    # than assumed from docs, which don't document the schema.
    raw_json_file = os.path.join(out_dir, "httpx_raw.json")
    tool = config["tools"]["httpx"]
    rate = config["rate_limit"]["requests_per_second"]
    timeout = config["rate_limit"]["timeout_seconds"]
    headers = _header_flags(config)
    cmd = (
        f"{shlex.quote(tool)} -l {shlex.quote(verified_file)} "
        f"-rate-limit {shlex.quote(str(rate))} "
        f"-timeout {shlex.quote(str(timeout))} {headers} "
        f"-silent -td -json -o {shlex.quote(raw_json_file)}"
    )
    _run_command(cmd, "Running httpx to filter live hosts")

    tech_dir = os.path.join(config["output"]["base_dir"], program, "tech")
    _ensure_dir(tech_dir)
    tech_report_file = os.path.join(tech_dir, "tech_report.json")

    urls = []
    tech_entries = []
    malformed = 0
    if os.path.exists(raw_json_file):
        with open(raw_json_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                url = record.get("url")
                if url:
                    urls.append(url)
                tech_entries.append({
                    "url": url,
                    "webserver": record.get("webserver"),
                    "tech": record.get("tech", []),
                    "status_code": record.get("status_code"),
                    "title": record.get("title"),
                })
    if malformed:
        print(f"[!] Skipped {malformed} malformed JSON line(s) from httpx output")

    with open(out_file, "w") as f:
        f.write("\n".join(urls) + "\n")
    with open(tech_report_file, "w") as f:
        json.dump(tech_entries, f, indent=2)

    count = len(urls)
    if count == 0:
        raise RuntimeError(
            f"httpx found 0 live hosts out of {len(hosts)} candidate(s). This can "
            f"mean every host is down/unreachable, or an upstream stage (subfinder) "
            f"already returned bad data -- check the subdomains files before "
            f"re-running."
        )
    return out_file


def run_katana(live_hosts_file, config):
    program = config["target"]["program_name"]
    out_dir = os.path.join(config["output"]["base_dir"], program, "urls")
    _ensure_dir(out_dir)
    raw_file = os.path.join(out_dir, "urls_raw.txt")
    out_file = os.path.join(out_dir, "urls.txt")
    tool = config["tools"]["katana"]
    rate = config["rate_limit"]["requests_per_second"]
    domain = config["target"]["domain"]

    # Phase 2 addition: save every crawled response body (HTML + JS) to disk.
    # This piggybacks on the crawl katana is already doing -- no extra requests.
    responses_dir = os.path.join(config["output"]["base_dir"], program, "responses")
    _ensure_dir(responses_dir)

    headers = _header_flags(config)
    # -cs restricts katana's crawl to the target domain (native scope control)
    cmd = (
        f"{shlex.quote(tool)} -list {shlex.quote(live_hosts_file)} "
        f"-rate-limit {shlex.quote(str(rate))} "
        f"-cs {shlex.quote(domain)} -silent -store-response "
        f"-store-response-dir {shlex.quote(responses_dir)} {headers} "
        f"-o {shlex.quote(raw_file)}"
    )
    _run_command(cmd, "Running katana to crawl URLs")

    if not os.path.exists(raw_file):
        raise RuntimeError(
            f"katana did not produce an output file at {raw_file}. This usually "
            f"means it had nothing to crawl (an empty live-hosts list) -- check "
            f"the earlier pipeline stages before re-running."
        )

    # Second layer: filter any URL that slipped through against our own scope config
    kept = []
    dropped = []
    with open(raw_file, "r") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            if is_in_scope(url, config):
                kept.append(url)
            else:
                dropped.append(url)
    with open(out_file, "w") as f:
        f.write("\n".join(kept) + "\n")
    if dropped:
        print(f"[!] Dropped {len(dropped)} out-of-scope URL(s) from katana output:")
        for url in dropped:
            print(f"    - {url}")
    return out_file


def run_discovery(config=None):
    """Runs the full Phase 1 pipeline: subfinder -> httpx -> katana."""
    if config is None:
        config = load_config()
    domain = config["target"]["domain"]
    subdomains_file = run_subfinder(domain, config)
    live_hosts_file = run_httpx(subdomains_file, config)
    urls_file = run_katana(live_hosts_file, config)
    print(f"[+] Discovery complete. URLs written to: {urls_file}")
    return urls_file


if __name__ == "__main__":
    run_discovery()
