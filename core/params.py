"""
params.py
Phase 2: Parameter extraction.

Pulls candidate parameters from three sources:
  1. Query strings in crawled URLs (urls.txt)
  2. JS files saved by katana during the crawl (responses dir)
  3. HTML forms in pages saved by katana during the crawl (responses dir)

Writes a combined JSON list to data/<program>/params/params.json

Note on JS extraction: this is heuristic/regex-based, not a JS parser.
It will catch common patterns (query-string-like references, "params: {...}"
object literals, basic .get()/.post() calls) but will miss heavily
minified/bundled JS with renamed variables. Treat js-sourced params as
candidates to review, not guaranteed-accurate.
"""
import os
import re
import json
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from core.scope import load_config

JS_PARAM_PATTERNS = [
    re.compile(r'[?&]([a-zA-Z0-9_\-]+)='),                                    # query-string-like refs inside JS strings
    re.compile(r'\.(?:get|post)\(\s*[\'"][^\'"]*[\'"]\s*,\s*\{([^}]*)\}'),    # axios-style calls, rough
    re.compile(r'params\s*:\s*\{([^}]*)\}'),                                 # object literals named "params"
]

FORM_INPUT_TAGS = ("input", "select", "textarea")


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _responses_dir(config):
    program = config["target"]["program_name"]
    return os.path.join(config["output"]["base_dir"], program, "responses")


def _parse_katana_response_file(raw):
    """
    Katana -store-response files are structured as:
        <crawled URL>
        (blank line)
        <raw HTTP request block>
        (blank line)
        <raw HTTP response: status line, headers, blank line, body>

    Files are hash-named with a .txt extension regardless of actual content
    type, so we can't sniff by filename -- we parse the response headers to
    pull Content-Type, and split off the body.

    Returns (url, content_type, body). Any field defaults to "" if the file
    doesn't match the expected shape (defensive -- format could still shift
    across katana versions or edge-case responses).
    """
    lines = raw.split("\n")
    if not lines:
        return "", "", ""
    url = lines[0].strip()

    content_type = ""
    body_start = None
    in_response = False
    for i, line in enumerate(lines):
        if line.startswith("HTTP/"):
            in_response = True
            continue
        if in_response:
            if line.strip() == "":
                body_start = i + 1
                break
            if line.lower().startswith("content-type:"):
                content_type = line.split(":", 1)[1].strip().lower()

    body = "\n".join(lines[body_start:]) if body_start is not None else ""
    return url, content_type, body


def _walk_response_files(config):
    """
    Katana's -store-response-dir layout can vary slightly by version, so
    this walks the whole tree and yields (filepath, url, content_type, body)
    for every file found, already parsed via _parse_katana_response_file().
    """
    root = _responses_dir(config)
    if not os.path.isdir(root):
        print(f"[!] No responses directory found at {root} -- did run_katana use -store-response?")
        return
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    raw = f.read()
            except OSError:
                continue
            url, content_type, body = _parse_katana_response_file(raw)
            yield fpath, url, content_type, body


def extract_from_urls(config):
    """Extract query-string parameters from the final scoped urls.txt."""
    program = config["target"]["program_name"]
    urls_file = os.path.join(config["output"]["base_dir"], program, "urls", "urls.txt")
    results = []
    if not os.path.isfile(urls_file):
        print(f"[!] {urls_file} not found -- run Phase 1 discovery first.")
        return results
    with open(urls_file, "r") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in qs:
                results.append({
                    "url": url,
                    "param": param,
                    "source": "url",
                    "method": "GET",
                })
    return results


def extract_from_js(config):
    """Scan saved JS response bodies (identified by Content-Type) for parameter-like references."""
    results = []
    for fpath, url, content_type, body in _walk_response_files(config):
        if "javascript" not in content_type and "ecmascript" not in content_type:
            continue
        found = set()
        for pattern in JS_PARAM_PATTERNS:
            for match in pattern.finditer(body):
                group = match.group(1)
                if not group:
                    continue
                # patterns 2 and 3 capture a blob like "foo: 1, bar: 2" -- split it
                if ":" in group:
                    for piece in group.split(","):
                        key = piece.split(":")[0].strip().strip("'\"")
                        if key:
                            found.add(key)
                else:
                    found.add(group)
        for param in found:
            results.append({
                "url": url or fpath,
                "param": param,
                "source": "js",
                "method": "UNKNOWN",
            })
    return results


def extract_from_html(config):
    """Parse saved HTML pages (identified by Content-Type) for form fields."""
    results = []
    for fpath, url, content_type, body in _walk_response_files(config):
        if "html" not in content_type:
            continue
        soup = BeautifulSoup(body, "html.parser")
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or url or fpath
            for tag in form.find_all(FORM_INPUT_TAGS):
                name = tag.get("name")
                if name:
                    results.append({
                        "url": action,
                        "param": name,
                        "source": "html_form",
                        "method": method,
                    })
    return results


def run_param_extraction(config=None):
    """Runs all three extraction sources and writes combined params.json."""
    if config is None:
        config = load_config()
    program = config["target"]["program_name"]
    out_dir = os.path.join(config["output"]["base_dir"], program, "params")
    _ensure_dir(out_dir)
    out_file = os.path.join(out_dir, "params.json")

    url_params = extract_from_urls(config)
    js_params = extract_from_js(config)
    html_params = extract_from_html(config)

    combined = url_params + js_params + html_params

    with open(out_file, "w") as f:
        json.dump(combined, f, indent=2)

    print(
        f"[+] Extracted {len(combined)} parameter references "
        f"({len(url_params)} url, {len(js_params)} js, {len(html_params)} html_form)"
    )
    print(f"[+] Written to: {out_file}")
    return out_file


if __name__ == "__main__":
    run_param_extraction()