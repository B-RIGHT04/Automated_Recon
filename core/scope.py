"""
scope.py
Enforces the target scope defined in config/config.yaml, using a
rule-based, most-specific-match-wins model.

Each rule has a "pattern" (a bare domain, a wildcard domain, or a
domain+path) and a "status" of "allow" or "deny". When checking a URL,
every rule that matches is considered, and the MOST SPECIFIC matching
rule's status wins -- not list order. This lets a broad wildcard rule
(e.g. "*.example.com/*": allow) be overridden by a narrower rule (a
specific subdomain: deny), which can itself be overridden by an even
narrower rule (a specific path on that subdomain: allow). This mirrors
how real bug bounty program scope tables are often written (e.g.
Bugcrowd's Dell program: whole domain wildcard-allowed, specific
subdomain excluded, specific paths on that subdomain re-included).

Specificity precedence (in order):
    1. Exact domain match beats wildcard domain match.
    2. Within the same domain-match level, an exact path prefix match
       beats a rule with no path (i.e. a rule that applies to the whole
       domain regardless of path).

Caveat: if two rules have IDENTICAL specificity and conflicting status
(e.g. duplicate patterns with different status), the first one
encountered in the config list wins silently. Avoid writing overlapping
rules with the same specificity -- keep each pattern unique.

Every module that makes a request (discovery, params, reflect) must
call enforce_scope() before touching a target.
"""
import yaml
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a URL/domain falls outside the allowed scope."""
    pass


def load_config(config_path="config/config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def _split_target(url_or_domain):
    """Returns (hostname, path) for a URL or bare domain. Path defaults to '/'."""
    if "://" in url_or_domain:
        parsed = urlparse(url_or_domain)
        return (parsed.hostname or "").lower(), (parsed.path or "/")
    parts = url_or_domain.split("/", 1)
    hostname = parts[0].lower()
    path = "/" + parts[1] if len(parts) > 1 else "/"
    return hostname, path


def _parse_rule_pattern(pattern):
    """
    Parses a rule pattern into (hostname_pattern, path_pattern, domain_specificity).
      - hostname_pattern: bare domain, with a leading "*." stripped if wildcarded.
      - path_pattern: None if the rule doesn't pin down a path (matches any
        path on that domain); otherwise a literal path prefix, e.g.
        "/nav/administration". A pattern of "/", "/*", or "*" for the path
        also means "matches any path" (treated as no path pin).
      - domain_specificity: 2 for an exact domain, 1 for a wildcard domain.
    """
    hostname, path = _split_target(pattern)

    if hostname.startswith("*."):
        domain_specificity = 1
        hostname = hostname[2:]
    else:
        domain_specificity = 2

    if path in ("/", "/*", "*"):
        path_pattern = None
    else:
        path_pattern = path.rstrip("*")

    return hostname, path_pattern, domain_specificity


def _hostname_matches(hostname, rule_hostname, is_wildcard):
    if is_wildcard:
        return hostname == rule_hostname or hostname.endswith("." + rule_hostname)
    return hostname == rule_hostname


def _rule_specificity_if_matches(hostname, path, rule):
    """Returns a (domain_specificity, path_specificity) tuple if the rule matches, else None."""
    rule_hostname, rule_path, domain_specificity = _parse_rule_pattern(rule["pattern"])
    is_wildcard = domain_specificity == 1

    if not _hostname_matches(hostname, rule_hostname, is_wildcard):
        return None

    if rule_path is None:
        return (domain_specificity, 1)  # domain-level rule, any path

    if path.startswith(rule_path):
        return (domain_specificity, 2)  # path-level rule, more specific

    return None


def _best_match_status(hostname, path, rules):
    """Returns the status ('allow'/'deny') of the single most specific matching rule, or None."""
    best_specificity = None
    best_status = None
    for rule in rules:
        specificity = _rule_specificity_if_matches(hostname, path, rule)
        if specificity is None:
            continue
        if best_specificity is None or specificity > best_specificity:
            best_specificity = specificity
            best_status = rule["status"]
    return best_status


def is_in_scope(url_or_domain, config=None):
    if config is None:
        config = load_config()
    hostname, path = _split_target(url_or_domain)
    if not hostname:
        return False

    rules = config.get("scope", {}).get("rules", []) or []
    status = _best_match_status(hostname, path, rules)
    return status == "allow"


def enforce_scope(url_or_domain, config=None):
    """Raises ScopeViolation if the target is out of scope. Call this before any request."""
    if not is_in_scope(url_or_domain, config):
        raise ScopeViolation(f"'{url_or_domain}' is not in the allowed scope.")
    return True