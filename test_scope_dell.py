"""
test_scope_dell.py
Manual verification script -- run this against the new scope.py BEFORE
running the discovery pipeline against a real target. Checks the new
rule-based matching against known-correct answers from the actual
Bugcrowd Dell scope table.

Usage:
    python3 test_scope_dell.py
"""
from core.scope import is_in_scope

DELL_CONFIG = {
    "scope": {
        "rules": [
            {"pattern": "*.dell.com/*", "status": "allow"},
            {"pattern": "*.delltechnologies.com/*", "status": "allow"},
            {"pattern": "educate.dell.com", "status": "deny"},
            {"pattern": "console.dell.com", "status": "deny"},
            {"pattern": "console-test.dell.com", "status": "deny"},
            {"pattern": "salesproductivity.dell.com", "status": "deny"},
            {"pattern": "console.delltechnologies.com", "status": "deny"},
            {"pattern": "console.delltechnologies.com/nav/administration", "status": "allow"},
            {"pattern": "console.delltechnologies.com/nav/invoice", "status": "allow"},
            {"pattern": "console.delltechnologies.com/nav/billing", "status": "allow"},
        ]
    }
}

# (url, expected_in_scope, why)
CASES = [
    ("https://www.dell.com/some/page", True, "plain dell.com subdomain, wildcard allow"),
    ("https://api.delltechnologies.com/anything", True, "plain delltechnologies.com subdomain, wildcard allow"),
    ("https://educate.dell.com/", False, "explicitly denied subdomain"),
    ("https://console.dell.com/", False, "explicitly denied subdomain"),
    ("https://console-test.dell.com/", False, "explicitly denied subdomain"),
    ("https://salesproductivity.dell.com/", False, "explicitly denied subdomain"),
    ("https://console.delltechnologies.com/", False, "denied at domain level, no path override"),
    ("https://console.delltechnologies.com/nav/catalog", False, "domain denied, path not re-allowed"),
    ("https://console.delltechnologies.com/nav/support", False, "domain denied, path not re-allowed"),
    ("https://console.delltechnologies.com/nav/subscriptions", False, "domain denied, path not re-allowed"),
    ("https://console.delltechnologies.com/nav/administration", True, "path-level re-include"),
    ("https://console.delltechnologies.com/nav/invoice", True, "path-level re-include"),
    ("https://console.delltechnologies.com/nav/billing", True, "path-level re-include"),
    ("https://console.delltechnologies.com/nav/administration/sub-page", True, "prefix match under re-included path"),
    ("https://evil.com/", False, "unrelated domain, no matching rule at all"),
]

if __name__ == "__main__":
    passed = 0
    failed = 0
    for url, expected, reason in CASES:
        actual = is_in_scope(url, DELL_CONFIG)
        status = "PASS" if actual == expected else "FAIL"
        if actual == expected:
            passed += 1
        else:
            failed += 1
        print(f"[{status}] {url}  ->  got={actual} expected={expected}  ({reason})")
    print(f"\n{passed} passed, {failed} failed")