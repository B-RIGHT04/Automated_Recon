"""
test_httpx_filter.py
Dry-run test for the new scope-filtering logic added to run_httpx() in
discovery.py. Feeds a small FAKE subdomain list (standing in for what
subfinder might return) through the same _filter_scope() function used
in the real pipeline, and checks the kept/dropped results against what
we know should happen per Dell's real scope rules. No network activity,
no live tools involved.

Usage:
    python3 test_httpx_filter.py
"""
import os
import tempfile
from core.discovery import _filter_scope

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

# Fake subfinder-style output: a mix of in-scope and known-excluded subdomains
FAKE_SUBDOMAINS = [
    "www.dell.com",
    "api.delltechnologies.com",
    "console.dell.com",           # should be dropped -- explicitly denied
    "educate.dell.com",           # should be dropped -- explicitly denied
    "console-test.dell.com",      # should be dropped -- explicitly denied
    "salesproductivity.dell.com", # should be dropped -- explicitly denied
    "console.delltechnologies.com",  # should be dropped -- denied at domain level (no path here)
    "support.dell.com",
    "totally-unrelated.com",      # should be dropped -- no matching rule at all
]

EXPECTED_KEPT = {"www.dell.com", "api.delltechnologies.com", "support.dell.com"}
EXPECTED_DROPPED = {
    "console.dell.com",
    "educate.dell.com",
    "console-test.dell.com",
    "salesproductivity.dell.com",
    "console.delltechnologies.com",
    "totally-unrelated.com",
}

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        input_file = os.path.join(tmp, "fake_subdomains.txt")
        output_file = os.path.join(tmp, "fake_scoped.txt")

        with open(input_file, "w") as f:
            f.write("\n".join(FAKE_SUBDOMAINS) + "\n")

        _filter_scope(input_file, output_file, DELL_CONFIG, "subdomain")

        with open(output_file, "r") as f:
            kept = {line.strip() for line in f if line.strip()}

        print(f"\nKept ({len(kept)}): {sorted(kept)}")

        dropped = set(FAKE_SUBDOMAINS) - kept
        print(f"Dropped ({len(dropped)}): {sorted(dropped)}")

        ok = True
        if kept != EXPECTED_KEPT:
            print(f"\n[FAIL] Kept set doesn't match expected.\n  expected: {sorted(EXPECTED_KEPT)}\n  got:      {sorted(kept)}")
            ok = False
        if dropped != EXPECTED_DROPPED:
            print(f"\n[FAIL] Dropped set doesn't match expected.\n  expected: {sorted(EXPECTED_DROPPED)}\n  got:      {sorted(dropped)}")
            ok = False

        print("\n[PASS] Filter behaved exactly as expected." if ok else "\n[FAIL] See above.")