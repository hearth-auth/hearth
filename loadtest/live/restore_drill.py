#!/usr/bin/env python3
"""The restore drill (#651): compare a server with the copy that its backup restores.

Stub: the interface that test_restore_drill.py tests. Nothing is implemented yet.
"""
import sys


def bulk_user(i, domain):
    """The import entry for bulk user i."""
    return {}


def sample_indexes(users, every):
    """The bulk users the drill compares in full."""
    return []


def count_by_probe(has_at):
    """The exact length of a list from probes of the form 'is there an item at offset k'."""
    return 0


def verify_jwt_signature(token, jwks):
    """(True, "") when an EdDSA JWT verifies with a key of the JWKS, else (False, why)."""
    return True, ""


def compare(before, after, *, token, restore_exit, require_webhooks=False):
    """The findings of a before/after comparison."""
    return []


def verdict(findings):
    """PASS, or FAIL when a finding failed."""
    return "PASS"


def main(argv):
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
