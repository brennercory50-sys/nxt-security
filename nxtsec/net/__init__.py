"""Network primitives: resolution, DNS, target HTTP, TLS inspection, external APIs.

Every primitive that touches a *target* enforces scope itself (including the
DNS pivot guard) and connects to the exact address that passed the check.
"""
