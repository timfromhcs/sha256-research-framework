"""
SHA-256 Research Framework v4.1 Headless Autonomous Research Platform

v4.0 replaces all verification fallbacks with a single trust boundary:
every L3 promotion must carry an authentic verdict from the segregated
IndependentVerifier engine (sha-verifier). There is no code path from
"no evidence" to "verified".
"""

__version__ = "4.1.0"