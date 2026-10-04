from __future__ import annotations

from .tls_rules import (
    check_tls_version,
    check_cipher,
    check_forward_secrecy,
)


def analyze_tls(tls_data: dict) -> dict:
    """
    Analyze TLS information for one stream.

    Input:
        tls_data = {
            "tls_version": ...,
            "cipher_suite": ...,
            "key_exchange": ...,
            "forward_secrecy": ...
        }

    Returns normalized TLS analysis plus security findings.
    """

    if not isinstance(tls_data, dict):
        tls_data = {}

    tls_version = tls_data.get("tls_version")
    cipher_suite = tls_data.get("cipher_suite")
    key_exchange = tls_data.get("key_exchange")
    forward_secrecy = tls_data.get("forward_secrecy")

    findings = []

    # ---------------------------------------------------------
    # TLS VERSION
    # ---------------------------------------------------------

    version_finding = check_tls_version(tls_version)

    if version_finding:
        findings.append(version_finding)

    # ---------------------------------------------------------
    # CIPHER
    # ---------------------------------------------------------

    cipher_finding = check_cipher(cipher_suite)

    if cipher_finding:
        findings.append(cipher_finding)

    # ---------------------------------------------------------
    # FORWARD SECRECY
    # ---------------------------------------------------------

    forward_secrecy_finding = check_forward_secrecy(
        key_exchange,
        forward_secrecy,
    )

    if forward_secrecy_finding:
        findings.append(forward_secrecy_finding)

    # ---------------------------------------------------------
    # RESULT
    # ---------------------------------------------------------

    tls_observed = any(
        value is not None
        for value in (
            tls_version,
            cipher_suite,
            key_exchange,
            forward_secrecy,
        )
    )

    return {
        "tls_observed": tls_observed,
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "key_exchange": key_exchange,
        "forward_secrecy": forward_secrecy,
        "findings": findings,
    }