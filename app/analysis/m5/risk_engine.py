from __future__ import annotations

from .ml_predictor import predict_risk


def calculate_risk(features: dict, ml_risk=None) -> dict:
    """
    M5 risk calculation.

    Combines rule-based indicators with the optional ML prediction.
    """

    score = 0
    findings = []

    # ---------------------------------------------------------
    # STARTTLS
    # ---------------------------------------------------------

    if features.get("starttls_detected") is False:
        score += 30

        findings.append({
            "severity": "HIGH",
            "type": "NO_STARTTLS",
            "message": "STARTTLS was not detected.",
            "recommendation": "Use TLS/STARTTLS for email communication.",
        })

    # ---------------------------------------------------------
    # TLS VERSION
    # ---------------------------------------------------------

    tls_version = features.get("tls_version")

    if tls_version:
        version = str(tls_version).upper()

        if "SSLV2" in version or "SSLV3" in version:
            score += 40

        elif "TLS 1.0" in version or "TLS 1.1" in version:
            score += 30

    # ---------------------------------------------------------
    # CIPHER
    # ---------------------------------------------------------

    cipher = features.get("cipher_suite")

    if cipher:
        cipher_upper = str(cipher).upper()

        weak_ciphers = (
            "RC4",
            "3DES",
            "DES",
            "NULL",
            "EXPORT",
        )

        for weak_cipher in weak_ciphers:
            if weak_cipher in cipher_upper:
                score += 25
                break

    # ---------------------------------------------------------
    # FORWARD SECRECY
    # ---------------------------------------------------------

    if features.get("forward_secrecy") is False:
        score += 15

    # ---------------------------------------------------------
    # M4 FINDINGS
    # ---------------------------------------------------------

    m4_findings = features.get("findings", [])

    if isinstance(m4_findings, list):
        for finding in m4_findings:
            severity = str(
                finding.get("severity", "")
            ).upper()

            if severity == "CRITICAL":
                score += 40

            elif severity == "HIGH":
                score += 25

            elif severity == "MEDIUM":
                score += 15

            elif severity == "LOW":
                score += 5

    # ---------------------------------------------------------
    # ML RISK
    # ---------------------------------------------------------

    if ml_risk is not None:
        try:
            ml_value = float(ml_risk)

            # Support either 0-1 or 0-100 ML output.
            if 0 <= ml_value <= 1:
                score += ml_value * 20
            else:
                score += ml_value * 0.20

        except (TypeError, ValueError):
            pass

    # ---------------------------------------------------------
    # NORMALIZE
    # ---------------------------------------------------------

    score = max(0, min(100, round(score)))

    if score >= 75:
        level = "CRITICAL"

    elif score >= 50:
        level = "HIGH"

    elif score >= 25:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": score,
        "risk_level": level,
        "findings": findings,
    }