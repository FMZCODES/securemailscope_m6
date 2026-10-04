from __future__ import annotations

from pathlib import Path
from typing import Any

from .m3.stream_analyzer import analyze_pcap as analyze_m3
from .m4.engine import analyze as analyze_m4
from .m5.engine import analyze as analyze_m5


def run_full_pipeline(pcap_path: str | Path) -> dict[str, Any]:
    """
    Full SecureMailScope analysis pipeline.

    Flow:
        M2 -> M3 -> M4 -> M5

    M2:
        PCAP parsing is handled by the existing M2 parser.

    M3:
        TCP stream reconstruction and email protocol analysis.

    M4:
        TLS, STARTTLS and certificate analysis.

    M5:
        Feature extraction, ML prediction and risk calculation.

    This function only handles M3-M5 because M2 is already
    executed by app.main before this pipeline is called.
    """

    pcap_path = Path(pcap_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    # -------------------------
    # M3
    # -------------------------
    m3_result = analyze_m3(pcap_path)

    if not isinstance(m3_result, dict):
        raise TypeError(
            "M3 returned an invalid result. Expected dict."
        )

    # -------------------------
    # M4
    # -------------------------
    m4_result = analyze_m4(m3_result)

    if not isinstance(m4_result, dict):
        raise TypeError(
            "M4 returned an invalid result. Expected dict."
        )

    # -------------------------
    # M5
    # -------------------------
    m5_result = analyze_m5(m4_result)

    if not isinstance(m5_result, dict):
        raise TypeError(
            "M5 returned an invalid result. Expected dict."
        )

    # -------------------------
    # Combined result
    # -------------------------
    return {
        "pipeline": "M2 -> M3 -> M4 -> M5",

        "m3": m3_result,

        "m4": m4_result,

        "m5": m5_result,
    }


# Backwards-compatible function name.
# Existing code using run_m3_m5() will continue to work.
def run_m3_m5(pcap_path: str | Path) -> dict[str, Any]:
    return run_full_pipeline(pcap_path)