"""
Protocol identification for SecureMailScope M2.

Identifies application protocols using:
1. TCP/UDP ports
2. TShark/PyShark layer information
"""

from typing import Optional


# ============================================================
# Port mappings
# ============================================================

PORT_PROTOCOLS = {
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
}


# ============================================================
# Safe value conversion
# ============================================================

def _to_string(value) -> str:
    """
    Convert a PyShark field or normal Python value
    into a safe string.
    """

    if value is None:
        return ""

    try:
        return str(value).strip().lower()

    except Exception:
        return ""


# ============================================================
# Main protocol identification
# ============================================================

def identify_application_protocol(
    packet,
    src_port=None,
    dst_port=None,
) -> str:
    """
    Identify the application protocol for a packet.

    Parameters
    ----------
    packet:
        PyShark packet.

    src_port:
        Source TCP/UDP port.

    dst_port:
        Destination TCP/UDP port.

    Returns
    -------
    str
        Identified application protocol or "UNKNOWN".
    """

    # --------------------------------------------------------
    # Normalize ports
    # --------------------------------------------------------

    try:
        src_port = int(src_port) if src_port else None
    except (TypeError, ValueError):
        src_port = None

    try:
        dst_port = int(dst_port) if dst_port else None
    except (TypeError, ValueError):
        dst_port = None


    # --------------------------------------------------------
    # First: identify using ports
    # --------------------------------------------------------

    if src_port in PORT_PROTOCOLS:
        return PORT_PROTOCOLS[src_port]

    if dst_port in PORT_PROTOCOLS:
        return PORT_PROTOCOLS[dst_port]


    # --------------------------------------------------------
    # Second: inspect TShark highest layer
    # --------------------------------------------------------

    try:

        highest_layer = getattr(
            packet,
            "highest_layer",
            None,
        )

        highest_layer = _to_string(
            highest_layer
        )

        if highest_layer:

            protocol_map = {
                "smtp": "SMTP",
                "imap": "IMAP",
                "pop": "POP3",
                "pop3": "POP3",
                "ssl": "TLS",
                "tls": "TLS",
                "http": "HTTP",
                "http2": "HTTP",
                "dns": "DNS",
                "ftp": "FTP",
                "ssh": "SSH",
            }

            if highest_layer in protocol_map:
                return protocol_map[highest_layer]

    except Exception:
        pass


    # --------------------------------------------------------
    # Third: inspect packet layers
    # --------------------------------------------------------

    try:

        layers = getattr(
            packet,
            "layers",
            [],
        )

        for layer in layers:

            layer_name = getattr(
                layer,
                "layer_name",
                "",
            )

            layer_name = _to_string(
                layer_name
            )

            protocol_map = {
                "smtp": "SMTP",
                "imap": "IMAP",
                "pop": "POP3",
                "pop3": "POP3",
                "tls": "TLS",
                "ssl": "TLS",
                "http": "HTTP",
                "http2": "HTTP",
                "dns": "DNS",
                "ftp": "FTP",
                "ssh": "SSH",
            }

            if layer_name in protocol_map:
                return protocol_map[layer_name]

    except Exception:
        pass


    # --------------------------------------------------------
    # Nothing identified
    # --------------------------------------------------------

    return "UNKNOWN"