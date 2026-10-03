"""
SecureMailScope M2 - PCAP Parser

Responsibilities:
    PCAP
      -> TShark/PyShark
      -> packet extraction
      -> protocol identification
      -> structured PacketRecord output

This module does NOT perform:
    - SMTP/IMAP/POP3 content analysis
    - TLS/certificate analysis
    - risk scoring
    - MongoDB storage
    - FastAPI handling
"""

from __future__ import annotations
import asyncio
import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import List, Tuple

import pyshark

from .exceptions import InvalidPcapFileError
from .models import PacketRecord, ProtocolSummary
from .protocol_identifier import identify_application_protocol


logger = logging.getLogger("secure_mail_scope.m2_parser")


# ============================================================
# Logging
# ============================================================

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s",
    )


# ============================================================
# Supported PCAP extensions
# ============================================================

SUPPORTED_EXTENSIONS = {
    ".pcap",
    ".pcapng",
    ".cap",
}


# ============================================================
# TShark discovery
# ============================================================

def _find_tshark() -> str:
    """
    Find TShark on the current machine.

    Search order:
        1. TSHARK_PATH environment variable
        2. TShark available on PATH
        3. Standard Windows Wireshark locations
    """

    # --------------------------------------------------------
    # 1. Environment variable
    # --------------------------------------------------------

    env_path = os.environ.get("TSHARK_PATH")

    if env_path:
        env_path = os.path.expandvars(env_path)
        env_path = os.path.expanduser(env_path)

        if Path(env_path).is_file():
            return env_path


    # --------------------------------------------------------
    # 2. PATH
    # --------------------------------------------------------

    path = shutil.which("tshark")

    if path:
        return path


    # --------------------------------------------------------
    # 3. Standard Windows locations
    # --------------------------------------------------------

    possible_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    for candidate in possible_paths:

        if Path(candidate).is_file():
            return candidate


    # --------------------------------------------------------
    # Not found
    # --------------------------------------------------------

    raise RuntimeError(
        "TShark was not found. Install Wireshark/TShark or set "
        "the TSHARK_PATH environment variable."
    )


# ============================================================
# Python 3.14 / PyShark event-loop compatibility
# ============================================================

def _ensure_event_loop() -> asyncio.AbstractEventLoop:
    """
    PyShark versions commonly used with this project expect
    a current asyncio event loop.

    Python 3.14 no longer automatically creates one in some
    situations, so create one explicitly.
    """

    try:
        loop = asyncio.get_event_loop()

    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop


# ============================================================
# Safe conversion helpers
# ============================================================

def _safe_str(value) -> str:
    """
    Convert PyShark fields safely to strings.

    PyShark fields are not always normal Python strings.
    """

    if value is None:
        return ""

    try:
        return str(value)

    except Exception:
        return ""


def _safe_int(value, default=0) -> int:
    """
    Convert a PyShark field to int safely.
    """

    if value is None:
        return default

    try:
        return int(str(value))

    except (TypeError, ValueError):
        return default

    except Exception:
        return default


# ============================================================
# Packet field extraction
# ============================================================

def _get_ip_addresses(packet):
    """
    Extract source and destination IP addresses.

    Supports both IPv4 and IPv6.
    """

    src_ip = ""
    dst_ip = ""

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    try:

        if hasattr(packet, "ip"):

            src_ip = _safe_str(
                getattr(packet.ip, "src", "")
            )

            dst_ip = _safe_str(
                getattr(packet.ip, "dst", "")
            )

    except Exception:
        pass


    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    if not src_ip and not dst_ip:

        try:

            if hasattr(packet, "ipv6"):

                src_ip = _safe_str(
                    getattr(packet.ipv6, "src", "")
                )

                dst_ip = _safe_str(
                    getattr(packet.ipv6, "dst", "")
                )

        except Exception:
            pass


    return src_ip, dst_ip


# ============================================================

def _get_ports(packet):
    """
    Extract source and destination TCP/UDP ports.
    """

    src_port = None
    dst_port = None


    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    try:

        if hasattr(packet, "tcp"):

            src_port = _safe_int(
                getattr(packet.tcp, "srcport", None),
                None,
            )

            dst_port = _safe_int(
                getattr(packet.tcp, "dstport", None),
                None,
            )

            return src_port, dst_port

    except Exception:
        pass


    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    try:

        if hasattr(packet, "udp"):

            src_port = _safe_int(
                getattr(packet.udp, "srcport", None),
                None,
            )

            dst_port = _safe_int(
                getattr(packet.udp, "dstport", None),
                None,
            )

            return src_port, dst_port

    except Exception:
        pass


    return src_port, dst_port


# ============================================================

def _get_transport_protocol(packet) -> str:
    """
    Identify TCP/UDP/other transport protocol.
    """

    try:

        if hasattr(packet, "tcp"):
            return "TCP"

    except Exception:
        pass


    try:

        if hasattr(packet, "udp"):
            return "UDP"

    except Exception:
        pass


    try:

        if hasattr(packet, "sctp"):
            return "SCTP"

    except Exception:
        pass


    return "UNKNOWN"


# ============================================================

def _get_packet_timestamp(packet) -> str:
    """
    Extract packet timestamp.
    """

    try:

        timestamp = getattr(
            packet,
            "sniff_time",
            None,
        )

        if timestamp is not None:
            return timestamp.isoformat()

    except Exception:
        pass


    return ""


# ============================================================

def _get_packet_number(packet, fallback: int) -> int:
    """
    Extract packet number safely.
    """

    try:

        number = getattr(
            packet,
            "number",
            None,
        )

        if number is not None:
            return int(str(number))

    except Exception:
        pass


    return fallback


# ============================================================
# Packet -> PacketRecord
# ============================================================

def _packet_to_record(packet, packet_number: int) -> PacketRecord:
    """
    Convert a PyShark packet into the project's PacketRecord.

    IMPORTANT:
    This matches the actual model fields:
        src_ip
        dst_ip
        src_port
        dst_port

    There is intentionally NO `length` argument because your
    PacketRecord model does not define a `length` field.
    """

    # --------------------------------------------------------
    # Basic packet information
    # --------------------------------------------------------

    actual_packet_number = _get_packet_number(
        packet,
        packet_number,
    )

    timestamp = _get_packet_timestamp(packet)

    src_ip, dst_ip = _get_ip_addresses(packet)

    src_port, dst_port = _get_ports(packet)

    transport_protocol = _get_transport_protocol(packet)


    # --------------------------------------------------------
    # Application protocol
    # --------------------------------------------------------

    application_protocol = identify_application_protocol(
        packet,
        src_port,
        dst_port,
    )


    # --------------------------------------------------------
    # Create PacketRecord
    # --------------------------------------------------------

    def _get_packet_length(packet):
        ...

    record = PacketRecord(
        packet_number=actual_packet_number,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport_protocol=transport_protocol,
        application_protocol=application_protocol,
        packet_length=_get_packet_length(packet),
)

    return record


# ============================================================
# Protocol summary
# ============================================================

def _build_summary(
    packets: List[PacketRecord],
    total_packets: int,
    skipped_packets: int,
) -> ProtocolSummary:
    """
    Build ProtocolSummary from successfully parsed packets.
    """

    smtp_packets = 0
    imap_packets = 0
    pop3_packets = 0
    unknown_packets = 0


    for packet in packets:

        protocol = _safe_str(
            getattr(
                packet,
                "application_protocol",
                "",
            )
        ).upper()


        if protocol == "SMTP":

            smtp_packets += 1


        elif protocol in {
            "IMAP",
            "IMAPS",
        }:

            imap_packets += 1


        elif protocol in {
            "POP3",
            "POP3S",
        }:

            pop3_packets += 1


        elif protocol in {
            "",
            "UNKNOWN",
        }:

            unknown_packets += 1


    return ProtocolSummary(
        total_packets=total_packets,
        smtp_packets=smtp_packets,
        imap_packets=imap_packets,
        pop3_packets=pop3_packets,
        unknown_packets=unknown_packets,
        skipped_packets=skipped_packets,
    )


# ============================================================
# Main parser
# ============================================================

def parse_pcap(
    file_path: str,
) -> Tuple[List[PacketRecord], ProtocolSummary]:
    """
    Parse a PCAP/PCAPNG file.

    Parameters
    ----------
    file_path:
        Path to .pcap, .pcapng, or .cap file.

    Returns
    -------
    packets:
        List of PacketRecord objects.

    summary:
        ProtocolSummary object.

    Raises
    ------
    InvalidPcapFileError
        If the file does not exist, has an unsupported extension,
        TShark cannot be found, or PyShark cannot open the PCAP.
    """

    # --------------------------------------------------------
    # Resolve path
    # --------------------------------------------------------

    path = Path(file_path).expanduser().resolve()


    # --------------------------------------------------------
    # Check file
    # --------------------------------------------------------

    if not path.exists():

        raise InvalidPcapFileError(
            f"PCAP file does not exist: {path}"
        )


    if not path.is_file():

        raise InvalidPcapFileError(
            f"PCAP path is not a file: {path}"
        )


    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:

        raise InvalidPcapFileError(
            "Unsupported PCAP file extension. "
            "Use .pcap, .pcapng, or .cap."
        )


    # --------------------------------------------------------
    # Find TShark
    # --------------------------------------------------------

    try:

        tshark_path = _find_tshark()

    except Exception as exc:

        raise InvalidPcapFileError(
            str(exc)
        ) from exc


    logger.info(
        "Using TShark: %s",
        tshark_path,
    )


    # --------------------------------------------------------
    # Fix Python 3.14 / PyShark event loop
    # --------------------------------------------------------

    _ensure_event_loop()


    # --------------------------------------------------------
    # Open PCAP
    # --------------------------------------------------------

    try:
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

        capture = pyshark.FileCapture(
            str(path),
            keep_packets=False,
            tshark_path=tshark_path,
        )
    except Exception as exc:
        raise InvalidPcapFileError(
            f"TShark could not open '{path}': {exc}"
        ) from exc


    # --------------------------------------------------------
    # Parse packets
    # --------------------------------------------------------

    packets: List[PacketRecord] = []

    total_packets = 0

    skipped_packets = 0


    try:

        for packet in capture:

            total_packets += 1


            try:

                record = _packet_to_record(
                    packet,
                    total_packets,
                )

                packets.append(record)


            except Exception as exc:

                skipped_packets += 1

                logger.warning(
                    "Skipping packet %s: %s",
                    total_packets,
                    exc,
                )


    except Exception as exc:

        raise InvalidPcapFileError(
            f"Error while reading PCAP '{path}': {exc}"
        ) from exc


    finally:

        try:
            capture.close()

        except Exception:
            pass


    # --------------------------------------------------------
    # Build summary
    # --------------------------------------------------------

    summary = _build_summary(
        packets=packets,
        total_packets=total_packets,
        skipped_packets=skipped_packets,
    )


    # --------------------------------------------------------
    # Logging
    # --------------------------------------------------------

    logger.info(
        "PCAP parsing completed."
    )

    logger.info(
        "Total packets: %s",
        total_packets,
    )

    logger.info(
        "Kept packets: %s",
        len(packets),
    )

    logger.info(
        "Skipped packets: %s",
        skipped_packets,
    )


    return packets, summary


# ============================================================
# Optional command-line test
# ============================================================

if __name__ == "__main__":

    import sys


    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python -m app.analysis.m2_parser.parser "
            "path\\to\\file.pcap"
        )

        raise SystemExit(1)


    pcap_file = sys.argv[1]


    try:

        parsed_packets, parsed_summary = parse_pcap(
            pcap_file
        )


        print()
        print("========================================")
        print("SecureMailScope M2 PCAP Parser")
        print("========================================")
        print()

        print("Summary:")
        print(parsed_summary)

        print()

        print(
            "Packets:",
            len(parsed_packets),
        )

        print()


        for packet in parsed_packets[:10]:

            print(packet)


    except Exception as exc:

        print(
            f"ERROR: {exc}"
        )

        raise