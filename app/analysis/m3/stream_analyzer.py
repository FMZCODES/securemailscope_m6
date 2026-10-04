from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import re
import shutil
import subprocess

from scapy.all import rdpcap, IP, IPv6, TCP


EMAIL_PORTS = {
    25: "SMTP",
    465: "SMTP",
    587: "SMTP",
    143: "IMAP",
    993: "IMAP",
    110: "POP3",
    995: "POP3",
}

EMAIL_COMMANDS = (
    "HELO",
    "EHLO",
    "MAIL FROM",
    "RCPT TO",
    "AUTH",
    "LOGIN",
    "STARTTLS",
    "USER",
    "PASS",
)

# Common IANA TLS cipher-suite IDs. TShark may return either the symbolic
# name or the numeric value depending on its output configuration/version.
TLS_CIPHER_IDS = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}

TLS_VERSION_IDS = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
    "768": "SSL 3.0",
    "769": "TLS 1.0",
    "770": "TLS 1.1",
    "771": "TLS 1.2",
    "772": "TLS 1.3",
}


def _find_tshark() -> str | None:
    """Find TShark on Windows/Linux/macOS."""

    tshark = shutil.which("tshark")

    if tshark:
        return tshark

    windows_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    for path in windows_paths:
        if Path(path).is_file():
            return path

    return None


def _protocol(src_port: int, dst_port: int) -> str:
    """Identify an email protocol from either TCP endpoint."""

    return (
        EMAIL_PORTS.get(src_port)
        or EMAIL_PORTS.get(dst_port)
        or "TCP"
    )


def _ip_layer(packet):
    if IP in packet:
        return packet[IP]

    if IPv6 in packet:
        return packet[IPv6]

    return None


def _build_stream(
    stream_id: str,
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    protocol: str,
) -> dict[str, Any]:

    return {
        "stream_id": stream_id,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": 0,
        "starttls_detected": False,
        "email_commands": [],
        "data": "",
        "tls": {
            "observed": False,
            "tls_version": None,
            "cipher_suite": None,
            "key_exchange": None,
            "forward_secrecy": None,
        },
        "_tshark_stream_id": None,
    }


def _finalize_stream(stream: dict[str, Any]) -> dict[str, Any]:
    """Analyse accumulated TCP payload data."""

    data = stream.get("data", "")
    upper = data.upper()

    stream["starttls_detected"] = "STARTTLS" in upper

    stream["email_commands"] = [
        command
        for command in EMAIL_COMMANDS
        if command in upper
    ]

    return stream


def _first_value(value: str) -> str | None:
    if not value:
        return None
    for item in re.split(r"[,;,]", value):
        item = item.strip()
        if item:
            return item
    return None


def _normalize_tls_version(value: str | None) -> str | None:
    value = _first_value(value or "")
    if not value:
        return None

    normalized = value.strip()
    lowered = normalized.lower()

    if lowered in TLS_VERSION_IDS:
        return TLS_VERSION_IDS[lowered]

    match = re.search(r"0x([0-9a-fA-F]{4})", normalized)
    if match:
        return TLS_VERSION_IDS.get(
            f"0x{match.group(1).lower()}",
            normalized,
        )

    # TShark may already return a display name.
    if "TLS 1.3" in normalized:
        return "TLS 1.3"
    if "TLS 1.2" in normalized:
        return "TLS 1.2"
    if "TLS 1.1" in normalized:
        return "TLS 1.1"
    if "TLS 1.0" in normalized:
        return "TLS 1.0"

    return normalized


def _normalize_cipher(value: str | None) -> str | None:
    value = _first_value(value or "")
    if not value:
        return None

    normalized = value.strip()

    # Handle values such as 0xc02f or c02f.
    match = re.fullmatch(r"(?:0x)?([0-9a-fA-F]{4})", normalized)
    if match:
        cipher_id = int(match.group(1), 16)
        return TLS_CIPHER_IDS.get(cipher_id, normalized)

    return normalized


def _infer_key_exchange(cipher_suite: str | None, key_share: str | None = None) -> str | None:
    text = (cipher_suite or "").upper()
    key_share_text = (key_share or "").upper()

    if "ECDHE" in text:
        return "ECDHE"
    if "DHE" in text:
        return "DHE"
    if "ECDH" in text:
        return "ECDH"
    if "RSA" in text and "ECDHE" not in text:
        return "RSA"

    # TLS 1.3 cipher suites no longer encode the key exchange. A key-share
    # extension proves that an ephemeral group was used.
    if key_share_text:
        return "ECDHE"

    return None


def _forward_secrecy(key_exchange: str | None, cipher_suite: str | None, tls_version: str | None) -> bool | None:
    exchange = (key_exchange or "").upper()
    cipher = (cipher_suite or "").upper()

    if exchange in {"ECDHE", "DHE"}:
        return True

    if exchange in {"RSA", "ECDH"}:
        return False

    # TLS 1.3 uses ephemeral key exchange by design, but we only report
    # that when the capture contains TLS 1.3 handshake evidence.
    if tls_version == "TLS 1.3" and ("TLS_" in cipher or cipher):
        return True

    return None


def _extract_tls_metadata_with_tshark(
    pcap_path: Path,
) -> dict[str, dict[str, Any]]:
    """
    Extract TLS handshake metadata directly from TShark.

    M3 previously reconstructed SMTP streams but never populated TLS fields.
    This helper reads the actual TLS dissector fields from the same PCAP so M4
    receives real TLS evidence instead of empty placeholders.
    """

    tshark = _find_tshark()
    if not tshark:
        return {}

    # These fields are present in modern Wireshark/TShark and cover TLS 1.2
    # and TLS 1.3. We intentionally keep the command small so an unsupported
    # optional field cannot break the main stream parser.
    command = [
        tshark,
        "-r",
        str(pcap_path),
        "-Y",
        "tls.handshake || tls.record",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
        "-e",
        "tcp.stream",
        "-e",
        "tls.handshake.version",
        "-e",
        "tls.record.version",
        "-e",
        "tls.handshake.ciphersuite",
        "-e",
        "tls.handshake.extensions_key_share_group",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except Exception:
        return {}

    if completed.returncode != 0:
        return {}

    metadata: dict[str, dict[str, Any]] = {}

    for line in completed.stdout.splitlines():
        if not line.strip():
            continue

        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")

        stream_no, handshake_version, record_version, cipher, key_share = parts[:5]

        if not stream_no:
            continue

        item = metadata.setdefault(
            stream_no,
            {
                "tls_version": None,
                "cipher_suite": None,
                "key_exchange": None,
                "forward_secrecy": None,
            },
        )

        tls_version = _normalize_tls_version(
            handshake_version or record_version
        )
        if tls_version:
            # Prefer the strongest version observed in the handshake.
            current = item.get("tls_version")
            if current is None or tls_version == "TLS 1.3":
                item["tls_version"] = tls_version

        cipher_suite = _normalize_cipher(cipher)
        if cipher_suite and not item.get("cipher_suite"):
            item["cipher_suite"] = cipher_suite

        key_exchange = _infer_key_exchange(
            item.get("cipher_suite"),
            key_share,
        )
        if key_exchange:
            item["key_exchange"] = key_exchange

        item["forward_secrecy"] = _forward_secrecy(
            item.get("key_exchange"),
            item.get("cipher_suite"),
            item.get("tls_version"),
        )

    return metadata


def _apply_tls_metadata(
    streams: dict[str, dict[str, Any]],
    metadata: dict[str, dict[str, Any]],
) -> None:
    """Attach TShark TLS metadata to the matching M3 TCP stream."""

    if not metadata:
        return

    for stream in streams.values():
        stream_no = stream.get("_tshark_stream_id")
        if stream_no is None:
            continue

        item = metadata.get(str(stream_no))
        if not item:
            continue

        tls = stream.setdefault("tls", {})

        for key in (
            "tls_version",
            "cipher_suite",
            "key_exchange",
            "forward_secrecy",
        ):
            value = item.get(key)
            if value is not None:
                tls[key] = value

        tls["observed"] = any(
            tls.get(key) is not None
            for key in (
                "tls_version",
                "cipher_suite",
                "key_exchange",
                "forward_secrecy",
            )
        )


def _clean_stream(stream: dict[str, Any]) -> dict[str, Any]:
    """Remove internal parser-only fields before returning M3."""

    stream.pop("data", None)
    stream.pop("_tshark_stream_id", None)
    return stream


def _analyze_with_tshark(
    pcap_path: Path,
) -> dict[str, Any] | None:
    """Analyse TCP packets using TShark."""

    tshark = _find_tshark()

    if not tshark:
        return None

    command = [
        tshark,
        "-r",
        str(pcap_path),
        "-Y",
        "tcp",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.payload",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

    if completed.returncode != 0:
        return None

    streams: dict[str, dict[str, Any]] = {}

    for line in completed.stdout.splitlines():
        if not line.strip():
            continue

        parts = line.split("\t")
        while len(parts) < 8:
            parts.append("")

        (
            tcp_stream_id,
            ip_src,
            ipv6_src,
            ip_dst,
            ipv6_dst,
            src_port_raw,
            dst_port_raw,
            payload_hex,
        ) = parts[:8]

        source_ip = ip_src or ipv6_src
        destination_ip = ip_dst or ipv6_dst

        if not source_ip or not destination_ip:
            continue

        try:
            source_port = int(src_port_raw)
            destination_port = int(dst_port_raw)
        except ValueError:
            continue

        protocol = _protocol(source_port, destination_port)

        endpoint_a = (source_ip, source_port)
        endpoint_b = (destination_ip, destination_port)

        if endpoint_a <= endpoint_b:
            stream_id = (
                f"{source_ip}:{source_port}-"
                f"{destination_ip}:{destination_port}"
            )
        else:
            stream_id = (
                f"{destination_ip}:{destination_port}-"
                f"{source_ip}:{source_port}"
            )

        stream = streams.setdefault(
            stream_id,
            _build_stream(
                stream_id,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,
            ),
        )

        stream["_tshark_stream_id"] = tcp_stream_id
        stream["packet_count"] += 1

        if payload_hex:
            try:
                payload = bytes.fromhex(payload_hex.replace(":", ""))
                text = payload.decode("utf-8", errors="ignore")
                stream["data"] += text
            except Exception:
                pass

    # Extract TLS from the same capture after the TCP streams exist.
    tls_metadata = _extract_tls_metadata_with_tshark(pcap_path)
    _apply_tls_metadata(streams, tls_metadata)

    results = [
        _clean_stream(_finalize_stream(stream))
        for stream in streams.values()
    ]

    return {
        "module": "M3 - TCP Stream and Email Analysis",
        "parser": "tshark",
        "streams_analyzed": len(results),
        "results": results,
    }


def _analyze_with_scapy(
    pcap_path: Path,
) -> dict[str, Any]:
    """Scapy fallback parser."""

    packets = rdpcap(str(pcap_path))
    streams: dict[str, dict[str, Any]] = {}

    for packet in packets:
        if TCP not in packet:
            continue

        ip = _ip_layer(packet)
        if ip is None:
            continue

        source_ip = str(ip.src)
        destination_ip = str(ip.dst)
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        protocol = _protocol(source_port, destination_port)

        endpoint_a = (source_ip, source_port)
        endpoint_b = (destination_ip, destination_port)

        if endpoint_a <= endpoint_b:
            stream_id = (
                f"{source_ip}:{source_port}-"
                f"{destination_ip}:{destination_port}"
            )
        else:
            stream_id = (
                f"{destination_ip}:{destination_port}-"
                f"{source_ip}:{source_port}"
            )

        stream = streams.setdefault(
            stream_id,
            _build_stream(
                stream_id,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,
            ),
        )

        stream["packet_count"] += 1

        if packet[TCP].payload:
            try:
                payload = bytes(packet[TCP].payload)
                text = payload.decode("utf-8", errors="ignore")
                stream["data"] += text
            except Exception:
                pass

    results = [
        _clean_stream(_finalize_stream(stream))
        for stream in streams.values()
    ]

    return {
        "module": "M3 - TCP Stream and Email Analysis",
        "parser": "scapy",
        "streams_analyzed": len(results),
        "results": results,
    }


def analyze_pcap(
    pcap_path: str | Path,
) -> dict[str, Any]:

    pcap_path = Path(pcap_path)

    if not pcap_path.is_file():
        raise FileNotFoundError(
            f"PCAP not found: {pcap_path}"
        )

    result = _analyze_with_tshark(pcap_path)

    if result is not None:
        return result

    return _analyze_with_scapy(pcap_path)


def save_output(
    result: dict[str, Any],
    output_path: str | Path,
) -> None:

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(
            result.get("results", []),
            indent=4,
        ),
        encoding="utf-8",
    )
