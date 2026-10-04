from __future__ import annotations

from pathlib import Path
from typing import Any
import json
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


def _find_tshark() -> str | None:
    """
    Find TShark on Windows/Linux/macOS.
    """

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
    """
    Identify an email protocol from either TCP endpoint.
    """

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
    }


def _finalize_stream(stream: dict[str, Any]) -> dict[str, Any]:
    """
    Analyse accumulated TCP payload data.
    """

    data = stream.get("data", "")

    upper = data.upper()

    stream["starttls_detected"] = "STARTTLS" in upper

    stream["email_commands"] = [
        command
        for command in EMAIL_COMMANDS
        if command in upper
    ]

    return stream


def _analyze_with_tshark(
    pcap_path: Path,
) -> dict[str, Any] | None:
    """
    Analyse TCP packets using TShark.

    This is the preferred method because the project already
    uses TShark through M2 and it handles PCAP parsing better
    than loading the entire capture with Scapy.
    """

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

        while len(parts) < 7:
            parts.append("")

        (
            ip_src,
            ipv6_src,
            ip_dst,
            ipv6_dst,
            src_port_raw,
            dst_port_raw,
            payload_hex,
        ) = parts[:7]

        source_ip = ip_src or ipv6_src
        destination_ip = ip_dst or ipv6_dst

        if not source_ip or not destination_ip:
            continue

        try:
            source_port = int(src_port_raw)
            destination_port = int(dst_port_raw)
        except ValueError:
            continue

        protocol = _protocol(
            source_port,
            destination_port,
        )

        # Bidirectional TCP stream identifier.
        endpoint_a = (
            source_ip,
            source_port,
        )

        endpoint_b = (
            destination_ip,
            destination_port,
        )

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

        if payload_hex:
            try:
                payload = bytes.fromhex(
                    payload_hex.replace(":", "")
                )

                text = payload.decode(
                    "utf-8",
                    errors="ignore",
                )

                stream["data"] += text

            except Exception:
                pass

    results = [
        _finalize_stream(stream)
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
    """
    Scapy fallback parser.
    """

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

        protocol = _protocol(
            source_port,
            destination_port,
        )

        endpoint_a = (
            source_ip,
            source_port,
        )

        endpoint_b = (
            destination_ip,
            destination_port,
        )

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

                text = payload.decode(
                    "utf-8",
                    errors="ignore",
                )

                stream["data"] += text

            except Exception:
                pass

    results = [
        _finalize_stream(stream)
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

    # --------------------------------------------------
    # Preferred parser: TShark
    # --------------------------------------------------

    result = _analyze_with_tshark(pcap_path)

    if result is not None:
        return result

    # --------------------------------------------------
    # Fallback parser: Scapy
    # --------------------------------------------------

    return _analyze_with_scapy(pcap_path)


def save_output(
    result: dict[str, Any],
    output_path: str | Path,
) -> None:

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            result.get("results", []),
            indent=4,
        ),
        encoding="utf-8",
    )