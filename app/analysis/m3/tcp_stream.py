from scapy.all import rdpcap, IP, TCP


EMAIL_PORTS = {
    25: "SMTP",
    465: "SMTP",
    587: "SMTP",
    143: "IMAP",
    993: "IMAP",
    110: "POP3",
    995: "POP3",
}


def detect_protocol(src_port, dst_port):
    if src_port in EMAIL_PORTS:
        return EMAIL_PORTS[src_port]

    if dst_port in EMAIL_PORTS:
        return EMAIL_PORTS[dst_port]

    return "TCP"


def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    streams = {}

    for packet in packets:

        if IP not in packet or TCP not in packet:
            continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)

        protocol = detect_protocol(src_port, dst_port)

        stream_id = (
            f"{src_ip}:{src_port}-"
            f"{dst_ip}:{dst_port}"
        )

        if stream_id not in streams:
            streams[stream_id] = {
                "stream_id": stream_id,
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": protocol,
                "packet_count": 0,
                "data": "",
            }

        streams[stream_id]["packet_count"] += 1

        if packet[TCP].payload:
            try:
                payload = bytes(packet[TCP].payload)
                text = payload.decode(
                    "utf-8",
                    errors="ignore"
                )

                streams[stream_id]["data"] += text

            except Exception:
                pass

    results = []

    commands = [
        "HELO",
        "EHLO",
        "MAIL FROM",
        "RCPT TO",
        "AUTH",
        "LOGIN",
        "STARTTLS",
        "USER",
        "PASS",
    ]

    for stream in streams.values():

        data = stream["data"].upper()

        starttls_detected = "STARTTLS" in data

        email_commands = []

        for command in commands:
            if command in data:
                email_commands.append(command)

        results.append({
            "stream_id": stream["stream_id"],
            "source_ip": stream["source_ip"],
            "source_port": stream["source_port"],
            "destination_ip": stream["destination_ip"],
            "destination_port": stream["destination_port"],
            "protocol": stream["protocol"],
            "packet_count": stream["packet_count"],
            "starttls_detected": starttls_detected,
            "email_commands": email_commands,
            "data": stream["data"],
        })

    return results