export default function ProtocolSummary({
  protocols = [],
  starttlsCount = 0,
  totalStreams = 0,
  tlsVersions = [],
  cipherSuites = [],
  keyExchanges = [],
  forwardSecrecy = [],
}) {
  return (
    <div className="card protocol-card">
      <p className="label">Protocol & TLS summary</p>

      <div className="summary-list">
        <SummaryRow
          label="Email protocols"
          value={formatList(protocols, "Not detected")}
        />
        <SummaryRow
          label="STARTTLS"
          value={
            totalStreams > 0
              ? `${starttlsCount}/${totalStreams} stream(s) detected`
              : "Not detected"
          }
        />
        <SummaryRow
          label="TLS version"
          value={formatList(tlsVersions, "Not observed in capture")}
        />
        <SummaryRow
          label="Cipher suite"
          value={formatList(cipherSuites, "Not observed in capture")}
        />
        <SummaryRow
          label="Key exchange"
          value={formatList(keyExchanges, "Not observed in capture")}
        />
        <SummaryRow
          label="Forward Secrecy"
          value={formatList(forwardSecrecy, "Not observed in capture")}
        />
      </div>
    </div>
  );
}

function SummaryRow({ label, value }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatList(values, fallback) {
  if (!Array.isArray(values) || values.length === 0) {
    return fallback;
  }

  return values.filter(Boolean).join(", ") || fallback;
}
