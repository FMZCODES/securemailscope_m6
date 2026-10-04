export default function ProtocolSummary({
  protocols,
  starttlsCount,
  totalStreams,
  tlsVersions,
  cipherSuites,
  keyExchanges,
  forwardSecrecy,
}) {
  return (
    <div className="card protocol-card">
      <p className="label">Protocol & TLS summary</p>

      <div className="summary-list">
        <SummaryRow label="Email protocols" value={join(protocols)} />
        <SummaryRow
          label="STARTTLS"
          value={
            totalStreams
              ? `${starttlsCount}/${totalStreams} stream(s) detected`
              : "—"
          }
        />
        <SummaryRow label="TLS version" value={join(tlsVersions)} />
        <SummaryRow label="Cipher suite" value={join(cipherSuites)} />
        <SummaryRow label="Key exchange" value={join(keyExchanges)} />
        <SummaryRow label="Forward Secrecy" value={join(forwardSecrecy)} />
      </div>
    </div>
  );
}

function SummaryRow({ label, value }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value || "—"}</strong>
    </div>
  );
}

function join(values) {
  return Array.isArray(values) && values.length ? values.join(", ") : "";
}
