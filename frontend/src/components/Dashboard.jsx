import SecurityScore from "./SecurityScore";
import ProtocolSummary from "./ProtocolSummary";
import FindingsTable from "./FindingsTable";

export default function Dashboard({ data }) {
  const m2 = data?.m2 || {};
  const m2Summary = m2.summary || {};
  const m3 = data?.m3 || {};
  const m4 = data?.m4 || {};
  const m5 = data?.m5 || {};

  const m3Streams = Array.isArray(m3.results) ? m3.results : [];
  const m4Streams = Array.isArray(m4.results) ? m4.results : [];
  const m5Streams = Array.isArray(m5.results) ? m5.results : [];

  const riskScores = m5Streams
    .map((stream) => Number(stream?.risk?.score))
    .filter(Number.isFinite);

  const overallRisk = riskScores.length ? Math.max(...riskScores) : null;
  const securityScore = overallRisk === null ? null : 100 - overallRisk;

  const protocols = unique(
    m3Streams.map((stream) => stream?.protocol).filter(Boolean)
  );

  const findings = buildFindings(m4Streams, m5Streams);

  const tlsVersions = unique(
    m4Streams.map((stream) => stream?.tls?.tls_version).filter(Boolean)
  );

  const cipherSuites = unique(
    m4Streams.map((stream) => stream?.tls?.cipher_suite).filter(Boolean)
  );

  const keyExchanges = unique(
    m4Streams.map((stream) => stream?.tls?.key_exchange).filter(Boolean)
  );

  const forwardSecrecy = unique(
    m4Streams
      .map((stream) => stream?.tls?.forward_secrecy)
      .filter((value) => value !== undefined && value !== null)
      .map(formatBool)
  );

  const starttlsCount = m4Streams.filter(
    (stream) => stream?.starttls_detected === true
  ).length;

  return (
    <section className="dashboard">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Assessment result</p>
          <h2>Security Posture Dashboard</h2>
          <p className="muted">
            Complete M2 → M3 → M4 → M5 analysis for {data?.filename || "uploaded PCAP"}.
          </p>
        </div>

        <span className="status-pill">
          {data?.status || "Analysis complete"}
        </span>
      </div>

      <div className="dashboard-grid">
        <SecurityScore
          score={securityScore}
          riskScore={overallRisk}
          streams={m5Streams.length}
        />
        <ProtocolSummary
          protocols={protocols}
          starttlsCount={starttlsCount}
          totalStreams={m4Streams.length || m3Streams.length}
          tlsVersions={tlsVersions}
          cipherSuites={cipherSuites}
          keyExchanges={keyExchanges}
          forwardSecrecy={forwardSecrecy}
        />
      </div>

      <div className="assessment-grid">
        <ModuleCard
          title="M2 — PCAP Analysis"
          subtitle="Packet and protocol summary"
        >
          <MetricGrid
            items={[
              ["Total packets", m2Summary.total_packets],
              ["SMTP packets", m2Summary.smtp_packets],
              ["IMAP packets", m2Summary.imap_packets],
              ["POP3 packets", m2Summary.pop3_packets],
              ["Unknown packets", m2Summary.unknown_packets],
              ["Skipped packets", m2Summary.skipped_packets],
            ]}
          />
        </ModuleCard>

        <ModuleCard
          title="M3 — Stream Analysis"
          subtitle={`${m3Streams.length || m3.streams_analyzed || 0} stream(s) analyzed`}
        >
          {m3Streams.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Packets</th>
                    <th>STARTTLS</th>
                  </tr>
                </thead>
                <tbody>
                  {m3Streams.map((stream, index) => (
                    <tr key={stream.stream_id || index}>
                      <td>{stream.protocol || "TCP"}</td>
                      <td>{formatEndpoint(stream.source_ip, stream.source_port)}</td>
                      <td>{formatEndpoint(stream.destination_ip, stream.destination_port)}</td>
                      <td>{valueOrDash(stream.packet_count)}</td>
                      <td>{formatBool(stream.starttls_detected)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              M3 stream details are not present in this response.
            </div>
          )}
        </ModuleCard>
      </div>

      <ModuleCard
        title="M4 — TLS & Certificate Analysis"
        subtitle={`${m4Streams.length || m4.streams_analyzed || 0} stream(s) analyzed`}
      >
        {m4Streams.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>STARTTLS</th>
                  <th>TLS version</th>
                  <th>Cipher suite</th>
                  <th>Key exchange</th>
                  <th>Forward secrecy</th>
                  <th>Certificate</th>
                </tr>
              </thead>
              <tbody>
                {m4Streams.map((stream, index) => (
                  <tr key={stream.stream_id || index}>
                    <td>{stream.protocol || "—"}</td>
                    <td>{formatBool(stream.starttls_detected)}</td>
                    <td>{stream.tls?.tls_version || "—"}</td>
                    <td>{stream.tls?.cipher_suite || "—"}</td>
                    <td>{stream.tls?.key_exchange || "—"}</td>
                    <td>{formatBool(stream.tls?.forward_secrecy)}</td>
                    <td>{formatBool(stream.certificate?.observed)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">M4 stream details are not present in this response.</div>
        )}
      </ModuleCard>

      <ModuleCard
        title="M5 — AI/ML Risk Assessment"
        subtitle={`${m5Streams.length || m5.streams_analyzed || 0} stream(s) analyzed`}
      >
        {m5Streams.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Risk score</th>
                  <th>Risk level</th>
                  <th>ML model</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {m5Streams.map((stream, index) => {
                  const risk = stream.risk || {};
                  const streamFindings = [
                    ...(Array.isArray(stream.findings) ? stream.findings : []),
                    ...(Array.isArray(risk.findings) ? risk.findings : []),
                  ];

                  return (
                    <tr key={stream.stream_id || index}>
                      <td>{stream.protocol || "—"}</td>
                      <td><strong>{valueOrDash(risk.score)}</strong>/100</td>
                      <td>
                        <span className={`severity ${String(risk.risk_level || "INFO").toLowerCase()}`}>
                          {risk.risk_level || "—"}
                        </span>
                      </td>
                      <td>{stream.ml_model_status || "—"}</td>
                      <td>{streamFindings.length}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">M5 risk details are not present in this response.</div>
        )}
      </ModuleCard>

      <FindingsTable findings={findings} />

      <ModuleCard title="Analysis Information" subtitle="Run metadata and persistence status">
        <MetricGrid
          items={[
            ["Analysis ID", data?.analysis_id],
            ["Filename", data?.filename],
            ["Pipeline", data?.pipeline],
            ["Status", data?.status],
            ["MongoDB saved", formatBool(data?.mongodb_saved)],
            ["Created at", data?.created_at],
          ]}
        />
        {data?.message && <p className="muted module-message">{data.message}</p>}
      </ModuleCard>

      <details className="raw-data">
        <summary>View raw JSON</summary>
        <pre>{JSON.stringify(data, null, 2)}</pre>
      </details>
    </section>
  );
}

function ModuleCard({ title, subtitle, children }) {
  return (
    <div className="card module-card">
      <div className="section-heading compact">
        <div>
          <p className="label">{title}</p>
          <p className="module-subtitle">{subtitle}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

function MetricGrid({ items }) {
  return (
    <div className="metric-grid">
      {items.map(([label, value]) => (
        <div className="metric" key={label}>
          <span>{label}</span>
          <strong>{valueOrDash(value)}</strong>
        </div>
      ))}
    </div>
  );
}

function buildFindings(m4Streams, m5Streams) {
  const findings = [];

  m4Streams.forEach((stream) => {
    (Array.isArray(stream?.findings) ? stream.findings : []).forEach((finding) => {
      findings.push({ ...finding, stream_id: stream.stream_id, source: "M4" });
    });
  });

  m5Streams.forEach((stream) => {
    const riskFindings = Array.isArray(stream?.risk?.findings)
      ? stream.risk.findings
      : [];

    riskFindings.forEach((finding) => {
      findings.push({ ...finding, stream_id: stream.stream_id, source: "M5" });
    });
  });

  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.stream_id}|${finding.type}|${finding.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function unique(values) {
  return [...new Set(values.map(String))];
}

function valueOrDash(value) {
  return value === undefined || value === null || value === "" ? "—" : value;
}

function formatBool(value) {
  if (value === true) return "Enabled";
  if (value === false) return "Disabled";
  return "—";
}

function formatEndpoint(ip, port) {
  if (!ip && !port) return "—";
  return `${ip || "?"}:${port || "?"}`;
}
