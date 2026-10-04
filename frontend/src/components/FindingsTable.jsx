export default function FindingsTable({ findings }) {
  return (
    <div className="card findings-card">
      <div className="section-heading compact">
        <div>
          <p className="label">Security findings</p>
          <h3>{findings.length} finding(s)</h3>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty-state">
          No security findings were returned by M4/M5.
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Stream</th>
                <th>Message</th>
                <th>Recommendation</th>
              </tr>
            </thead>

            <tbody>
              {findings.map((finding, index) => (
                <tr key={`${finding.stream_id || "stream"}-${finding.type || "finding"}-${index}`}>
                  <td>{finding.source || "—"}</td>
                  <td>
                    <span
                      className={`severity ${String(
                        finding.severity || "INFO"
                      ).toLowerCase()}`}
                    >
                      {finding.severity || "INFO"}
                    </span>
                  </td>
                  <td>{finding.type || "—"}</td>
                  <td>{finding.stream_id || "—"}</td>
                  <td>{finding.message || finding.description || "—"}</td>
                  <td>
                    {finding.recommendation ||
                      "Review the finding and apply the appropriate security configuration."}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
