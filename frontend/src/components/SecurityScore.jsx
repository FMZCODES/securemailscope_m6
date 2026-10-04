export default function SecurityScore({ score, riskScore, streams }) {
  return (
    <div className="card score-card">
      <p className="label">Security posture score</p>

      <div className="score">
        {score === null || score === undefined ? "—" : score}
        <span>/100</span>
      </div>

      <p className="muted">
        {riskScore === null || riskScore === undefined
          ? "M5 risk data is not available in this response."
          : `Overall risk: ${riskScore}/100 across ${streams} stream(s).`}
      </p>
    </div>
  );
}
