import { useState } from "react";
import Navbar from "./components/Navbar";
import PcapUpload from "./components/PcapUpload";
import Dashboard from "./components/Dashboard";
import { analyzePcap, getResults } from "./services/api";

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleAnalyze(file) {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const uploadResult = await analyzePcap(file);

      if (uploadResult?.analysis_id) {
        try {
          const completeResult = await getResults(uploadResult.analysis_id);
          setResult(completeResult);
          return;
        } catch (resultError) {
          console.warn(
            "Complete result could not be loaded; using upload response:",
            resultError
          );
        }
      }

      setResult(uploadResult);
    } catch (err) {
      setError(err.message || "PCAP analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <Navbar />

      <main className="container">
        <section className="hero">
          <div>
            <p className="eyebrow">SIH26159 • Cybersecurity</p>
            <h1>SecureMailScope</h1>
            <p className="hero-text">
              AI-assisted cryptographic security posture assessment for
              encrypted email communications.
            </p>
          </div>
        </section>

        <PcapUpload onAnalyze={handleAnalyze} loading={loading} />

        {error && <div className="error-box">{error}</div>}

        {result && <Dashboard data={result} />}
      </main>
    </div>
  );
}
