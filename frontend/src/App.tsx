import { useState } from "react";
import "./App.css";
import { detectSecrets } from "./services/secretDetector";
import { analyzeRisk } from "./services/riskEngine";
import type { RiskAnalysis } from "./services/riskEngine";

function App() {
  const [secret, setSecret] = useState("");
  const [analysis, setAnalysis] = useState<RiskAnalysis | null>(null);

  const handleAnalyze = () => {
    const detectedSecrets = detectSecrets(secret);
    const result = analyzeRisk(detectedSecrets);

    setAnalysis(result);
  };

  const getRiskClass = (level: string) => {
    return `risk-${level.toLowerCase()}`;
  };

  return (
    <main className="app">
      <div className="container">
        <header className="header">
          <p className="eyebrow">ADAPTIVE SECRET LIFECYCLE</p>

          <h1>Securely share sensitive information.</h1>

          <p className="subtitle">
            Analyze your content before sharing it and determine the level of
            protection it needs.
          </p>
        </header>

        <section className="card">
          <div className="card-header">
            <h2>Create Secure Secret</h2>
            <span className="status">LOCAL ANALYSIS</span>
          </div>

          <label htmlFor="secret-input">Secret or sensitive content</label>

          <textarea
            id="secret-input"
            value={secret}
            onChange={(event) => {
              setSecret(event.target.value);
              setAnalysis(null);
            }}
            placeholder={`Example:
DB_HOST=production.company.com
DB_USER=admin
DB_PASSWORD=your-password`}
            rows={10}
          />

          <div className="actions">
            <button
              type="button"
              onClick={handleAnalyze}
              disabled={!secret.trim()}
            >
              Analyze Secret
            </button>
          </div>
        </section>

        {analysis && (
          <section className="card result-card">
            <div className="card-header">
              <h2>Security Analysis</h2>

              <span className={`risk-badge ${getRiskClass(analysis.level)}`}>
                {analysis.level}
              </span>
            </div>

            <div className="placeholder-grid">
              <div>
                <span>Detected Secrets</span>
                <strong>{analysis.detectedSecrets.length}</strong>
              </div>

              <div>
                <span>Risk Score</span>
                <strong>{analysis.score}/100</strong>
              </div>

              <div>
                <span>Risk Level</span>
                <strong>{analysis.level}</strong>
              </div>
            </div>

            <div className="analysis-section">
              <h3>Detected Content</h3>

              {analysis.detectedSecrets.length === 0 ? (
                <p className="result-placeholder">
                  No obvious sensitive secrets were detected.
                </p>
              ) : (
                <div className="detected-list">
                  {analysis.detectedSecrets.map((secretItem, index) => (
                    <div className="detected-item" key={`${secretItem.type}-${index}`}>
                      <div>
                        <strong>{secretItem.label}</strong>
                        <span>
                          Confidence:{" "}
                          {Math.round(secretItem.confidence * 100)}%
                        </span>
                      </div>

                      <span
                        className={`severity severity-${secretItem.severity}`}
                      >
                        {secretItem.severity.toUpperCase()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="analysis-section">
              <h3>Security Recommendations</h3>

              <div className="recommendations">
                {analysis.recommendations.map((recommendation) => (
                  <div className="recommendation" key={recommendation}>
                    <span>✓</span>
                    <p>{recommendation}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

export default App;