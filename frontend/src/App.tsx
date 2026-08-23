import { useState } from "react";
import "./App.css";

function App() {
  const [secret, setSecret] = useState("");
  const [analyzed, setAnalyzed] = useState(false);

  const handleAnalyze = () => {
    setAnalyzed(true);
  };

  return (
    <main className="app">
      <div className="container">
        <header className="header">
          <div>
            <p className="eyebrow">ADAPTIVE SECRET LIFECYCLE</p>
            <h1>Securely share sensitive information.</h1>
            <p className="subtitle">
              Analyze your content before sharing it and determine the level
              of protection it needs.
            </p>
          </div>
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
              setAnalyzed(false);
            }}
            placeholder={`Example:\nDB_HOST=production.company.com\nDB_USER=admin\nDB_PASSWORD=your-password`}
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

        {analyzed && (
          <section className="card result-card">
            <div className="card-header">
              <h2>Security Analysis</h2>
              <span className="risk-badge">PENDING ENGINE</span>
            </div>

            <p className="result-placeholder">
              Secret detection and compound risk scoring will appear here.
            </p>

            <div className="placeholder-grid">
              <div>
                <span>Detected Secrets</span>
                <strong>—</strong>
              </div>

              <div>
                <span>Risk Score</span>
                <strong>—</strong>
              </div>

              <div>
                <span>Risk Level</span>
                <strong>—</strong>
              </div>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

export default App;
