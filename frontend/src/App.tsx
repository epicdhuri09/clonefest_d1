import { useEffect, useRef, useState } from "react";
import "./App.css";

import { detectSecrets } from "./services/secretDetector";
import { analyzeRisk } from "./services/riskEngine";

import {
  encryptSecret,
  createShare,
  getShare,
  decryptSecret,
} from "./services/encryption";

import type { RiskAnalysis } from "./services/riskEngine";

function App() {
  const [secret, setSecret] = useState("");
  const [analysis, setAnalysis] = useState<RiskAnalysis | null>(null);

  const [encryptedData, setEncryptedData] = useState<{
    ciphertext: string;
    iv: string;
    key: string;
  } | null>(null);

  const [isEncrypting, setIsEncrypting] = useState(false);
  const [encryptionError, setEncryptionError] = useState("");

  const [shareId, setShareId] = useState<string | null>(null);
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [shareExpiresAt, setShareExpiresAt] = useState<string | null>(null);
  const [shareMaxViews, setShareMaxViews] = useState<number | null>(null);

  const [receivedSecret, setReceivedSecret] = useState("");
  const [shareError, setShareError] = useState("");
  const [isLoadingShare, setIsLoadingShare] = useState(false);

  /*
   * Prevent React StrictMode from requesting the same
   * one-time secret twice during development.
   */
  const shareLoaded = useRef(false);

  /*
   * Check whether this is a secure-share URL.
   *
   * Example:
   * http://localhost:5174/?share=abc123#encryption-key
   */
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get("share");

    if (!id) {
      return;
    }

    if (shareLoaded.current) {
      return;
    }

    shareLoaded.current = true;

    loadSharedSecret(id);
  }, []);

  /*
   * Load and decrypt a shared secret.
   */
  const loadSharedSecret = async (id: string) => {
    setIsLoadingShare(true);
    setShareError("");
    setReceivedSecret("");

    try {
      /*
       * The encryption key lives in the URL fragment.
       *
       * Example:
       * ?share=abc123#BASE64_KEY
       */
      const key = decodeURIComponent(
      window.location.hash.replace(/^#/, ""),
      );

      if (!key) {
        throw new Error(
          "Encryption key is missing from the share link.",
        );
      }

      /*
       * Ask the backend for the encrypted payload.
       *
       * The backend does NOT receive the encryption key.
       */
      const share = await getShare(id);

      /*
       * Decrypt locally in the browser.
       */
      const plaintext = await decryptSecret({
        ciphertext: share.ciphertext,
        iv: share.iv,
        key,
      });

      setShareId(share.id);
      setReceivedSecret(plaintext);
      setShareExpiresAt(share.expiresAt);
      setShareMaxViews(share.maxViews);
    } catch (error) {
      console.error("Failed to open secure share:", error);

      if (error instanceof Error) {
        setShareError(error.message);
      } else {
        setShareError(
          "This secure share could not be opened.",
        );
      }
    } finally {
      setIsLoadingShare(false);
    }
  };

  /*
   * Analyze the secret locally.
   */
  const handleAnalyze = () => {
    const detectedSecrets = detectSecrets(secret);
    const result = analyzeRisk(detectedSecrets);

    setAnalysis(result);
    setEncryptedData(null);
    setEncryptionError("");
  };

  /*
   * Encrypt locally and create a backend share.
   */
  const handleCreateSecureShare = async () => {
    if (!secret.trim()) {
      return;
    }

    setIsEncrypting(true);
    setEncryptionError("");
    setEncryptedData(null);
    setShareUrl(null);

    try {
      /*
       * Encrypt entirely in the browser.
       */
      const encrypted = await encryptSecret(secret);

      setEncryptedData(encrypted);

      /*
       * Only ciphertext + IV are sent to backend.
       * The key remains in the browser.
       */
      const createdShare = await createShare(encrypted, {
        expiresInMinutes: 10,
        maxViews: 1,
        riskLevel: analysis?.level ?? "LOW",
      });

      /*
       * Put the encryption key in the URL fragment.
       *
       * Important:
       * URL fragments are not sent to the backend.
       */
      const url = `${window.location.origin}/?share=${encodeURIComponent(
        createdShare.id,
      )}#${encodeURIComponent(encrypted.key)}`;

      setShareId(createdShare.id);
      setShareUrl(url);
      setShareExpiresAt(createdShare.expiresAt);
      setShareMaxViews(createdShare.maxViews);
    } catch (error) {
      console.error("Secure share creation failed:", error);

      if (error instanceof Error) {
        setEncryptionError(error.message);
      } else {
        setEncryptionError(
          "Failed to create secure share.",
        );
      }
    } finally {
      setIsEncrypting(false);
    }
  };

  /*
   * Copy secure-share URL.
   */
  const handleCopyLink = async () => {
    if (!shareUrl) {
      return;
    }

    try {
      await navigator.clipboard.writeText(shareUrl);
    } catch (error) {
      console.error("Failed to copy link:", error);
    }
  };

  const getRiskClass = (level: string) => {
    return `risk-${level.toLowerCase()}`;
  };

  /*
   * ---------------------------------------------------------
   * SECURE SHARE VIEW
   * ---------------------------------------------------------
   */
  if (window.location.search.includes("share=")) {
    return (
      <main className="app">
        <div className="container">

          <header className="header">
            <p className="eyebrow">
              ADAPTIVE SECRET LIFECYCLE
            </p>

            <h1>Secure Share</h1>

            <p className="subtitle">
              Encrypted information is decrypted locally in your
              browser.
            </p>
          </header>

          <section className="card result-card">

            <div className="card-header">
              <h2>Secret Received</h2>

              <span className="status">
                SECURE
              </span>
            </div>

            {isLoadingShare && (
              <div className="encryption-success">
                <div className="success-header">
                  <span>🔐</span>
                  <strong>
                    Opening secure share...
                  </strong>
                </div>

                <p>
                  Retrieving encrypted data and decrypting it
                  locally.
                </p>
              </div>
            )}

            {shareError && (
              <div className="encryption-error">
                <strong>
                  This secure share could not be opened.
                </strong>

                <p>
                  {shareError}
                </p>
              </div>
            )}

            {receivedSecret && !shareError && (
              <>
                <div className="encryption-success">
                  <div className="success-header">
                    <span>✓</span>

                    <strong>
                      Secret decrypted locally
                    </strong>
                  </div>

                  <p>
                    The server provided encrypted data. The
                    encryption key remained in this browser.
                  </p>
                </div>

                <div className="analysis-section">
                  <h3>
                    Decrypted Information
                    <span className="status">
                      LOCAL
                    </span>
                  </h3>

                  <pre className="decrypted-secret">
                    {receivedSecret}
                  </pre>
                </div>

                <div className="share-section">
                  <div>
                    <h3>
                      🔒 Zero-knowledge decryption
                    </h3>

                    <p>
                      Decryption happened locally in your
                      browser. The server never received the
                      encryption key.
                    </p>
                  </div>
                </div>

                {shareExpiresAt && (
                  <div className="share-metadata">
                    <span>
                      Expires:{" "}
                      {new Date(
                        shareExpiresAt,
                      ).toLocaleString()}
                    </span>

                    {shareMaxViews && (
                      <span>
                        Maximum views: {shareMaxViews}
                      </span>
                    )}
                  </div>
                )}
              </>
            )}

          </section>
        </div>
      </main>
    );
  }

  /*
   * ---------------------------------------------------------
   * CREATE SECRET VIEW
   * ---------------------------------------------------------
   */

  return (
    <main className="app">
      <div className="container">

        <header className="header">
          <p className="eyebrow">
            ADAPTIVE SECRET LIFECYCLE
          </p>

          <h1>
            Securely share sensitive information.
          </h1>

          <p className="subtitle">
            Analyze your content, protect it locally, and
            prepare it for secure sharing.
          </p>
        </header>

        <section className="card">

          <div className="card-header">
            <h2>Create Secure Secret</h2>

            <span className="status">
              LOCAL ANALYSIS
            </span>
          </div>

          <label htmlFor="secret-input">
            Secret or sensitive content
          </label>

          <textarea
            id="secret-input"
            value={secret}
            onChange={(event) => {
              setSecret(event.target.value);
              setAnalysis(null);
              setEncryptedData(null);
              setEncryptionError("");
              setShareUrl(null);
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

              <span
                className={`risk-badge ${getRiskClass(
                  analysis.level,
                )}`}
              >
                {analysis.level}
              </span>
            </div>

            <div className="placeholder-grid">

              <div>
                <span>
                  Detected Secrets
                </span>

                <strong>
                  {analysis.detectedSecrets.length}
                </strong>
              </div>

              <div>
                <span>
                  Risk Score
                </span>

                <strong>
                  {analysis.score}/100
                </strong>
              </div>

              <div>
                <span>
                  Risk Level
                </span>

                <strong>
                  {analysis.level}
                </strong>
              </div>

            </div>

            <div className="analysis-section">

              <h3>
                Detected Content
              </h3>

              {analysis.detectedSecrets.length === 0 ? (
                <p className="result-placeholder">
                  No obvious sensitive secrets were
                  detected.
                </p>
              ) : (
                <div className="detected-list">

                  {analysis.detectedSecrets.map(
                    (secretItem, index) => (
                      <div
                        className="detected-item"
                        key={`${secretItem.type}-${index}`}
                      >

                        <div>
                          <strong>
                            {secretItem.label}
                          </strong>

                          <span>
                            Confidence:{" "}
                            {Math.round(
                              secretItem.confidence * 100,
                            )}
                            %
                          </span>
                        </div>

                        <span
                          className={`severity severity-${secretItem.severity}`}
                        >
                          {secretItem.severity.toUpperCase()}
                        </span>

                      </div>
                    ),
                  )}

                </div>
              )}

            </div>

            <div className="analysis-section">

              <h3>
                Security Recommendations
              </h3>

              <div className="recommendations">

                {analysis.recommendations.map(
                  (recommendation) => (
                    <div
                      className="recommendation"
                      key={recommendation}
                    >
                      <span>✓</span>

                      <p>
                        {recommendation}
                      </p>
                    </div>
                  ),
                )}

              </div>

            </div>

            <div className="share-section">

              <div>
                <h3>
                  Ready to Share?
                </h3>

                <p>
                  Your secret will be encrypted locally
                  before the encrypted data is sent to the
                  sharing service.
                </p>
              </div>

              <button
                type="button"
                className="share-button"
                onClick={
                  handleCreateSecureShare
                }
                disabled={isEncrypting}
              >
                {isEncrypting
                  ? "Creating Secure Share..."
                  : "Create Secure Share"}
              </button>

            </div>

            {encryptionError && (
              <div className="encryption-error">
                {encryptionError}
              </div>
            )}

            {encryptedData && (
              <div className="encryption-success">

                <div className="success-header">

                  <span>✓</span>

                  <strong>
                    Secret encrypted successfully
                  </strong>

                </div>

                <p>
                  AES-256-GCM encryption completed
                  locally.
                </p>

                <div className="encrypted-preview">

                  <span>
                    Ciphertext
                  </span>

                  <code>
                    {encryptedData.ciphertext.slice(
                      0,
                      80,
                    )}
                    ...
                  </code>

                </div>

              </div>
            )}

            {shareUrl && (
              <div className="share-created">

                <h2>
                  Secure Share Created
                </h2>

                <p>
                  Your encrypted secret is ready to
                  share.
                </p>

                <div className="share-status">
                  ACTIVE
                </div>

                <div className="share-link-row">

                  <input
                    type="text"
                    value={shareUrl}
                    readOnly
                  />

                  <button
                    type="button"
                    onClick={handleCopyLink}
                  >
                    Copy Link
                  </button>

                </div>

                <div className="share-details">

                  <span>
                    Encryption{" "}
                    <strong>
                      AES-256-GCM
                    </strong>
                  </span>

                  {shareExpiresAt && (
                    <span>
                      Expires{" "}
                      <strong>
                        {new Date(
                          shareExpiresAt,
                        ).toLocaleString()}
                      </strong>
                    </span>
                  )}

                  {shareMaxViews && (
                    <span>
                      Maximum Views{" "}
                      <strong>
                        {shareMaxViews}
                      </strong>
                    </span>
                  )}

                </div>

                <p className="key-warning">
                  🔒 The encryption key is kept in
                  the URL fragment and is not sent to
                  the backend.
                </p>

              </div>
            )}

          </section>
        )}

      </div>
    </main>
  );
}

export default App;