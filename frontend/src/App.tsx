import { useEffect, useRef, useState } from "react";
import "./App.css";

import {
  detectSecrets,
} from "./services/secretDetector";

import {
  analyzeRisk,
} from "./services/riskEngine";

import {
  encryptSecret,
  createShare,
  getShare,
  decryptSecret,
} from "./services/encryption";

import type {
  RiskAnalysis,
} from "./services/riskEngine";

import type {
  DetectedSecret,
} from "./services/secretDetector";

type EncryptedData = {
  ciphertext: string;
  iv: string;
  key: string;
};

type ShareInfo = {
  id: string;
  expiresAt: string;
  maxViews: number;
};

/*
 * ---------------------------------------------------------
 * DETECTED SECRET HIGHLIGHT
 * ---------------------------------------------------------
 */

function renderDetectedContent(
  text: string,
  detectedSecrets: DetectedSecret[],
) {
  if (
    detectedSecrets.length === 0 ||
    !text
  ) {
    return (
      <span>
        {text}
      </span>
    );
  }

  /*
   * Create ranges from the detected secrets.
   */

  const ranges = detectedSecrets
    .map((secret) => ({
      start: secret.start,
      end: secret.end,
      label: secret.label,
    }))
    .filter(
      (range) =>
        range.start >= 0 &&
        range.end <= text.length &&
        range.start < range.end,
    )
    .sort(
      (a, b) =>
        a.start - b.start,
    );

  /*
   * Prevent overlapping highlights.
   */

  const safeRanges: typeof ranges = [];

  for (const range of ranges) {
    const previous =
      safeRanges[
        safeRanges.length - 1
      ];

    if (
      previous &&
      range.start < previous.end
    ) {
      continue;
    }

    safeRanges.push(range);
  }

  const elements: React.ReactNode[] = [];

  let cursor = 0;

  safeRanges.forEach(
    (range, index) => {
      /*
       * Normal text before the secret.
       */

      if (cursor < range.start) {
        elements.push(
          <span
            key={`text-${index}`}
          >
            {text.slice(
              cursor,
              range.start,
            )}
          </span>,
        );
      }

      /*
       * Masked secret.
       */

      elements.push(
        <span
          key={`secret-${index}`}
          className="detected-highlight"
          title={`${range.label} detected`}
        >
          {"█".repeat(
            Math.max(
              6,
              Math.min(
                20,
                range.end -
                  range.start,
              ),
            ),
          )}
        </span>,
      );

      cursor = range.end;
    },
  );

  /*
   * Remaining text.
   */

  if (cursor < text.length) {
    elements.push(
      <span key="remaining-text">
        {text.slice(cursor)}
      </span>,
    );
  }

  return elements;
}

function App() {
  /*
   * ---------------------------------------------------------
   * ROUTING
   * ---------------------------------------------------------
   */

  const path =
    window.location.pathname;

  const isSharePage =
    path.startsWith("/share/");

  const shareId =
    isSharePage
      ? path.split("/share/")[1]
      : null;

  /*
   * ---------------------------------------------------------
   * CREATE PAGE STATE
   * ---------------------------------------------------------
   */

  const [secret, setSecret] =
    useState("");

  const [analysis, setAnalysis] =
    useState<RiskAnalysis | null>(
      null,
    );

  const [
    encryptedData,
    setEncryptedData,
  ] = useState<EncryptedData | null>(
    null,
  );

  const [shareInfo, setShareInfo] =
    useState<ShareInfo | null>(
      null,
    );

  const [
    isEncrypting,
    setIsEncrypting,
  ] = useState(false);

  const [
    encryptionError,
    setEncryptionError,
  ] = useState("");

  /*
   * ---------------------------------------------------------
   * SHARE CONTROLS
   * ---------------------------------------------------------
   */

  const [
    expiresInMinutes,
    setExpiresInMinutes,
  ] = useState(10);

  const [
    maxViews,
    setMaxViews,
  ] = useState(1);

  const [
    recommendedExpiry,
    setRecommendedExpiry,
  ] = useState(10);

  const [
    recommendedViews,
    setRecommendedViews,
  ] = useState(1);

  /*
   * ---------------------------------------------------------
   * RECEIVE PAGE STATE
   * ---------------------------------------------------------
   */

  const [
    receivedSecret,
    setReceivedSecret,
  ] = useState("");

  const [
    receiveError,
    setReceiveError,
  ] = useState("");

  const [
    isReceiving,
    setIsReceiving,
  ] = useState(false);

  const [
    receivedShareInfo,
    setReceivedShareInfo,
  ] = useState<{
    expiresAt: string;
    maxViews: number;
    views: number;
    riskLevel: string;
  } | null>(null);

  const hasLoadedShare =
    useRef(false);

  /*
   * ---------------------------------------------------------
   * LOAD SHARED SECRET
   * ---------------------------------------------------------
   */

  useEffect(() => {
    if (
      !isSharePage ||
      !shareId
    ) {
      return;
    }

    if (
      hasLoadedShare.current
    ) {
      return;
    }

    hasLoadedShare.current =
      true;

    const loadShare =
      async () => {
        setIsReceiving(true);
        setReceiveError("");

        try {
          /*
           * Encryption key is stored in the
           * URL fragment.
           *
           * Example:
           *
           * /share/abc123#key=ABC...
           *
           * The fragment is not sent to
           * the backend.
           */

          const hash =
            window.location.hash;

          if (!hash) {
            throw new Error(
              "Encryption key is missing from the share link.",
            );
          }

          const hashParams =
            new URLSearchParams(
              hash.substring(1),
            );

          const key =
            hashParams.get("key");

          if (!key) {
            throw new Error(
              "Encryption key is missing from the share link.",
            );
          }

          /*
           * Retrieve encrypted data.
           */

          const share =
            await getShare(
              shareId,
            );

          /*
           * Decrypt locally.
           */

          const plaintext =
            await decryptSecret({
              ciphertext:
                share.ciphertext,
              iv: share.iv,
              key,
            });

          setReceivedSecret(
            plaintext,
          );

          setReceivedShareInfo({
            expiresAt:
              share.expiresAt,
            maxViews:
              share.maxViews,
            views:
              share.views,
            riskLevel:
              share.riskLevel,
          });
        } catch (error) {
          console.error(
            "Failed to open secure share:",
            error,
          );

          if (
            error instanceof Error
          ) {
            setReceiveError(
              error.message,
            );
          } else {
            setReceiveError(
              "This secure share could not be opened.",
            );
          }
        } finally {
          setIsReceiving(false);
        }
      };

    loadShare();
  }, [
    isSharePage,
    shareId,
  ]);

  /*
   * ---------------------------------------------------------
   * ANALYZE
   * ---------------------------------------------------------
   */

  const handleAnalyze =
    () => {
      const detectedSecrets =
        detectSecrets(
          secret,
        );

      const result =
        analyzeRisk(
          detectedSecrets,
        );

      setAnalysis(result);

      /*
       * Risk-based recommendations.
       */

      const recommendations = {
        LOW: {
          expires: 30,
          views: 5,
        },

        MEDIUM: {
          expires: 15,
          views: 3,
        },

        HIGH: {
          expires: 10,
          views: 1,
        },

        CRITICAL: {
          expires: 5,
          views: 1,
        },
      };

      const recommended =
        recommendations[
          result.level
        ];

      setRecommendedExpiry(
        recommended.expires,
      );

      setRecommendedViews(
        recommended.views,
      );

      /*
       * Start with recommended values.
       */

      setExpiresInMinutes(
        recommended.expires,
      );

      setMaxViews(
        recommended.views,
      );

      setEncryptedData(null);
      setShareInfo(null);
      setEncryptionError("");
    };

  /*
   * ---------------------------------------------------------
   * CREATE SHARE
   * ---------------------------------------------------------
   */

  const handleCreateSecureShare =
    async () => {
      if (!secret.trim()) {
        return;
      }

      setIsEncrypting(true);
      setEncryptionError("");
      setEncryptedData(null);
      setShareInfo(null);

      try {
        /*
         * Encrypt locally.
         */

        const encrypted =
          await encryptSecret(
            secret,
          );

        setEncryptedData(
          encrypted,
        );

        /*
         * Send encrypted data to backend.
         *
         * Encryption key is NOT sent.
         */

        const share =
          await createShare(
            encrypted,
            {
              expiresInMinutes,
              maxViews,
              riskLevel:
                analysis?.level ??
                "LOW",
            },
          );

        setShareInfo(
          share,
        );
      } catch (error) {
        console.error(
          "Secure share creation failed:",
          error,
        );

        if (
          error instanceof Error
        ) {
          setEncryptionError(
            error.message,
          );
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
   * ---------------------------------------------------------
   * SHARE URL
   * ---------------------------------------------------------
   */

  const getShareUrl =
    () => {
      if (
        !shareInfo ||
        !encryptedData
      ) {
        return "";
      }

      /*
       * IMPORTANT:
       *
       * The key is placed after #.
       *
       * Therefore it stays in the browser
       * and is not sent to the backend.
       */

      return `${window.location.origin}/share/${shareInfo.id}#key=${encodeURIComponent(
        encryptedData.key,
      )}`;
    };

  /*
   * ---------------------------------------------------------
   * COPY LINK
   * ---------------------------------------------------------
   */

  const handleCopyLink =
    async () => {
      const url =
        getShareUrl();

      if (!url) {
        return;
      }

      try {
        await navigator.clipboard.writeText(
          url,
        );

        alert(
          "Secure share link copied.",
        );
      } catch (error) {
        console.error(
          "Failed to copy link:",
          error,
        );
      }
    };

  /*
   * ---------------------------------------------------------
   * OVERRIDE CHECK
   * ---------------------------------------------------------
   */

  const isOverridingRecommendation =
    expiresInMinutes !==
      recommendedExpiry ||
    maxViews !==
      recommendedViews;

  /*
   * ---------------------------------------------------------
   * RISK CSS CLASS
   * ---------------------------------------------------------
   */

  const getRiskClass =
    (level: string) => {
      return `risk-${level.toLowerCase()}`;
    };

  /*
   * =========================================================
   * SHARE PAGE
   * =========================================================
   */

  if (isSharePage) {
    return (
      <main className="app">

        <div className="container">

          <header className="header">

            <p className="eyebrow">
              ADAPTIVE SECRET LIFECYCLE
            </p>

            <h1>
              Secure Share
            </h1>

            <p className="subtitle">
              Encrypted information is
              decrypted locally in your
              browser.
            </p>

          </header>

          <section className="card result-card">

            <div className="card-header">

              <h2>
                Secret Received
              </h2>

              <span className="status">
                SECURE
              </span>

            </div>

            {isReceiving && (
              <div className="analysis-section">

                <h3>
                  Opening secure share...
                </h3>

                <p className="result-placeholder">
                  Retrieving encrypted
                  data and decrypting it
                  locally.
                </p>

              </div>
            )}

            {receiveError && (
              <div className="encryption-error">

                <strong>
                  This secure share
                  could not be opened.
                </strong>

                <p>
                  {receiveError}
                </p>

              </div>
            )}

            {!isReceiving &&
              !receiveError &&
              receivedSecret && (
                <>

                  <div className="encryption-success">

                    <div className="success-header">

                      <span>
                        ✓
                      </span>

                      <strong>
                        Secret decrypted locally
                      </strong>

                    </div>

                    <p>
                      The server provided
                      encrypted data. The
                      encryption key remained
                      in this browser.
                    </p>

                  </div>

                  <div className="analysis-section">

                    <h3>
                      Decrypted Information
                    </h3>

                    <pre className="secret-output">
                      {receivedSecret}
                    </pre>

                  </div>

                  <div className="analysis-section">

                    <h3>
                      🔐 Zero-knowledge
                      decryption
                    </h3>

                    <p className="result-placeholder">
                      Decryption happened
                      locally in your browser.
                      The server never received
                      the encryption key.
                    </p>

                  </div>

                  {receivedShareInfo && (
                    <div className="placeholder-grid">

                      <div>
                        <span>
                          Views Used
                        </span>

                        <strong>
                          {
                            receivedShareInfo.views
                          }
                          /
                          {
                            receivedShareInfo.maxViews
                          }
                        </strong>
                      </div>

                      <div>
                        <span>
                          Risk Level
                        </span>

                        <strong>
                          {
                            receivedShareInfo.riskLevel
                          }
                        </strong>
                      </div>

                      <div>
                        <span>
                          Expires
                        </span>

                        <strong>
                          {new Date(
                            receivedShareInfo.expiresAt,
                          ).toLocaleTimeString()}
                        </strong>
                      </div>

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
   * =========================================================
   * CREATE PAGE
   * =========================================================
   */

  return (
    <main className="app">

      <div className="container">

        <header className="header">

          <p className="eyebrow">
            ADAPTIVE SECRET LIFECYCLE
          </p>

          <h1>
            Securely share sensitive
            information.
          </h1>

          <p className="subtitle">
            Analyze your content,
            identify sensitive
            information, protect it
            locally, and prepare it
            for secure sharing.
          </p>

        </header>

        <section className="card">

          <div className="card-header">

            <h2>
              Create Secure Secret
            </h2>

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

              setSecret(
                event.target.value,
              );

              setAnalysis(null);
              setEncryptedData(null);
              setShareInfo(null);
              setEncryptionError("");

            }}
            placeholder={`Example:
hello my password is 1234

or:

DB_HOST=production.company.com
DB_USER=admin
DB_PASSWORD=your-password`}
            rows={10}
          />

          <div className="actions">

            <button
              type="button"
              onClick={
                handleAnalyze
              }
              disabled={
                !secret.trim()
              }
            >
              Analyze Secret
            </button>

          </div>

        </section>

        {analysis && (
          <section className="card result-card">

            <div className="card-header">

              <h2>
                Security Analysis
              </h2>

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
                  {
                    analysis
                      .detectedSecrets
                      .length
                  }
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

            {/* =================================================
                DETECTED CONTENT
               ================================================= */}

            <div className="analysis-section">

              <h3>
                Detected Content
              </h3>

              {analysis.detectedSecrets
                .length === 0 ? (

                <p className="result-placeholder">
                  No obvious sensitive
                  secrets were detected.
                </p>

              ) : (

                <>

                  <div className="detected-preview">

                    <div className="detected-preview-header">

                      <span>
                        Sensitive content
                        masked
                      </span>

                      <span className="status">
                        LOCAL
                      </span>

                    </div>

                    <div className="detected-preview-text">
                      {renderDetectedContent(
                        secret,
                        analysis.detectedSecrets,
                      )}
                    </div>

                  </div>

                  <div className="detected-list">

                    {analysis.detectedSecrets.map(
                      (
                        secretItem,
                        index,
                      ) => (

                        <div
                          className="detected-item"
                          key={`${secretItem.type}-${index}`}
                        >

                          <div>

                            <strong>
                              {
                                secretItem.label
                              }
                            </strong>

                            <span>
                              Detected:
                              {" "}
                              <code>
                                {
                                  secretItem.matchedText
                                }
                              </code>
                            </span>

                            <span>
                              Confidence:
                              {" "}
                              {Math.round(
                                secretItem.confidence *
                                  100,
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

                </>

              )}

            </div>

            {/* =================================================
                RECOMMENDATIONS
               ================================================= */}

            <div className="analysis-section">

              <h3>
                Security Recommendations
              </h3>

              <div className="recommendations">

                {analysis.recommendations.map(
                  (
                    recommendation,
                  ) => (

                    <div
                      className="recommendation"
                      key={
                        recommendation
                      }
                    >

                      <span>
                        ✓
                      </span>

                      <p>
                        {recommendation}
                      </p>

                    </div>

                  ),
                )}

              </div>

            </div>

            {/* =================================================
                SHARE CONTROLS
               ================================================= */}

            <div className="analysis-section">

              <div className="card-header">

                <h3>
                  Share Controls
                </h3>

                <span className="status">
                  USER CONTROL
                </span>

              </div>

              <p className="result-placeholder">
                Choose how long this
                secret should remain
                available and how many
                times it can be viewed.
              </p>

              <div className="share-controls">

                <div className="control-group">

                  <label htmlFor="expiry-select">
                    Expires after
                  </label>

                  <select
                    id="expiry-select"
                    value={
                      expiresInMinutes
                    }
                    onChange={(event) =>
                      setExpiresInMinutes(
                        Number(
                          event.target.value,
                        ),
                      )
                    }
                  >

                    <option value={5}>
                      5 minutes
                    </option>

                    <option value={10}>
                      10 minutes
                    </option>

                    <option value={15}>
                      15 minutes
                    </option>

                    <option value={30}>
                      30 minutes
                    </option>

                    <option value={60}>
                      1 hour
                    </option>

                    <option value={1440}>
                      24 hours
                    </option>

                  </select>

                </div>

                <div className="control-group">

                  <label htmlFor="views-select">
                    Maximum views
                  </label>

                  <select
                    id="views-select"
                    value={
                      maxViews
                    }
                    onChange={(event) =>
                      setMaxViews(
                        Number(
                          event.target.value,
                        ),
                      )
                    }
                  >

                    <option value={1}>
                      1 view
                    </option>

                    <option value={2}>
                      2 views
                    </option>

                    <option value={3}>
                      3 views
                    </option>

                    <option value={5}>
                      5 views
                    </option>

                    <option value={10}>
                      10 views
                    </option>

                  </select>

                </div>

              </div>

              <div className="security-note">

                🔐 Recommended for{" "}
                <strong>
                  {analysis.level}
                </strong>
                :{" "}
                <strong>
                  {recommendedExpiry} minutes
                </strong>
                {" · "}
                <strong>
                  {recommendedViews} view
                  {recommendedViews !== 1
                    ? "s"
                    : ""}
                </strong>

              </div>

              {isOverridingRecommendation && (
                <div className="encryption-error">

                  ⚠️ You are overriding
                  the recommended security
                  settings.

                  <p>
                    Your selected settings:
                    {" "}
                    <strong>
                      {
                        expiresInMinutes
                      } minutes
                    </strong>
                    {" · "}
                    <strong>
                      {maxViews} view
                      {maxViews !== 1
                        ? "s"
                        : ""}
                    </strong>
                  </p>

                </div>
              )}

            </div>

            {/* =================================================
                CREATE SHARE
               ================================================= */}

            <div className="share-section">

              <div>

                <h3>
                  Ready to Share?
                </h3>

                <p>
                  Your secret will be
                  encrypted locally
                  before the encrypted
                  data is sent to the
                  sharing service.
                </p>

              </div>

              <button
                type="button"
                className="share-button"
                onClick={
                  handleCreateSecureShare
                }
                disabled={
                  isEncrypting
                }
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

            {/* =================================================
                ENCRYPTION RESULT
               ================================================= */}

            {encryptedData && (
              <div className="encryption-success">

                <div className="success-header">

                  <span>
                    ✓
                  </span>

                  <strong>
                    Secret encrypted
                    successfully
                  </strong>

                </div>

                <p>
                  AES-256-GCM encryption
                  completed locally.
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

            {/* =================================================
                GENERATED SHARE
               ================================================= */}

            {shareInfo &&
              encryptedData && (
                <div className="analysis-section">

                  <h2>
                    Secure Share Created
                  </h2>

                  <p>
                    Your encrypted secret
                    is ready to share.
                  </p>

                  <div className="share-created">

                    <span className="share-status">
                      ACTIVE
                    </span>

                    <div className="share-link-row">

                      <input
                        type="text"
                        readOnly
                        value={
                          getShareUrl()
                        }
                      />

                      <button
                        type="button"
                        onClick={
                          handleCopyLink
                        }
                      >
                        Copy Link
                      </button>

                    </div>

                    <div className="placeholder-grid">

                      <div>
                        <span>
                          Encryption
                        </span>

                        <strong>
                          AES-256-GCM
                        </strong>
                      </div>

                      <div>
                        <span>
                          Expires
                        </span>

                        <strong>
                          {expiresInMinutes <
                          60
                            ? `${expiresInMinutes} minutes`
                            : expiresInMinutes ===
                              60
                            ? "1 hour"
                            : "24 hours"}
                        </strong>
                      </div>

                      <div>
                        <span>
                          Maximum Views
                        </span>

                        <strong>
                          {maxViews}
                        </strong>
                      </div>

                    </div>

                    <p className="security-note">
                      🔐 The encryption key
                      is kept in the URL
                      fragment and is not
                      sent to the backend.
                    </p>

                  </div>

                </div>
              )}

          </section>
        )}

      </div>

    </main>
  );
}

export default App;