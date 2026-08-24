import { useEffect, useRef, useState } from "react";
import "./App.css";

import { detectSecrets } from "./services/secretDetector";
import { analyzeRisk } from "./services/riskEngine";

import {
  encryptSecret,
  createShare,
  getShare,
  decryptSecret,
  burnShare,
} from "./services/encryption";

import type { RiskAnalysis } from "./services/riskEngine";
import type { DetectedSecret } from "./services/secretDetector";

type EncryptedData = {
  ciphertext: string;
  iv: string;
  key: string;
};

type ShareInfo = {
  id: string;
  expiresAt: string;
  maxViews: number;
  burnToken: string;
};

function renderDetectedContent(
  text: string,
  detectedSecrets: DetectedSecret[],
) {
  if (detectedSecrets.length === 0 || !text) {
    return <span>{text}</span>;
  }

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
    .sort((a, b) => a.start - b.start);

  const safeRanges: typeof ranges = [];

  for (const range of ranges) {
    const previous =
      safeRanges[safeRanges.length - 1];

    if (previous && range.start < previous.end) {
      continue;
    }

    safeRanges.push(range);
  }

  const elements: React.ReactNode[] = [];

  let cursor = 0;

  safeRanges.forEach((range, index) => {
    if (cursor < range.start) {
      elements.push(
        <span key={`text-${index}`}>
          {text.slice(cursor, range.start)}
        </span>,
      );
    }

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
              range.end - range.start,
            ),
          ),
        )}
      </span>,
    );

    cursor = range.end;
  });

  if (cursor < text.length) {
    elements.push(
      <span key="remaining-text">
        {text.slice(cursor)}
      </span>,
    );
  }

  return elements;
}

function formatDuration(
  totalMinutes: number,
): string {
  const total = Math.max(
    0,
    Math.floor(totalMinutes),
  );

  const days = Math.floor(
    total / 1440,
  );

  const hours = Math.floor(
    (total % 1440) / 60,
  );

  const minutes = total % 60;

  const parts: string[] = [];

  if (days > 0) {
    parts.push(
      `${days} day${days !== 1 ? "s" : ""}`,
    );
  }

  if (hours > 0) {
    parts.push(
      `${hours} hour${hours !== 1 ? "s" : ""}`,
    );
  }

  if (
    minutes > 0 ||
    parts.length === 0
  ) {
    parts.push(
      `${minutes} minute${
        minutes !== 1 ? "s" : ""
      }`,
    );
  }

  return parts.join(" · ");
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

  const shareId = isSharePage
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
   * KILL SWITCH STATE
   * ---------------------------------------------------------
   */

  const [
    isRevoking,
    setIsRevoking,
  ] = useState(false);

  const [
    isRevoked,
    setIsRevoked,
  ] = useState(false);

  const [
    revokeError,
    setRevokeError,
  ] = useState("");

  /*
   * ---------------------------------------------------------
   * FULLY CUSTOMIZABLE SHARE CONTROLS
   * ---------------------------------------------------------
   */

  const [
    expiryDays,
    setExpiryDays,
  ] = useState(0);

  const [
    expiryHours,
    setExpiryHours,
  ] = useState(0);

  const [
    expiryMinutes,
    setExpiryMinutes,
  ] = useState(10);

  const [
    maxViews,
    setMaxViews,
  ] = useState(1);

  const expiresInMinutes =
    expiryDays * 24 * 60 +
    expiryHours * 60 +
    expiryMinutes;

  /*
   * ---------------------------------------------------------
   * RISK RECOMMENDATIONS
   * ---------------------------------------------------------
   */

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
    if (!isSharePage || !shareId) {
      return;
    }

    if (hasLoadedShare.current) {
      return;
    }

    hasLoadedShare.current = true;

    const loadShare =
      async () => {
        setIsReceiving(true);
        setReceiveError("");

        try {
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
           * Backend checks:
           * - Does share exist?
           * - Is it revoked?
           * - Has it expired?
           * - Has view limit been reached?
           */

          const share =
            await getShare(shareId);

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
  }, [isSharePage, shareId]);

  /*
   * ---------------------------------------------------------
   * ANALYZE
   * ---------------------------------------------------------
   */

  const handleAnalyze = () => {
    const detectedSecrets =
      detectSecrets(secret);

    const result =
      analyzeRisk(
        detectedSecrets,
      );

    setAnalysis(result);

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
      recommendations[result.level];

    setRecommendedExpiry(
      recommended.expires,
    );

    setRecommendedViews(
      recommended.views,
    );

    setEncryptedData(null);
    setShareInfo(null);

    setEncryptionError("");

    /*
     * Reset kill-switch state
     * whenever a new secret is analyzed.
     */

    setIsRevoking(false);
    setIsRevoked(false);
    setRevokeError("");
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

      if (expiresInMinutes <= 0) {
        setEncryptionError(
          "Expiration time must be greater than 0 minutes.",
        );
        return;
      }

      if (
        !Number.isInteger(maxViews) ||
        maxViews <= 0
      ) {
        setEncryptionError(
          "Maximum views must be at least 1.",
        );
        return;
      }

      setIsEncrypting(true);
      setEncryptionError("");

      setEncryptedData(null);
      setShareInfo(null);

      /*
       * Reset kill switch for new share.
       */

      setIsRevoking(false);
      setIsRevoked(false);
      setRevokeError("");

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
         * Send encrypted data only.
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
   * KILL SWITCH / REVOKE SHARE
   * ---------------------------------------------------------
   */

  const handleRevokeShare =
    async () => {
      if (
        !shareInfo ||
        isRevoking ||
        isRevoked
      ) {
        return;
      }

      const confirmed =
        window.confirm(
          "Revoke this share permanently?\n\nAnyone with the link will no longer be able to access the secret.",
        );

      if (!confirmed) {
        return;
      }

      setIsRevoking(true);
      setRevokeError("");

      try {
        /*
         * Send revocation request
         * to backend.
         *
         * Backend changes:
         *
         * burned = true
         */

        await burnShare(
          shareInfo.id,
          shareInfo.burnToken,
        );

        /*
         * Mark locally as revoked.
         */

        setIsRevoked(true);

        /*
         * Remove the secret/link
         * from the creator UI.
         *
         * The backend is already
         * enforcing the revocation.
         */

        setEncryptedData(null);
      } catch (error) {
        console.error(
          "Failed to revoke share:",
          error,
        );

        if (
          error instanceof Error
        ) {
          setRevokeError(
            error.message,
          );
        } else {
          setRevokeError(
            "Failed to revoke secure share.",
          );
        }
      } finally {
        setIsRevoking(false);
      }
    };

  /*
   * ---------------------------------------------------------
   * SHARE URL
   * ---------------------------------------------------------
   */

  const getShareUrl = () => {
    if (
      !shareInfo ||
      !encryptedData ||
      isRevoked
    ) {
      return "";
    }

    /*
     * Key is stored in URL fragment.
     *
     * The fragment is never sent
     * to the backend.
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
    (level: string) =>
      `risk-${level.toLowerCase()}`;

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
                          ).toLocaleString()}
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

              setIsRevoked(false);
              setIsRevoking(false);
              setRevokeError("");
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
                Choose exactly how long
                this secret should remain
                available and how many
                times it can be viewed.
              </p>

              <div className="share-controls">

                <div className="control-group">

                  <label>
                    Expires after
                  </label>

                  <div
                    style={{
                      display: "flex",
                      gap: "8px",
                      alignItems: "center",
                      flexWrap: "wrap",
                    }}
                  >

                    <div>

                      <input
                        type="number"
                        min="0"
                        step="1"
                        value={
                          expiryDays
                        }
                        onChange={(event) =>
                          setExpiryDays(
                            Math.max(
                              0,
                              Number(
                                event.target.value,
                              ) || 0,
                            ),
                          )
                        }
                        aria-label="Expiry days"
                      />

                      <span>
                        {" "}days
                      </span>

                    </div>

                    <div>

                      <input
                        type="number"
                        min="0"
                        step="1"
                        value={
                          expiryHours
                        }
                        onChange={(event) =>
                          setExpiryHours(
                            Math.max(
                              0,
                              Number(
                                event.target.value,
                              ) || 0,
                            ),
                          )
                        }
                        aria-label="Expiry hours"
                      />

                      <span>
                        {" "}hours
                      </span>

                    </div>

                    <div>

                      <input
                        type="number"
                        min="0"
                        step="1"
                        value={
                          expiryMinutes
                        }
                        onChange={(event) =>
                          setExpiryMinutes(
                            Math.max(
                              0,
                              Number(
                                event.target.value,
                              ) || 0,
                            ),
                          )
                        }
                        aria-label="Expiry minutes"
                      />

                      <span>
                        {" "}minutes
                      </span>

                    </div>

                  </div>

                </div>

                <div className="control-group">

                  <label htmlFor="views-input">
                    Maximum views
                  </label>

                  <div>

                    <input
                      id="views-input"
                      type="number"
                      min="1"
                      step="1"
                      value={
                        maxViews
                      }
                      onChange={(event) =>
                        setMaxViews(
                          Math.max(
                            1,
                            Number(
                              event.target.value,
                            ) || 1,
                          ),
                        )
                      }
                    />

                    <span>
                      {" "}views
                    </span>

                  </div>

                </div>

              </div>

              <div className="security-note">

                🔐 Your policy:
                {" "}

                <strong>
                  {formatDuration(
                    expiresInMinutes,
                  )}
                </strong>

                {" · "}

                <strong>
                  {maxViews} view
                  {maxViews !== 1
                    ? "s"
                    : ""}
                </strong>

              </div>

              <div className="security-note">

                💡 Recommended for{" "}
                <strong>
                  {analysis.level}
                </strong>
                :{" "}

                <strong>
                  {formatDuration(
                    recommendedExpiry,
                  )}
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
                      {formatDuration(
                        expiresInMinutes,
                      )}
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
                  isEncrypting ||
                  expiresInMinutes <= 0 ||
                  maxViews <= 0
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

            {encryptedData &&
              !isRevoked && (
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
                GENERATED SHARE + KILL SWITCH
               ================================================= */}

            {shareInfo && (
              <div className="analysis-section">

                {isRevoked ? (

                  /*
                   * =============================================
                   * REVOKED STATE
                   * =============================================
                   */

                  <div className="encryption-error">

                    <div className="success-header">

                      <span>
                        ✓
                      </span>

                      <strong>
                        Share Revoked
                      </strong>

                    </div>

                    <p>
                      This secure share has
                      been permanently
                      disabled.
                    </p>

                    <p>
                      Anyone using the
                      original link will now
                      receive a "Share has
                      been burned" response
                      from the backend.
                    </p>

                    <div className="security-note">

                      🔴 Kill switch activated

                    </div>

                  </div>

                ) : (

                  /*
                   * =============================================
                   * ACTIVE SHARE
                   * =============================================
                   */

                  <>

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
                            {formatDuration(
                              expiresInMinutes,
                            )}
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

                      {/* =========================================
                          KILL SWITCH
                         ========================================= */}

                      <div
                        style={{
                          marginTop:
                            "24px",
                          paddingTop:
                            "20px",
                          borderTop:
                            "1px solid rgba(255,255,255,0.1)",
                        }}
                      >

                        <div
                          style={{
                            marginBottom:
                              "12px",
                          }}
                        >

                          <strong>
                            Emergency Access Control
                          </strong>

                          <p
                            className="result-placeholder"
                            style={{
                              marginTop:
                                "6px",
                            }}
                          >
                            Revoke this share
                            immediately. The
                            original link will
                            stop working even
                            before its expiration
                            time or view limit is
                            reached.
                          </p>

                        </div>

                        <button
                          type="button"
                          onClick={
                            handleRevokeShare
                          }
                          disabled={
                            isRevoking
                          }
                          style={{
                            background:
                              "#b42318",
                            color:
                              "white",
                            border:
                              "none",
                            padding:
                              "12px 18px",
                            borderRadius:
                              "8px",
                            cursor:
                              isRevoking
                                ? "not-allowed"
                                : "pointer",
                            fontWeight:
                              600,
                            opacity:
                              isRevoking
                                ? 0.7
                                : 1,
                          }}
                        >
                          {isRevoking
                            ? "Revoking Share..."
                            : "🔴 Revoke Share"}
                        </button>

                        {revokeError && (
                          <div
                            className="encryption-error"
                            style={{
                              marginTop:
                                "12px",
                            }}
                          >
                            {revokeError}
                          </div>
                        )}

                      </div>

                    </div>

                  </>

                )}

              </div>
            )}

          </section>
        )}

      </div>

    </main>
  );
}

export default App;