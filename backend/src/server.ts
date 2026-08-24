import cors from "cors";
import express from "express";
import crypto from "node:crypto";
import {
  createShare,
  getShare,
  updateShare,
} from "./store.js";

const app = express();

const PORT = 4000;

/*
 * Allow the frontend during local development.
 *
 * Vite can run on either 5173 or 5174 depending on
 * what port is available.
 */
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174",
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests that don't have an Origin header
      // (for example direct browser/API testing).
      if (!origin) {
        callback(null, true);
        return;
      }

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error(`CORS blocked origin: ${origin}`));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  }),
);

app.use(express.json());

/*
 * Simple request logger.
 *
 * This lets us see in the backend terminal when
 * the frontend actually reaches the backend.
 */
app.use((req, _res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`,
  );

  next();
});

/*
 * Health check
 */
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "adaptive-secret-backend",
  });
});

/*
 * Create a secure share
 *
 * The backend receives:
 * - ciphertext
 * - IV
 * - expiration
 * - maximum views
 * - risk level
 *
 * IMPORTANT:
 * The encryption key is NEVER sent to the backend.
 */
app.post("/api/shares", (req, res) => {
  try {
    const {
      ciphertext,
      iv,
      expiresInMinutes = 10,
      maxViews = 1,
      riskLevel = "LOW",
    } = req.body;

    console.log("Creating secure share...");

    /*
     * Validate encrypted data
     */
    if (
      typeof ciphertext !== "string" ||
      !ciphertext.trim() ||
      typeof iv !== "string" ||
      !iv.trim()
    ) {
      return res.status(400).json({
        error: "ciphertext and iv are required",
      });
    }

    /*
     * Validate risk level
     */
    const allowedRiskLevels = [
      "LOW",
      "MEDIUM",
      "HIGH",
      "CRITICAL",
    ] as const;

    if (!allowedRiskLevels.includes(riskLevel)) {
      return res.status(400).json({
        error: "Invalid risk level",
      });
    }

    /*
     * Validate expiration
     */
    if (
      typeof expiresInMinutes !== "number" ||
      !Number.isFinite(expiresInMinutes) ||
      expiresInMinutes <= 0
    ) {
      return res.status(400).json({
        error: "Invalid expiration time",
      });
    }

    /*
     * Validate maximum views
     */
    if (
      typeof maxViews !== "number" ||
      !Number.isInteger(maxViews) ||
      maxViews <= 0
    ) {
      return res.status(400).json({
        error: "Invalid view limit",
      });
    }

    /*
     * Generate unique share ID
     */
    const id = crypto.randomUUID();

    const createdAt = new Date();

    const expiresAt = new Date(
      createdAt.getTime() +
        expiresInMinutes * 60 * 1000,
    );

    /*
     * Store the encrypted payload.
     *
     * Notice that there is NO encryption key here.
     */
    createShare({
      id,
      ciphertext,
      iv,
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      maxViews,
      views: 0,
      burned: false,
      riskLevel,
    });

    console.log(`Share created: ${id}`);

    return res.status(201).json({
      id,
      expiresAt: expiresAt.toISOString(),
      maxViews,
    });
  } catch (error) {
    console.error("Create share error:", error);

    return res.status(500).json({
      error: "Failed to create secure share",
    });
  }
});

/*
 * Retrieve a secure share
 *
 * Every successful retrieval counts as ONE view.
 */
app.get("/api/shares/:id", (req, res) => {
  try {
    const { id } = req.params;

    console.log(`Retrieving share: ${id}`);

    const share = getShare(id);

    /*
     * Share doesn't exist
     */
    if (!share) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    /*
     * Share was manually burned
     */
    if (share.burned) {
      return res.status(410).json({
        error: "Share has been burned",
      });
    }

    /*
     * Share expired
     */
    if (new Date() >= new Date(share.expiresAt)) {
      return res.status(410).json({
        error: "Share has expired",
      });
    }

    /*
     * View limit reached
     */
    if (share.views >= share.maxViews) {
      return res.status(410).json({
        error: "View limit reached",
      });
    }

    /*
     * Count this retrieval as a view.
     */
    const updatedShare = updateShare(id, {
      views: share.views + 1,
    });

    if (!updatedShare) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    console.log(
      `Share ${id} viewed: ${updatedShare.views}/${updatedShare.maxViews}`,
    );

    /*
     * Send ONLY encrypted information.
     *
     * The encryption key is never returned.
     */
    return res.json({
      id: updatedShare.id,
      ciphertext: updatedShare.ciphertext,
      iv: updatedShare.iv,
      expiresAt: updatedShare.expiresAt,
      maxViews: updatedShare.maxViews,
      views: updatedShare.views,
      riskLevel: updatedShare.riskLevel,
    });
  } catch (error) {
    console.error("Get share error:", error);

    return res.status(500).json({
      error: "Failed to retrieve secure share",
    });
  }
});

/*
 * Burn / permanently disable a share
 */
app.post("/api/shares/:id/burn", (req, res) => {
  try {
    const { id } = req.params;

    console.log(`Burning share: ${id}`);

    const share = getShare(id);

    if (!share) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    if (share.burned) {
      return res.status(410).json({
        error: "Share has already been burned",
      });
    }

    const updatedShare = updateShare(id, {
      burned: true,
    });

    if (!updatedShare) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    console.log(`Share burned: ${id}`);

    return res.json({
      id: updatedShare.id,
      status: "burned",
      message: "Share has been permanently disabled.",
    });
  } catch (error) {
    console.error("Burn share error:", error);

    return res.status(500).json({
      error: "Failed to burn secure share",
    });
  }
});

/*
 * Handle unknown API routes
 */
app.use("/api", (_req, res) => {
  res.status(404).json({
    error: "API endpoint not found",
  });
});

/*
 * Start backend
 */
app.listen(PORT, () => {
  console.log("");
  console.log("==========================================");
  console.log(" Adaptive Secret backend");
  console.log("==========================================");
  console.log(` Server: http://localhost:${PORT}`);
  console.log(` Health: http://localhost:${PORT}/api/health`);
  console.log("==========================================");
  console.log("");
});