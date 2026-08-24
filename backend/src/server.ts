import cors from "cors";
import express from "express";
import crypto from "node:crypto";

import {
  createShare,
  getShare,
  updateShare,
  incrementShareViews,
} from "./store.js";

const app = express();

const PORT = 4000;

// --------------------------------------------------
// CORS
// --------------------------------------------------

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error("Origin not allowed"),
      );
    },
  }),
);

app.use(express.json());


// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "adaptive-secret-backend",
  });
});


// --------------------------------------------------
// CREATE SHARE
// --------------------------------------------------

app.post("/api/shares", (req, res) => {
  const {
    ciphertext,
    iv,
    expiresInSeconds = 600,
    maxViews = 1,
    riskLevel = "LOW",
  } = req.body;

  // ----------------------------------------------
  // Validate encrypted data
  // ----------------------------------------------

  if (!ciphertext || !iv) {
    return res.status(400).json({
      error: "ciphertext and iv are required",
    });
  }

  // ----------------------------------------------
  // Validate risk level
  // ----------------------------------------------

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

  // ----------------------------------------------
  // Validate exact expiration
  // ----------------------------------------------

  if (
    !Number.isInteger(expiresInSeconds) ||
    expiresInSeconds <= 0
  ) {
    return res.status(400).json({
      error:
        "Expiration must be a positive number of seconds",
    });
  }

  // Maximum allowed lifetime: 365 days

  const MAX_EXPIRATION_SECONDS =
    365 * 24 * 60 * 60;

  if (
    expiresInSeconds >
    MAX_EXPIRATION_SECONDS
  ) {
    return res.status(400).json({
      error:
        "Expiration cannot exceed 365 days",
    });
  }

  // ----------------------------------------------
  // Validate view count
  // ----------------------------------------------

  if (
    !Number.isInteger(maxViews) ||
    maxViews <= 0
  ) {
    return res.status(400).json({
      error:
        "Maximum views must be a positive integer",
    });
  }

  if (maxViews > 10000) {
    return res.status(400).json({
      error:
        "Maximum views cannot exceed 10,000",
    });
  }

  // ----------------------------------------------
  // Generate IDs
  // ----------------------------------------------

  const id = crypto.randomUUID();

  /*
   * Separate authorization token for the
   * creator's kill switch.
   *
   * This token is NEVER included in the
   * recipient's share URL.
   */
  const burnToken = crypto
    .randomBytes(32)
    .toString("hex");

  // ----------------------------------------------
  // Calculate expiration
  // ----------------------------------------------

  const createdAt = new Date();

  const expiresAt = new Date(
    createdAt.getTime() +
      expiresInSeconds * 1000,
  );

  // ----------------------------------------------
  // Store share
  // ----------------------------------------------

  createShare({
    id,

    ciphertext,
    iv,

    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),

    maxViews,
    views: 0,

    burned: false,

    burnToken,

    riskLevel,
  });

  // ----------------------------------------------
  // Return creator information
  // ----------------------------------------------

  return res.status(201).json({
    id,

    expiresAt:
      expiresAt.toISOString(),

    maxViews,

    /*
     * Returned only to the creator.
     */
    burnToken,
  });
});


// --------------------------------------------------
// RETRIEVE SHARE
// --------------------------------------------------

app.get(
  "/api/shares/:id",
  (req, res) => {
    const share = getShare(
      req.params.id,
    );

    // --------------------------------------------
    // Not found
    // --------------------------------------------

    if (!share) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    // --------------------------------------------
    // Kill switch
    // --------------------------------------------

    if (share.burned) {
      return res.status(410).json({
        error:
          "Share has been permanently disabled",
      });
    }

    // --------------------------------------------
    // Expiration
    // --------------------------------------------

    if (
      new Date() >=
      new Date(share.expiresAt)
    ) {
      return res.status(410).json({
        error: "Share has expired",
      });
    }

    // --------------------------------------------
    // View limit
    // --------------------------------------------

    if (
      share.views >=
      share.maxViews
    ) {
      return res.status(410).json({
        error: "View limit reached",
      });
    }

    // --------------------------------------------
    // Count successful retrieval
    // --------------------------------------------

    const updatedShare =
      incrementShareViews(
        req.params.id,
      );

    if (!updatedShare) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    // --------------------------------------------
    // Return encrypted data
    // --------------------------------------------

    return res.json({
      id: updatedShare.id,

      ciphertext:
        updatedShare.ciphertext,

      iv: updatedShare.iv,

      expiresAt:
        updatedShare.expiresAt,

      maxViews:
        updatedShare.maxViews,

      views:
        updatedShare.views,

      riskLevel:
        updatedShare.riskLevel,
    });
  },
);


// --------------------------------------------------
// KILL SWITCH
// --------------------------------------------------

app.post(
  "/api/shares/:id/burn",
  (req, res) => {
    const share = getShare(
      req.params.id,
    );

    // --------------------------------------------
    // Not found
    // --------------------------------------------

    if (!share) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    // --------------------------------------------
    // Already burned
    // --------------------------------------------

    if (share.burned) {
      return res.status(410).json({
        error:
          "Share has already been disabled",
      });
    }

    // --------------------------------------------
    // Authorization
    // --------------------------------------------

    const { burnToken } =
      req.body;

    if (!burnToken) {
      return res.status(401).json({
        error:
          "Kill switch authorization required",
      });
    }

    if (
      burnToken !==
      share.burnToken
    ) {
      return res.status(403).json({
        error:
          "Invalid kill switch authorization",
      });
    }

    // --------------------------------------------
    // Disable share
    // --------------------------------------------

    const updatedShare =
      updateShare(
        req.params.id,
        {
          burned: true,
        },
      );

    if (!updatedShare) {
      return res.status(404).json({
        error: "Share not found",
      });
    }

    return res.json({
      id: updatedShare.id,

      status: "burned",

      message:
        "Share has been permanently disabled.",
    });
  },
);


// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(
  PORT,
  () => {
    console.log(
      `Adaptive Secret backend running on http://localhost:${PORT}`,
    );
  },
);