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

app.use(
  cors({
    origin: "http://localhost:5174",
  }),
);

app.use(express.json());

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "adaptive-secret-backend",
  });
});

app.post("/api/shares", (req, res) => {
  const {
    ciphertext,
    iv,
    expiresInMinutes = 10,
    maxViews = 1,
    riskLevel = "LOW",
  } = req.body;

  if (!ciphertext || !iv) {
    return res.status(400).json({
      error: "ciphertext and iv are required",
    });
  }

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

  if (
    !Number.isFinite(expiresInMinutes) ||
    expiresInMinutes <= 0
  ) {
    return res.status(400).json({
      error: "Invalid expiration time",
    });
  }

  if (!Number.isInteger(maxViews) || maxViews <= 0) {
    return res.status(400).json({
      error: "Invalid view limit",
    });
  }

  const id = crypto.randomUUID();

  const createdAt = new Date();

  const expiresAt = new Date(
    createdAt.getTime() +
      expiresInMinutes * 60 * 1000,
  );

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

  return res.status(201).json({
    id,
    expiresAt: expiresAt.toISOString(),
    maxViews,
  });
});

app.get("/api/shares/:id", (req, res) => {
  const share = getShare(req.params.id);

  if (!share) {
    return res.status(404).json({
      error: "Share not found",
    });
  }

  if (share.burned) {
    return res.status(410).json({
      error: "Share has been burned",
    });
  }

  if (new Date() >= new Date(share.expiresAt)) {
    return res.status(410).json({
      error: "Share has expired",
    });
  }

  if (share.views >= share.maxViews) {
    return res.status(410).json({
      error: "View limit reached",
    });
  }

  // Count this successful retrieval as a view.
  const updatedShare = updateShare(req.params.id, {
    views: share.views + 1,
  });

  if (!updatedShare) {
    return res.status(404).json({
      error: "Share not found",
    });
  }

  return res.json({
    id: updatedShare.id,
    ciphertext: updatedShare.ciphertext,
    iv: updatedShare.iv,
    expiresAt: updatedShare.expiresAt,
    maxViews: updatedShare.maxViews,
    views: updatedShare.views,
    riskLevel: updatedShare.riskLevel,
  });
});

app.listen(PORT, () => {
  console.log(
    `Adaptive Secret backend running on http://localhost:${PORT}`,
  );
});