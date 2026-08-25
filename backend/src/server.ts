import cors from "cors";
import express, {
  type Request,
  type Response,
  type NextFunction,
} from "express";
import crypto from "node:crypto";

import {
  createShare,
  getShare,
  updateShare,
  incrementShareViews,
  getSharesByOwner,

  createUser,
  getUserById,
  getUserByUsername,

  createSession,
  getSession,
  deleteSession,
} from "./store.js";

const app = express();

const PORT = 4000;


// ============================================================
// CORS
// ============================================================

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

      if (
        allowedOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(
        new Error(
          "Origin not allowed",
        ),
      );
    },
  }),
);

app.use(express.json());


// ============================================================
// PASSWORD HASHING
// ============================================================

function hashPassword(
  password: string,
): string {
  const salt =
    crypto.randomBytes(16);

  const hash =
    crypto.pbkdf2Sync(
      password,
      salt,
      100000,
      64,
      "sha512",
    );

  return [
    salt.toString("hex"),
    hash.toString("hex"),
  ].join(":");
}


function verifyPassword(
  password: string,
  storedHash: string,
): boolean {
  const parts =
    storedHash.split(":");

  if (parts.length !== 2) {
    return false;
  }

  const salt =
    Buffer.from(
      parts[0],
      "hex",
    );

  const originalHash =
    Buffer.from(
      parts[1],
      "hex",
    );

  const hash =
    crypto.pbkdf2Sync(
      password,
      salt,
      100000,
      64,
      "sha512",
    );

  if (
    hash.length !==
    originalHash.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    hash,
    originalHash,
  );
}


// ============================================================
// SESSION HELPERS
// ============================================================

const SESSION_DURATION_DAYS = 7;


function createAuthSession(
  userId: string,
): string {
  const sessionId =
    crypto.randomBytes(32)
      .toString("hex");

  const createdAt =
    new Date();

  const expiresAt =
    new Date(
      createdAt.getTime() +
        SESSION_DURATION_DAYS *
          24 *
          60 *
          60 *
          1000,
    );

  createSession({
    id: sessionId,

    userId,

    createdAt:
      createdAt.toISOString(),

    expiresAt:
      expiresAt.toISOString(),
  });

  return sessionId;
}


function getSessionToken(
  req: Request,
): string | undefined {
  const header =
    req.headers.authorization;

  if (
    !header ||
    !header.startsWith("Bearer ")
  ) {
    return undefined;
  }

  return header.substring(7);
}


function getAuthenticatedUser(
  req: Request,
) {
  const token =
    getSessionToken(req);

  if (!token) {
    return undefined;
  }

  const session =
    getSession(token);

  if (!session) {
    return undefined;
  }

  return getUserById(
    session.userId,
  );
}


// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================

function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const user =
    getAuthenticatedUser(req);

  if (!user) {
    return res.status(401).json({
      error:
        "Authentication required",
    });
  }

  (
    req as Request & {
      userId?: string;
    }
  ).userId = user.id;

  next();
}


// ============================================================
// HEALTH CHECK
// ============================================================

app.get(
  "/api/health",
  (_req, res) => {
    res.json({
      status: "ok",
      service:
        "adaptive-secret-backend",
    });
  },
);


// ============================================================
// REGISTER
// ============================================================

app.post(
  "/api/auth/register",
  (req, res) => {
    const {
      username,
      password,
    } = req.body;

    // --------------------------------------------
    // Validate username
    // --------------------------------------------

    if (
      typeof username !==
        "string" ||
      username.trim().length === 0
    ) {
      return res.status(400).json({
        error:
          "Username is required",
      });
    }

    const cleanUsername =
      username.trim();

    if (
      cleanUsername.length < 3
    ) {
      return res.status(400).json({
        error:
          "Username must be at least 3 characters",
      });
    }

    if (
      cleanUsername.length > 30
    ) {
      return res.status(400).json({
        error:
          "Username cannot exceed 30 characters",
      });
    }

    if (
      !/^[a-zA-Z0-9_]+$/.test(
        cleanUsername,
      )
    ) {
      return res.status(400).json({
        error:
          "Username can only contain letters, numbers, and underscores",
      });
    }

    // --------------------------------------------
    // Validate password
    // --------------------------------------------

    if (
      typeof password !==
        "string" ||
      password.length === 0
    ) {
      return res.status(400).json({
        error:
          "Password is required",
      });
    }

    if (
      password.length < 6
    ) {
      return res.status(400).json({
        error:
          "Password must be at least 6 characters",
      });
    }

    if (
      password.length > 128
    ) {
      return res.status(400).json({
        error:
          "Password cannot exceed 128 characters",
      });
    }

    // --------------------------------------------
    // Check username
    // --------------------------------------------

    const existingUser =
      getUserByUsername(
        cleanUsername,
      );

    if (existingUser) {
      return res.status(409).json({
        error:
          "Username is already taken",
      });
    }

    // --------------------------------------------
    // Create user
    // --------------------------------------------

    const userId =
      crypto.randomUUID();

    const passwordHash =
      hashPassword(
        password,
      );

    const createdAt =
      new Date();

    createUser({
      id: userId,

      username:
        cleanUsername,

      passwordHash,

      createdAt:
        createdAt.toISOString(),
    });

    // --------------------------------------------
    // Automatically log in
    // --------------------------------------------

    const sessionId =
      createAuthSession(
        userId,
      );

    return res.status(201).json({
      user: {
        id: userId,
        username:
          cleanUsername,
      },

      token: sessionId,
    });
  },
);


// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  (req, res) => {
    const {
      username,
      password,
    } = req.body;

    if (
      typeof username !==
        "string" ||
      typeof password !==
        "string"
    ) {
      return res.status(400).json({
        error:
          "Username and password are required",
      });
    }

    const user =
      getUserByUsername(
        username,
      );

    if (!user) {
      return res.status(401).json({
        error:
          "Invalid username or password",
      });
    }

    const valid =
      verifyPassword(
        password,
        user.passwordHash,
      );

    if (!valid) {
      return res.status(401).json({
        error:
          "Invalid username or password",
      });
    }

    const token =
      createAuthSession(
        user.id,
      );

    return res.json({
      user: {
        id: user.id,
        username:
          user.username,
      },

      token,
    });
  },
);


// ============================================================
// CURRENT USER
// ============================================================

app.get(
  "/api/auth/me",
  requireAuth,
  (req, res) => {
    const user =
      getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    return res.json({
      user: {
        id: user.id,
        username:
          user.username,
      },
    });
  },
);


// ============================================================
// LOGOUT
// ============================================================

app.post(
  "/api/auth/logout",
  requireAuth,
  (req, res) => {
    const token =
      getSessionToken(req);

    if (token) {
      deleteSession(token);
    }

    return res.json({
      status: "ok",
      message:
        "Logged out successfully",
    });
  },
);


// ============================================================
// CREATE SHARE
// ============================================================

app.post(
  "/api/shares",
  requireAuth,
  (req, res) => {
    const userId =
      (
        req as Request & {
          userId?: string;
        }
      ).userId;

    if (!userId) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    const {
      ciphertext,
      iv,

      expiresInSeconds = 600,

      maxViews = 1,

      riskLevel = "LOW",
    } = req.body;

    // --------------------------------------------
    // Validate encrypted data
    // --------------------------------------------

    if (
      !ciphertext ||
      !iv
    ) {
      return res.status(400).json({
        error:
          "ciphertext and iv are required",
      });
    }

    // --------------------------------------------
    // Validate risk level
    // --------------------------------------------

    const allowedRiskLevels = [
      "LOW",
      "MEDIUM",
      "HIGH",
      "CRITICAL",
    ] as const;

    if (
      !allowedRiskLevels.includes(
        riskLevel,
      )
    ) {
      return res.status(400).json({
        error:
          "Invalid risk level",
      });
    }

    // --------------------------------------------
    // Validate expiration
    // --------------------------------------------

    if (
      !Number.isInteger(
        expiresInSeconds,
      ) ||
      expiresInSeconds <= 0
    ) {
      return res.status(400).json({
        error:
          "Expiration must be a positive number of seconds",
      });
    }

    const MAX_EXPIRATION_SECONDS =
      365 *
      24 *
      60 *
      60;

    if (
      expiresInSeconds >
      MAX_EXPIRATION_SECONDS
    ) {
      return res.status(400).json({
        error:
          "Expiration cannot exceed 365 days",
      });
    }

    // --------------------------------------------
    // Validate view count
    // --------------------------------------------

    if (
      !Number.isInteger(
        maxViews,
      ) ||
      maxViews <= 0
    ) {
      return res.status(400).json({
        error:
          "Maximum views must be a positive integer",
      });
    }

    if (
      maxViews > 10000
    ) {
      return res.status(400).json({
        error:
          "Maximum views cannot exceed 10,000",
      });
    }

    // --------------------------------------------
    // Generate IDs
    // --------------------------------------------

    const id =
      crypto.randomUUID();

    const burnToken =
      crypto
        .randomBytes(32)
        .toString("hex");

    // --------------------------------------------
    // Calculate expiration
    // --------------------------------------------

    const createdAt =
      new Date();

    const expiresAt =
      new Date(
        createdAt.getTime() +
          expiresInSeconds *
            1000,
      );

    // --------------------------------------------
    // Store share
    // --------------------------------------------

    createShare({
      id,

      ciphertext,
      iv,

      createdAt:
        createdAt.toISOString(),

      expiresAt:
        expiresAt.toISOString(),

      maxViews,

      views: 0,

      burned: false,

      burnToken,

      riskLevel,

      ownerId: userId,
    });

    // --------------------------------------------
    // Return creator information
    // --------------------------------------------

    return res.status(201).json({
      id,

      expiresAt:
        expiresAt.toISOString(),

      maxViews,

      burnToken,
    });
  },
);


// ============================================================
// RETRIEVE PUBLIC SHARE
// ============================================================
//
// IMPORTANT:
// This endpoint intentionally does NOT require login.
// Anyone with a valid share link can retrieve it.
//

app.get(
  "/api/shares/:id",
  (req, res) => {
    const share =
      getShare(
        req.params.id,
      );

    if (!share) {
      return res.status(404).json({
        error:
          "Share not found",
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
      new Date(
        share.expiresAt,
      )
    ) {
      return res.status(410).json({
        error:
          "Share has expired",
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
        error:
          "View limit reached",
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
        error:
          "Share not found",
      });
    }

    // --------------------------------------------
    // Return encrypted data
    // --------------------------------------------

    return res.json({
      id:
        updatedShare.id,

      ciphertext:
        updatedShare.ciphertext,

      iv:
        updatedShare.iv,

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


// ============================================================
// GET MY SHARES
// ============================================================

app.get(
  "/api/shares",
  requireAuth,
  (req, res) => {
    const userId =
      (
        req as Request & {
          userId?: string;
        }
      ).userId;

    if (!userId) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    const shares =
      getSharesByOwner(
        userId,
      );

    // Never expose the burn token
    // through the dashboard endpoint.

    const safeShares =
      shares.map(
        (share) => ({
          id:
            share.id,

          createdAt:
            share.createdAt,

          expiresAt:
            share.expiresAt,

          maxViews:
            share.maxViews,

          views:
            share.views,

          burned:
            share.burned,

          riskLevel:
            share.riskLevel,
        }),
      );

    return res.json({
      shares:
        safeShares,
    });
  },
);


// ============================================================
// KILL SWITCH
// ============================================================

app.post(
  "/api/shares/:id/burn",
  requireAuth,
  (req, res) => {
    const userId =
      (
        req as Request & {
          userId?: string;
        }
      ).userId;

    if (!userId) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    const share =
      getShare(
        req.params.id,
      );

    // --------------------------------------------
    // Not found
    // --------------------------------------------

    if (!share) {
      return res.status(404).json({
        error:
          "Share not found",
      });
    }

    // --------------------------------------------
    // Ownership check
    // --------------------------------------------

    if (
      share.ownerId !==
      userId
    ) {
      return res.status(403).json({
        error:
          "You are not allowed to revoke this share",
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
    // Optional backwards-compatible
    // burn token verification
    // --------------------------------------------

    const {
      burnToken,
    } = req.body;

    if (
      burnToken &&
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
        error:
          "Share not found",
      });
    }

    return res.json({
      id:
        updatedShare.id,

      status:
        "burned",

      message:
        "Share has been permanently disabled.",
    });
  },
);


// ============================================================
// START SERVER
// ============================================================

app.listen(
  PORT,
  () => {
    console.log(
      `Adaptive Secret backend running on http://localhost:${PORT}`,
    );
  },
);