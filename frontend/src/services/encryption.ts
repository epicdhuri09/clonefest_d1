const encoder = new TextEncoder();
const decoder = new TextDecoder();

const API_BASE = "http://localhost:4000";

export interface EncryptedSecret {
  ciphertext: string;
  iv: string;
  key: string;
}

export interface ShareResponse {
  id: string;
  expiresAt: string;
  maxViews: number;
  burnToken: string;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem("authToken");

  return token
    ? { Authorization: `Bearer ${token}` }
    : {};
}

/** Encrypt locally using AES-256-GCM. */
export async function encryptSecret(
  secret: string,
): Promise<EncryptedSecret> {
  const key = await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encoder.encode(secret),
  );

  const rawKey = await crypto.subtle.exportKey("raw", key);

  return {
    ciphertext: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer),
    key: arrayBufferToBase64(rawKey),
  };
}

/** Create an authenticated secure share. */
export async function createShare(
  encryptedSecret: EncryptedSecret,
  options?: {
    expiresInMinutes?: number;
    maxViews?: number;
    riskLevel?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  },
): Promise<ShareResponse> {
  const expiresInMinutes = options?.expiresInMinutes ?? 10;

  const response = await fetch(`${API_BASE}/api/shares`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify({
      ciphertext: encryptedSecret.ciphertext,
      iv: encryptedSecret.iv,
      expiresInSeconds: Math.round(expiresInMinutes * 60),
      maxViews: options?.maxViews ?? 1,
      riskLevel: options?.riskLevel ?? "LOW",
    }),
  });

  if (!response.ok) {
    throw new Error(
      await parseResponseError(
        response,
        "Failed to create secure share.",
      ),
    );
  }

  return response.json();
}

async function parseResponseError(
  response: Response,
  fallback: string,
): Promise<string> {
  try {
    const data = await response.json();
    return data?.error || fallback;
  } catch {
    return fallback;
  }
}

/** Retrieve an encrypted share. Recipient authentication is not required. */
export async function getShare(
  shareId: string,
): Promise<{
  id: string;
  ciphertext: string;
  iv: string;
  expiresAt: string;
  maxViews: number;
  views: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}> {
  const response = await fetch(
    `${API_BASE}/api/shares/${encodeURIComponent(shareId)}`,
  );

  if (!response.ok) {
    throw new Error(
      await parseResponseError(
        response,
        "Failed to retrieve secure share.",
      ),
    );
  }

  return response.json();
}

/** Permanently revoke a share owned by the logged-in user. */
export async function burnShare(
  shareId: string,
  burnToken?: string,
): Promise<{
  id: string;
  status: string;
  message: string;
}> {
  const response = await fetch(
    `${API_BASE}/api/shares/${encodeURIComponent(shareId)}/burn`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeaders(),
      },
      body: JSON.stringify(
        burnToken ? { burnToken } : {},
      ),
    },
  );

  if (!response.ok) {
    throw new Error(
      await parseResponseError(
        response,
        "Failed to revoke secure share.",
      ),
    );
  }

  return response.json();
}

/** Decrypt locally in the browser. */
export async function decryptSecret(
  encryptedSecret: EncryptedSecret,
): Promise<string> {
  const keyData = base64ToArrayBuffer(
    encryptedSecret.key,
  );

  const iv = base64ToArrayBuffer(
    encryptedSecret.iv,
  );

  const ciphertext = base64ToArrayBuffer(
    encryptedSecret.ciphertext,
  );

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["decrypt"],
  );

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    ciphertext,
  );

  return decoder.decode(decrypted);
}
