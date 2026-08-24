const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

  const iv = crypto.getRandomValues(
    new Uint8Array(12),
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encoder.encode(secret),
  );

  const rawKey = await crypto.subtle.exportKey(
    "raw",
    key,
  );

  return {
    ciphertext: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer),
    key: arrayBufferToBase64(rawKey),
  };
}

/**
 * Create a share.
 *
 * The frontend works in minutes; the backend expects seconds.
 * The encryption key is never sent to the backend.
 */
export async function createShare(
  encryptedSecret: EncryptedSecret,
  options?: {
    expiresInMinutes?: number;
    maxViews?: number;
    riskLevel?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  },
): Promise<ShareResponse> {
  const expiresInMinutes = options?.expiresInMinutes ?? 10;

  if (!Number.isFinite(expiresInMinutes) || expiresInMinutes <= 0) {
    throw new Error("Expiration time must be greater than 0.");
  }

  const expiresInSeconds = Math.round(expiresInMinutes * 60);

  const response = await fetch(
    "http://localhost:4000/api/shares",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ciphertext: encryptedSecret.ciphertext,
        iv: encryptedSecret.iv,
        expiresInSeconds,
        maxViews: options?.maxViews ?? 1,
        riskLevel: options?.riskLevel ?? "LOW",
      }),
    },
  );

  if (!response.ok) {
    let errorMessage = "Failed to create secure share.";

    try {
      const errorData = await response.json();
      if (errorData?.error) {
        errorMessage = errorData.error;
      }
    } catch {
      // Keep default error.
    }

    throw new Error(errorMessage);
  }

  const data = await response.json();

  if (!data?.id || !data?.expiresAt || !data?.burnToken) {
    throw new Error("Backend returned an incomplete share response.");
  }

  return data;
}

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
    `http://localhost:4000/api/shares/${encodeURIComponent(shareId)}`,
  );

  if (!response.ok) {
    let errorMessage = "Failed to retrieve secure share.";

    try {
      const errorData = await response.json();
      if (errorData?.error) {
        errorMessage = errorData.error;
      }
    } catch {
      // Keep default error.
    }

    throw new Error(errorMessage);
  }

  return response.json();
}

/**
 * Creator-only kill switch.
 * The burnToken is never included in the recipient URL.
 */
export async function burnShare(
  shareId: string,
  burnToken: string,
): Promise<{
  id: string;
  status: string;
  message: string;
}> {
  if (!burnToken) {
    throw new Error("Kill switch authorization is missing.");
  }

  const response = await fetch(
    `http://localhost:4000/api/shares/${encodeURIComponent(shareId)}/burn`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        burnToken,
      }),
    },
  );

  if (!response.ok) {
    let errorMessage = "Failed to revoke secure share.";

    try {
      const errorData = await response.json();
      if (errorData?.error) {
        errorMessage = errorData.error;
      }
    } catch {
      // Keep default error.
    }

    throw new Error(errorMessage);
  }

  return response.json();
}

export async function revokeShare(
  shareId: string,
  burnToken: string,
): Promise<{
  id: string;
  status: string;
  message: string;
}> {
  return burnShare(shareId, burnToken);
}

export async function decryptSecret(
  encryptedSecret: EncryptedSecret,
): Promise<string> {
  const keyData = base64ToArrayBuffer(encryptedSecret.key);
  const iv = base64ToArrayBuffer(encryptedSecret.iv);
  const ciphertext = base64ToArrayBuffer(encryptedSecret.ciphertext);

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