export type SecretType =
  | "password"
  | "pin"
  | "otp"
  | "api_key"
  | "token"
  | "jwt"
  | "private_key"
  | "encryption_key"
  | "recovery_code"
  | "database_credential"
  | "card"
  | "cvv"
  | "bank_account"
  | "ifsc"
  | "iban"
  | "swift"
  | "upi_id"
  | "email"
  | "phone"
  | "aadhaar"
  | "pan";

export interface DetectedSecret {
  type: SecretType;
  label: string;
  confidence: number;
  severity: "medium" | "high" | "critical";
  start: number;
  end: number;
  matchedText: string;
}

type PatternDefinition = {
  type: SecretType;
  label: string;
  pattern: RegExp;
  confidence: number;
  severity: DetectedSecret["severity"];
};

const patterns: PatternDefinition[] = [
  // =========================================================
  // PASSWORDS
  // =========================================================

  {
    type: "password",
    label: "Password",
    pattern:
      /\b(?:password|passwd|pwd)\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.96,
    severity: "high",
  },

  {
    type: "password",
    label: "Account Password",
    pattern:
      /\b(?:account|login|email|user)\s+password\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.97,
    severity: "high",
  },

  {
    type: "password",
    label: "Phone Password",
    pattern:
      /\b(?:phone|mobile|device|screen|lock)\s+(?:password|passcode)\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.97,
    severity: "high",
  },

  {
    type: "password",
    label: "Card Password",
    pattern:
      /\b(?:credit\s+card|debit\s+card|card)\s+password\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.97,
    severity: "critical",
  },

  {
    type: "password",
    label: "Environment Password",
    pattern:
      /\b(?:DB_|DATABASE_|ADMIN_|USER_)?PASSWORD\s*=\s*["']?([^\s"']+)["']?/gi,
    confidence: 0.98,
    severity: "high",
  },

  // =========================================================
  // PIN / PASSCODE
  // =========================================================

  {
    type: "pin",
    label: "PIN",
    pattern:
      /\b(?:pin|card\s+pin|atm\s+pin|bank\s+pin|phone\s+pin|mobile\s+pin|device\s+pin|mpin)\s*(?:is|equals|:|=)\s*(\d{3,8})\b/gi,
    confidence: 0.97,
    severity: "critical",
  },

  // =========================================================
  // OTP / VERIFICATION CODES
  // =========================================================

  {
    type: "otp",
    label: "OTP / Verification Code",
    pattern:
      /\b(?:otp|one[-\s]?time\s+(?:password|code)|verification\s+code|verification\s+otp|login\s+code|security\s+code)\s*(?:is|equals|:|=)\s*(\d{4,8})\b/gi,
    confidence: 0.98,
    severity: "critical",
  },

  {
    type: "otp",
    label: "2FA Code",
    pattern:
      /\b(?:2fa|mfa|two[-\s]?factor)\s+(?:code|otp)\s*(?:is|equals|:|=)\s*(\d{4,8})\b/gi,
    confidence: 0.98,
    severity: "critical",
  },

  // =========================================================
  // RECOVERY / BACKUP CODES
  // =========================================================

  {
    type: "recovery_code",
    label: "Recovery Code",
    pattern:
      /\b(?:recovery\s+code|backup\s+code|recovery\s+key|backup\s+key)\s*(?:is|equals|:|=)\s*["']?([A-Za-z0-9_-]{4,})["']?/gi,
    confidence: 0.97,
    severity: "critical",
  },

  // =========================================================
  // API KEYS / CLIENT SECRETS
  // =========================================================

  {
    type: "api_key",
    label: "API Key",
    pattern:
      /\b(?:api[\s_-]?key|apikey|secret[\s_-]?key)\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.96,
    severity: "high",
  },

  {
    type: "api_key",
    label: "Client Secret",
    pattern:
      /\b(?:client[\s_-]?secret|app[\s_-]?secret|application[\s_-]?secret)\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.97,
    severity: "critical",
  },

  {
    type: "api_key",
    label: "API Secret",
    pattern:
      /\b(?:api[\s_-]?secret|webhook[\s_-]?secret)\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.97,
    severity: "critical",
  },

  // Common Stripe-like secret/public keys
  {
    type: "api_key",
    label: "API Key",
    pattern:
      /\b((?:sk|pk|rk)_[A-Za-z0-9_-]{16,})\b/g,
    confidence: 0.98,
    severity: "high",
  },

  // AWS access key IDs
  {
    type: "api_key",
    label: "AWS Access Key",
    pattern:
      /\b(AKIA[0-9A-Z]{16})\b/g,
    confidence: 0.99,
    severity: "critical",
  },

  // GitHub tokens
  {
    type: "token",
    label: "GitHub Token",
    pattern:
      /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,})\b/g,
    confidence: 0.99,
    severity: "critical",
  },

  // =========================================================
  // TOKENS
  // =========================================================

  {
    type: "token",
    label: "Access Token",
    pattern:
      /\b(?:token|access[\s_-]?token|auth[\s_-]?token|bearer[\s_-]?token|session[\s_-]?token|refresh[\s_-]?token)\s*(?:is|equals|:|=)\s*["']?([^\s"',.;!?]+)["']?/gi,
    confidence: 0.96,
    severity: "high",
  },

  {
    type: "token",
    label: "Bearer Token",
    pattern:
      /\bBearer\s+([A-Za-z0-9._~+/=-]{10,})/gi,
    confidence: 0.98,
    severity: "high",
  },

  // =========================================================
  // JWT
  // =========================================================

  {
    type: "jwt",
    label: "JWT Token",
    pattern:
      /\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b/g,
    confidence: 0.99,
    severity: "high",
  },

  // =========================================================
  // PRIVATE KEYS
  // =========================================================

  {
    type: "private_key",
    label: "Private Key",
    pattern:
      /(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/g,
    confidence: 0.99,
    severity: "critical",
  },

  // =========================================================
  // ENCRYPTION / DECRYPTION KEYS
  // =========================================================

  {
    type: "encryption_key",
    label: "Encryption / Decryption Key",
    pattern:
      /\b(?:encryption\s+key|decryption\s+key|decrypt\s+key|encrypt\s+key|master\s+key|crypto\s+key)\s*(?:is|equals|:|=)\s*["']?([A-Za-z0-9+/=_-]{6,})["']?/gi,
    confidence: 0.97,
    severity: "critical",
  },

  {
    type: "encryption_key",
    label: "Secret Key",
    pattern:
      /\b(?:SECRET_KEY|ENCRYPTION_KEY|DECRYPTION_KEY|MASTER_KEY)\s*=\s*["']?([^\s"']+)["']?/g,
    confidence: 0.98,
    severity: "critical",
  },

  // =========================================================
  // DATABASE CREDENTIALS
  // =========================================================

  {
    type: "database_credential",
    label: "Database Password",
    pattern:
      /\bDB_PASSWORD\s*=\s*["']?([^\s"']+)["']?/gi,
    confidence: 0.98,
    severity: "critical",
  },

  {
    type: "database_credential",
    label: "Database Username",
    pattern:
      /\bDB_USER(?:NAME)?\s*=\s*["']?([^\s"']+)["']?/gi,
    confidence: 0.9,
    severity: "medium",
  },

  {
    type: "database_credential",
    label: "Database Connection",
    pattern:
      /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s]+)/gi,
    confidence: 0.99,
    severity: "critical",
  },

  // =========================================================
  // PAYMENT CARD
  // =========================================================

  {
    type: "card",
    label: "Card Number",
    pattern:
      /\b(?:card\s+number|credit\s+card|debit\s+card)\s*(?:is|equals|:|=)\s*((?:\d[ -]?){13,19})\b/gi,
    confidence: 0.96,
    severity: "critical",
  },

  {
    type: "cvv",
    label: "CVV / CVC",
    pattern:
      /\b(?:cvv|cvc|cvv2|cvc2|card\s+security\s+code)\s*(?:is|equals|:|=)\s*(\d{3,4})\b/gi,
    confidence: 0.99,
    severity: "critical",
  },

  // =========================================================
  // BANK DETAILS
  // =========================================================

  {
    type: "bank_account",
    label: "Bank Account Number",
    pattern:
      /\b(?:bank\s+account|account\s+number|account\s+no|a\/c\s+no)\s*(?:is|equals|:|=)\s*(\d{6,18})\b/gi,
    confidence: 0.96,
    severity: "critical",
  },

  {
    type: "ifsc",
    label: "IFSC Code",
    pattern:
      /\b(?:ifsc|ifsc\s+code)\s*(?:is|equals|:|=)?\s*([A-Z]{4}0[A-Z0-9]{6})\b/gi,
    confidence: 0.99,
    severity: "high",
  },

  {
    type: "iban",
    label: "IBAN",
    pattern:
      /\b(?:iban)\s*(?:is|equals|:|=)?\s*([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/gi,
    confidence: 0.99,
    severity: "critical",
  },

  {
    type: "swift",
    label: "SWIFT / BIC Code",
    pattern:
      /\b(?:swift|bic|swift\s+code|bic\s+code)\s*(?:is|equals|:|=)?\s*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gi,
    confidence: 0.96,
    severity: "high",
  },

  {
    type: "upi_id",
    label: "UPI ID",
    pattern:
      /\b(?:upi|upi\s+id)\s*(?:is|equals|:|=)?\s*([A-Za-z0-9._-]{2,}@[A-Za-z][A-Za-z0-9.-]{1,})\b/gi,
    confidence: 0.95,
    severity: "high",
  },

  // =========================================================
  // PERSONAL INFORMATION
  // =========================================================

  {
    type: "email",
    label: "Email Address",
    pattern:
      /\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b/gi,
    confidence: 0.96,
    severity: "medium",
  },

  {
    type: "phone",
    label: "Phone Number",
    pattern:
      /\b(?:phone|mobile|contact|telephone)\s*(?:is|equals|:|=)?\s*(\+?\d[\d\s-]{7,14}\d)\b/gi,
    confidence: 0.93,
    severity: "medium",
  },

  // Indian Aadhaar format: 12 digits, often grouped 4-4-4.
  {
    type: "aadhaar",
    label: "Aadhaar Number",
    pattern:
      /\b(?:aadhaar|aadhar)\s*(?:number|no)?\s*(?:is|equals|:|=)?\s*(\d{4}[\s-]?\d{4}[\s-]?\d{4})\b/gi,
    confidence: 0.98,
    severity: "critical",
  },

  // Indian PAN
  {
    type: "pan",
    label: "PAN Number",
    pattern:
      /\b(?:pan|pan\s+number|pan\s+no)\s*(?:is|equals|:|=)?\s*([A-Z]{5}\d{4}[A-Z])\b/gi,
    confidence: 0.98,
    severity: "high",
  },
];

function createDetections(
  text: string,
  definition: PatternDefinition,
): DetectedSecret[] {
  const flags =
    definition.pattern.flags.includes("g")
      ? definition.pattern.flags
      : `${definition.pattern.flags}g`;

  const regex = new RegExp(
    definition.pattern.source,
    flags,
  );

  const results: DetectedSecret[] = [];

  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    const matchedText =
      match[1] ?? match[0];

    const offset =
      match[1]
        ? match[0].indexOf(match[1])
        : 0;

    const start =
      match.index +
      Math.max(0, offset);

    results.push({
      type: definition.type,
      label: definition.label,
      confidence: definition.confidence,
      severity: definition.severity,
      start,
      end: start + matchedText.length,
      matchedText,
    });

    if (match[0].length === 0) {
      regex.lastIndex++;
    }
  }

  return results;
}

export function detectSecrets(
  text: string,
): DetectedSecret[] {
  if (!text.trim()) {
    return [];
  }

  const detected: DetectedSecret[] = [];

  for (const definition of patterns) {
    detected.push(
      ...createDetections(
        text,
        definition,
      ),
    );
  }

  /*
   * Remove detections that point to exactly the same text.
   *
   * Unlike the OLD version, this does NOT remove two
   * passwords just because both have type "password".
   */
  const unique =
    new Map<string, DetectedSecret>();

  for (const secret of detected) {
    const key =
      `${secret.start}-${secret.end}`;

    const existing =
      unique.get(key);

    if (
      !existing ||
      secret.confidence >
        existing.confidence
    ) {
      unique.set(
        key,
        secret,
      );
    }
  }

  return Array.from(
    unique.values(),
  ).sort(
    (a, b) =>
      a.start - b.start,
  );
}