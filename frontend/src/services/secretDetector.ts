export type SecretType =
  | "password"
  | "api_key"
  | "jwt"
  | "private_key"
  | "database_credential";

export interface DetectedSecret {
  type: SecretType;
  label: string;
  confidence: number;
  severity: "medium" | "high" | "critical";
}

const patterns: {
  type: SecretType;
  label: string;
  pattern: RegExp;
  confidence: number;
  severity: DetectedSecret["severity"];
}[] = [
  {
    type: "password",
    label: "Password",
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*[^\s]+/i,
    confidence: 0.95,
    severity: "high",
  },
  {
    type: "api_key",
    label: "API Key",
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[^\s]+/i,
    confidence: 0.9,
    severity: "high",
  },
  {
    type: "jwt",
    label: "JWT Token",
    pattern: /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/,
    confidence: 0.98,
    severity: "high",
  },
  {
    type: "private_key",
    label: "Private Key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    confidence: 0.99,
    severity: "critical",
  },
  {
    type: "database_credential",
    label: "Database Credential",
    pattern: /(?:DB_HOST\s*[:=]\s*[^\s]+[\s\S]*DB_USER\s*[:=]\s*[^\s]+[\s\S]*DB_PASSWORD\s*[:=]\s*[^\s]+)|(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s]+/i,
    confidence: 0.95,
    severity: "critical",
  },
];

export function detectSecrets(text: string): DetectedSecret[] {
  return patterns
    .filter(({ pattern }) => pattern.test(text))
    .map(({ type, label, confidence, severity }) => ({
      type,
      label,
      confidence,
      severity,
    }));
}