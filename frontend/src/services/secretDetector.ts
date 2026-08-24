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

  /*
   * Exact location of the sensitive value
   * inside the original text.
   */
  start: number;
  end: number;

  /*
   * The actual sensitive value that was detected.
   */
  matchedText: string;
}

/*
 * ---------------------------------------------------------
 * DETECTION PATTERNS
 * ---------------------------------------------------------
 */

const patterns: {
  type: SecretType;
  label: string;
  pattern: RegExp;
  confidence: number;
  severity: DetectedSecret["severity"];
}[] = [
  /*
   * PASSWORD
   */

  {
    type: "password",
    label: "Password",
    pattern:
      /\b(?:password|passwd|pwd)\s*(?:is|:|=)\s*([^\s,.;!?]+)/i,
    confidence: 0.96,
    severity: "high",
  },

  {
    type: "password",
    label: "Password",
    pattern:
      /\b(?:password|passwd|pwd)\s*(?:is|:|=)\s*["']([^"']{1,100})["']/i,
    confidence: 0.98,
    severity: "high",
  },

  /*
   * Environment variable passwords.
   */

  {
    type: "password",
    label: "Password",
    pattern:
      /\b(?:DB_)?PASSWORD\s*=\s*([^\s]+)/i,
    confidence: 0.98,
    severity: "high",
  },

  /*
   * API KEY
   */

  {
    type: "api_key",
    label: "API Key",
    pattern:
      /\b(?:api[\s_-]?key|apikey|secret[\s_-]?key)\s*(?:is|:|=)\s*([^\s,.;!?]+)/i,
    confidence: 0.94,
    severity: "high",
  },

  {
    type: "api_key",
    label: "API Key",
    pattern:
      /\b(?:api[\s_-]?key|apikey|secret[\s_-]?key)\s*(?:is|:|=)\s*["']([^"']{1,200})["']/i,
    confidence: 0.97,
    severity: "high",
  },

  /*
   * Common API key formats.
   */

  {
    type: "api_key",
    label: "API Key",
    pattern:
      /\b(?:sk|pk|rk)_[A-Za-z0-9_-]{16,}\b/,
    confidence: 0.97,
    severity: "high",
  },

  /*
   * JWT
   */

  {
    type: "jwt",
    label: "JWT Token",
    pattern:
      /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/,
    confidence: 0.99,
    severity: "high",
  },

  /*
   * PRIVATE KEY
   */

  {
    type: "private_key",
    label: "Private Key",
    pattern:
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    confidence: 0.99,
    severity: "critical",
  },

  /*
   * DATABASE CREDENTIAL
   */

  {
    type: "database_credential",
    label: "Database Credential",
    pattern:
      /\bDB_HOST\s*=\s*[^\s]+\s+DB_USER\s*=\s*[^\s]+\s+DB_PASSWORD\s*=\s*[^\s]+/i,
    confidence: 0.98,
    severity: "critical",
  },

  /*
   * Database connection strings.
   */

  {
    type: "database_credential",
    label: "Database Credential",
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s]+/i,
    confidence: 0.98,
    severity: "critical",
  },
];

/*
 * ---------------------------------------------------------
 * NATURAL LANGUAGE PASSWORD
 * ---------------------------------------------------------
 *
 * Examples:
 *
 * "hello my password is 1234"
 * "my password is hunter2"
 * "the password is abc123"
 */

function detectNaturalLanguagePassword(
  text: string,
): DetectedSecret | null {
  const pattern =
    /\b(?:my|the|your|login|account)?\s*(?:password|passwd|pwd)\s+(?:is|equals|=)\s+([^\s,.;!?]+)/i;

  const match = pattern.exec(text);

  if (!match || match.index === undefined) {
    return null;
  }

  const value = match[1].trim();

  if (value.length < 2) {
    return null;
  }

  const start =
    match.index + match[0].lastIndexOf(value);

  return {
    type: "password",
    label: "Password",
    confidence: 0.96,
    severity: "high",
    start,
    end: start + value.length,
    matchedText: value,
  };
}

/*
 * ---------------------------------------------------------
 * NATURAL LANGUAGE API KEY
 * ---------------------------------------------------------
 *
 * Examples:
 *
 * "my API key is abc123..."
 * "the secret key is xyz..."
 */

function detectNaturalLanguageApiKey(
  text: string,
): DetectedSecret | null {
  const pattern =
    /\b(?:my|the|your)?\s*(?:api[\s_-]?key|apikey|secret[\s_-]?key)\s+(?:is|equals|=)\s+([^\s,.;!?]+)/i;

  const match = pattern.exec(text);

  if (!match || match.index === undefined) {
    return null;
  }

  const value = match[1].trim();

  if (value.length < 6) {
    return null;
  }

  const start =
    match.index + match[0].lastIndexOf(value);

  return {
    type: "api_key",
    label: "API Key",
    confidence: 0.93,
    severity: "high",
    start,
    end: start + value.length,
    matchedText: value,
  };
}

/*
 * ---------------------------------------------------------
 * CREATE DETECTION FROM REGULAR EXPRESSION
 * ---------------------------------------------------------
 */

function createDetection(
  text: string,
  definition: (typeof patterns)[number],
): DetectedSecret | null {
  const pattern = new RegExp(
    definition.pattern.source,
    definition.pattern.flags,
  );

  const match = pattern.exec(text);

  if (!match || match.index === undefined) {
    return null;
  }

  /*
   * If the regex contains a capture group, use that
   * group as the sensitive value.
   *
   * Example:
   *
   * password=1234
   *
   * We highlight:
   *
   * 1234
   *
   * rather than:
   *
   * password=1234
   */

  let matchedText = match[0];
  let start = match.index;

  if (match[1]) {
    matchedText = match[1];

    const capturedOffset =
      match[0].indexOf(match[1]);

    start =
      match.index +
      Math.max(0, capturedOffset);
  }

  return {
    type: definition.type,
    label: definition.label,
    confidence: definition.confidence,
    severity: definition.severity,
    start,
    end: start + matchedText.length,
    matchedText,
  };
}

/*
 * ---------------------------------------------------------
 * MAIN DETECTOR
 * ---------------------------------------------------------
 */

export function detectSecrets(
  text: string,
): DetectedSecret[] {
  if (!text.trim()) {
    return [];
  }

  const detected: DetectedSecret[] = [];

  /*
   * Run all predefined patterns.
   */

  for (const definition of patterns) {
    const result = createDetection(
      text,
      definition,
    );

    if (result) {
      detected.push(result);
    }
  }

  /*
   * Natural language password.
   */

  const naturalPassword =
    detectNaturalLanguagePassword(text);

  if (naturalPassword) {
    detected.push(naturalPassword);
  }

  /*
   * Natural language API key.
   */

  const naturalApiKey =
    detectNaturalLanguageApiKey(text);

  if (naturalApiKey) {
    detected.push(naturalApiKey);
  }

  /*
   * Remove duplicate secret TYPES.
   *
   * If multiple password rules detect the same
   * password, keep the highest-confidence result.
   */

  const uniqueSecrets =
    new Map<SecretType, DetectedSecret>();

  for (const secret of detected) {
    const existing =
      uniqueSecrets.get(secret.type);

    if (
      !existing ||
      secret.confidence > existing.confidence
    ) {
      uniqueSecrets.set(
        secret.type,
        secret,
      );
    }
  }

  return Array.from(
    uniqueSecrets.values(),
  );
}