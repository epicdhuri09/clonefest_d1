import type {
  DetectedSecret,
  SecretType,
} from "./secretDetector";

export type RiskLevel =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export interface RiskAnalysis {
  score: number;
  level: RiskLevel;
  detectedSecrets: DetectedSecret[];
  recommendations: string[];
}

const baseWeights: Record<
  SecretType,
  number
> = {
  password: 30,
  pin: 40,
  otp: 45,

  api_key: 45,
  token: 45,
  jwt: 45,

  private_key: 75,
  encryption_key: 70,
  recovery_code: 60,

  database_credential: 60,

  card: 65,
  cvv: 55,
  bank_account: 55,
  ifsc: 25,
  iban: 55,
  swift: 30,
  upi_id: 35,

  email: 10,
  phone: 15,
  aadhaar: 65,
  pan: 45,
};

function calculateBaseScore(
  secrets: DetectedSecret[],
): number {
  return secrets.reduce(
    (total, secret) => {
      return (
        total +
        baseWeights[secret.type]
      );
    },
    0,
  );
}

function calculateCombinationBonus(
  secrets: DetectedSecret[],
): number {
  const types = new Set(
    secrets.map(
      (secret) => secret.type,
    ),
  );

  let bonus = 0;

  // Password + database credential
  if (
    types.has("password") &&
    types.has("database_credential")
  ) {
    bonus += 20;
  }

  // Password + API key/token
  if (
    types.has("password") &&
    (
      types.has("api_key") ||
      types.has("token")
    )
  ) {
    bonus += 15;
  }

  // Password + OTP
  if (
    types.has("password") &&
    types.has("otp")
  ) {
    bonus += 20;
  }

  // Password + recovery code
  if (
    types.has("password") &&
    types.has("recovery_code")
  ) {
    bonus += 20;
  }

  // PIN + card number
  if (
    types.has("pin") &&
    types.has("card")
  ) {
    bonus += 25;
  }

  // CVV + card number
  if (
    types.has("cvv") &&
    types.has("card")
  ) {
    bonus += 25;
  }

  // Card + bank account
  if (
    types.has("card") &&
    types.has("bank_account")
  ) {
    bonus += 20;
  }

  // Bank account + IFSC
  if (
    types.has("bank_account") &&
    types.has("ifsc")
  ) {
    bonus += 20;
  }

  // Bank account + UPI
  if (
    types.has("bank_account") &&
    types.has("upi_id")
  ) {
    bonus += 15;
  }

  // IBAN + SWIFT/BIC
  if (
    types.has("iban") &&
    types.has("swift")
  ) {
    bonus += 20;
  }

  // Aadhaar + PAN
  if (
    types.has("aadhaar") &&
    types.has("pan")
  ) {
    bonus += 20;
  }

  // Personal identity bundle
  if (
    types.has("email") &&
    types.has("phone")
  ) {
    bonus += 10;
  }

  // Private key + anything else
  if (
    types.has("private_key") &&
    secrets.length > 1
  ) {
    bonus += 25;
  }

  // Encryption/decryption key + another secret
  if (
    types.has("encryption_key") &&
    secrets.length > 1
  ) {
    bonus += 20;
  }

  // Multiple authentication factors together
  if (
    types.has("password") &&
    types.has("pin") &&
    types.has("otp")
  ) {
    bonus += 25;
  }

  return bonus;
}

function getRiskLevel(
  score: number,
): RiskLevel {
  if (score >= 81) {
    return "CRITICAL";
  }

  if (score >= 51) {
    return "HIGH";
  }

  if (score >= 21) {
    return "MEDIUM";
  }

  return "LOW";
}

function getRecommendations(
  level: RiskLevel,
  secrets: DetectedSecret[],
): string[] {
  const recommendations: string[] =
    [];

  // =========================================================
  // GENERAL RECOMMENDATIONS
  // =========================================================

  if (level === "LOW") {
    recommendations.push(
      "Normal sharing controls",
    );

    recommendations.push(
      "Optional expiration",
    );
  }

  if (level === "MEDIUM") {
    recommendations.push(
      "Set an expiration time",
    );

    recommendations.push(
      "Consider password protection",
    );

    recommendations.push(
      "Limit the number of views",
    );
  }

  if (level === "HIGH") {
    recommendations.push(
      "Enable password protection",
    );

    recommendations.push(
      "Use a short expiration",
    );

    recommendations.push(
      "Limit access views",
    );

    recommendations.push(
      "Avoid permanent sharing",
    );
  }

  if (level === "CRITICAL") {
    recommendations.push(
      "Enable strong protection",
    );

    recommendations.push(
      "Use very short expiration",
    );

    recommendations.push(
      "Allow one-time access",
    );

    recommendations.push(
      "Automatically delete after access",
    );
  }

  // =========================================================
  // CREDENTIALS
  // =========================================================

  const hasCredential =
    secrets.some(
      (secret) =>
        secret.type === "password" ||
        secret.type === "pin" ||
        secret.type === "api_key" ||
        secret.type === "token" ||
        secret.type === "jwt" ||
        secret.type === "private_key" ||
        secret.type === "encryption_key" ||
        secret.type === "recovery_code" ||
        secret.type ===
          "database_credential",
    );

  if (
    hasCredential &&
    level !== "LOW"
  ) {
    recommendations.push(
      "Consider rotating the underlying credential after sharing",
    );
  }

  // =========================================================
  // OTP / MFA
  // =========================================================

  const hasOtp =
    secrets.some(
      (secret) =>
        secret.type === "otp",
    );

  if (hasOtp) {
    recommendations.push(
      "Do not reuse or forward one-time passwords or verification codes",
    );
  }

  // =========================================================
  // PRIVATE / ENCRYPTION KEYS
  // =========================================================

  const hasCryptographicKey =
    secrets.some(
      (secret) =>
        secret.type ===
          "private_key" ||
        secret.type ===
          "encryption_key",
    );

  if (hasCryptographicKey) {
    recommendations.push(
      "Avoid transmitting cryptographic keys through normal messaging channels",
    );

    recommendations.push(
      "Rotate the exposed key if it may have been disclosed",
    );
  }

  // =========================================================
  // API TOKENS
  // =========================================================

  const hasApiCredential =
    secrets.some(
      (secret) =>
        secret.type === "api_key" ||
        secret.type === "token" ||
        secret.type === "jwt",
    );

  if (hasApiCredential) {
    recommendations.push(
      "Restrict token permissions and revoke exposed tokens when possible",
    );
  }

  // =========================================================
  // DATABASE CREDENTIALS
  // =========================================================

  const hasDatabaseCredential =
    secrets.some(
      (secret) =>
        secret.type ===
        "database_credential",
    );

  if (hasDatabaseCredential) {
    recommendations.push(
      "Avoid exposing production database credentials",
    );

    recommendations.push(
      "Rotate database passwords if accidental exposure occurs",
    );
  }

  // =========================================================
  // FINANCIAL INFORMATION
  // =========================================================

  const hasFinancialData =
    secrets.some(
      (secret) =>
        secret.type === "card" ||
        secret.type === "cvv" ||
        secret.type === "pin" ||
        secret.type ===
          "bank_account" ||
        secret.type === "ifsc" ||
        secret.type === "iban" ||
        secret.type === "swift" ||
        secret.type === "upi_id",
    );

  if (hasFinancialData) {
    recommendations.push(
      "Avoid sharing banking or payment information unless absolutely necessary",
    );
  }

  const hasCardData =
    secrets.some(
      (secret) =>
        secret.type === "card" ||
        secret.type === "cvv",
    );

  if (hasCardData) {
    recommendations.push(
      "Never store or share card security codes together with card numbers",
    );
  }

  // =========================================================
  // BANK ACCOUNT
  // =========================================================

  const hasBankAccount =
    secrets.some(
      (secret) =>
        secret.type ===
        "bank_account",
    );

  if (hasBankAccount) {
    recommendations.push(
      "Mask bank account numbers before sharing whenever possible",
    );
  }

  // =========================================================
  // PERSONAL INFORMATION
  // =========================================================

  const hasPersonalData =
    secrets.some(
      (secret) =>
        secret.type === "email" ||
        secret.type === "phone" ||
        secret.type === "aadhaar" ||
        secret.type === "pan",
    );

  if (hasPersonalData) {
    recommendations.push(
      "Minimize exposure of personal identifying information",
    );
  }

  // =========================================================
  // HIGH-VALUE IDENTITY DOCUMENTS
  // =========================================================

  const hasIdentityDocument =
    secrets.some(
      (secret) =>
        secret.type === "aadhaar" ||
        secret.type === "pan",
    );

  if (hasIdentityDocument) {
    recommendations.push(
      "Mask identity numbers and share only the minimum required information",
    );
  }

  // =========================================================
  // MULTIPLE SECRETS
  // =========================================================

  if (secrets.length >= 3) {
    recommendations.push(
      "This message contains multiple sensitive values; consider sharing them separately",
    );
  }

  if (secrets.length >= 5) {
    recommendations.push(
      "High concentration of sensitive information detected",
    );
  }

  // Remove duplicate recommendation strings.
  return Array.from(
    new Set(recommendations),
  );
}

export function analyzeRisk(
  secrets: DetectedSecret[],
): RiskAnalysis {
  if (secrets.length === 0) {
    return {
      score: 0,
      level: "LOW",
      detectedSecrets: [],
      recommendations: [
        "No obvious secrets detected",
      ],
    };
  }

  const baseScore =
    calculateBaseScore(secrets);

  const combinationBonus =
    calculateCombinationBonus(
      secrets,
    );

  const score = Math.min(
    100,
    baseScore +
      combinationBonus,
  );

  const level =
    getRiskLevel(score);

  const recommendations =
    getRecommendations(
      level,
      secrets,
    );

  return {
    score,
    level,
    detectedSecrets: secrets,
    recommendations,
  };
}