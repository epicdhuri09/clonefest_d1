import type { DetectedSecret, SecretType } from "./secretDetector";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface RiskAnalysis {
  score: number;
  level: RiskLevel;
  detectedSecrets: DetectedSecret[];
  recommendations: string[];
}

const baseWeights: Record<SecretType, number> = {
  password: 30,
  api_key: 40,
  jwt: 40,
  private_key: 70,
  database_credential: 60,
};

function calculateBaseScore(secrets: DetectedSecret[]): number {
  return secrets.reduce((total, secret) => {
    return total + baseWeights[secret.type];
  }, 0);
}

function calculateCombinationBonus(secrets: DetectedSecret[]): number {
  const types = new Set(secrets.map((secret) => secret.type));

  let bonus = 0;

  // Password + database credential is more dangerous together.
  if (types.has("password") && types.has("database_credential")) {
    bonus += 20;
  }

  // API key + password creates a stronger credential bundle.
  if (types.has("api_key") && types.has("password")) {
    bonus += 15;
  }

  // Private key combined with another secret is treated as critical.
  if (types.has("private_key") && secrets.length > 1) {
    bonus += 20;
  }

  return bonus;
}

function getRiskLevel(score: number): RiskLevel {
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
  const recommendations: string[] = [];

  if (level === "LOW") {
    recommendations.push("Normal sharing controls");
    recommendations.push("Optional expiration");
  }

  if (level === "MEDIUM") {
    recommendations.push("Set an expiration time");
    recommendations.push("Consider password protection");
    recommendations.push("Limit the number of views");
  }

  if (level === "HIGH") {
    recommendations.push("Enable password protection");
    recommendations.push("Use a short expiration");
    recommendations.push("Limit access views");
    recommendations.push("Avoid permanent sharing");
  }

  if (level === "CRITICAL") {
    recommendations.push("Enable strong protection");
    recommendations.push("Use very short expiration");
    recommendations.push("Allow one-time access");
    recommendations.push("Automatically delete after access");
  }

  // Extra recommendation for credential-like content.
  const hasCredential = secrets.some(
    (secret) =>
      secret.type === "password" ||
      secret.type === "api_key" ||
      secret.type === "private_key" ||
      secret.type === "database_credential",
  );

  if (hasCredential && level !== "LOW") {
    recommendations.push("Consider rotating the underlying credential after sharing");
  }

  return recommendations;
}

export function analyzeRisk(secrets: DetectedSecret[]): RiskAnalysis {
  if (secrets.length === 0) {
    return {
      score: 0,
      level: "LOW",
      detectedSecrets: [],
      recommendations: ["No obvious secrets detected"],
    };
  }

  const baseScore = calculateBaseScore(secrets);
  const combinationBonus = calculateCombinationBonus(secrets);

  const score = Math.min(100, baseScore + combinationBonus);
  const level = getRiskLevel(score);
  const recommendations = getRecommendations(level, secrets);

  return {
    score,
    level,
    detectedSecrets: secrets,
    recommendations,
  };
}