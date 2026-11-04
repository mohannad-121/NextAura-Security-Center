export { latestAssessmentFor } from "./serializers";
import type { RiskLevel } from "./rules";

export function riskLevelLabel(level: RiskLevel): string {
  return level === "UNKNOWN" ? "unknown — insufficient data" : level.toLowerCase();
}
