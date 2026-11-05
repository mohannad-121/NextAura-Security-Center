import { pgEnum } from "drizzle-orm/pg-core";

export const osTypeEnum = pgEnum("os_type", ["WINDOWS", "MACOS"]);
export const roleEnum = pgEnum("member_role", [
  "OWNER",
  "ADMIN",
  "SECURITY_ANALYST",
  "VIEWER",
]);
export const severityEnum = pgEnum("severity", [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
]);
export const checkStatusEnum = pgEnum("check_status", [
  "PASS",
  "FAIL",
  "WARNING",
  "UNKNOWN",
  "UNSUPPORTED",
  "PERMISSION_DENIED",
  "STALE",
]);
export const confidenceEnum = pgEnum("confidence", ["HIGH", "MEDIUM", "LOW"]);
export const findingStatusEnum = pgEnum("finding_status", [
  "OPEN",
  "ACKNOWLEDGED",
  "RESOLVED",
  "FALSE_POSITIVE",
]);
export const matchConfidenceEnum = pgEnum("match_confidence", [
  "CONFIRMED",
  "PROBABLE",
  "POSSIBLE",
  "UNKNOWN",
]);
export const deviceStatusEnum = pgEnum("device_status", ["ACTIVE", "REVOKED"]);
export const enrollmentStatusEnum = pgEnum("enrollment_status", [
  "PENDING",
  "CONSUMED",
  "EXPIRED",
  "CANCELLED",
]);
export const agentRequestStatusEnum = pgEnum("agent_request_status", [
  "PENDING",
  "DELIVERED",
  "ACKNOWLEDGED",
  "COMPLETED",
  "EXPIRED",
  "REJECTED",
]);
export const assessmentTriggerEnum = pgEnum("assessment_trigger", [
  "ENROLLMENT",
  "SCHEDULED",
  "MANUAL",
]);
export const assessmentStatusEnum = pgEnum("assessment_status", [
  "COMPLETE",
  "PARTIAL",
  "FAILED",
]);
export const reportTypeEnum = pgEnum("report_type", [
  "DEVICE_PDF",
  "ORGANIZATION_PDF",
  "FINDINGS_CSV",
]);
export const reportStatusEnum = pgEnum("report_status", [
  "COMPLETED",
  "FAILED",
]);
export const actorTypeEnum = pgEnum("actor_type", ["USER", "DEVICE", "SYSTEM"]);
export const incidentStatusEnum = pgEnum("incident_status", [
  "OPEN",
  "INVESTIGATING",
  "CONTAINED",
  "CLOSED",
]);
export const evidenceClassificationEnum = pgEnum("evidence_classification", [
  "CONFIRMED_DETECTION",
  "SUSPICIOUS_INDICATOR",
  "INCONCLUSIVE",
  "NO_FINDINGS_OBSERVED",
  "UNSUPPORTED",
]);

export const COLLECTOR_IDS = [
  "SYSTEM_INFO",
  "SECURITY_POSTURE",
  "ANTIVIRUS_STATUS",
  "SOFTWARE_INVENTORY",
  "STARTUP_INVENTORY",
  "SAFE_NETWORK_SUMMARY",
] as const;
export type CollectorId = (typeof COLLECTOR_IDS)[number];
