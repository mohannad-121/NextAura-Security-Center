import { and, desc, eq, inArray, sql } from "drizzle-orm";
import {
  db,
  assessmentsTable,
  assessmentChecksTable,
  securityFindingsTable,
  devicesTable,
  type Device,
  type Assessment,
  type Organization,
  type SecurityFinding,
} from "@workspace/db";
import { riskLevelFor } from "./rules";

export type SeverityCounts = { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; INFO: number };
export const emptySeverity = (): SeverityCounts => ({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });

export const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);

export function isOnline(device: Device, org: Organization, now = Date.now()): boolean {
  if (device.status === "REVOKED" || !device.lastSeenAt) return false;
  return now - device.lastSeenAt.getTime() <= org.onlineThresholdMinutes * 60_000;
}

export function agentReliability(device: Device, org: Organization, now = Date.now()) {
  if (device.status === "REVOKED") return "REVOKED" as const;
  if (!device.lastSeenAt) return "NEVER_REPORTED" as const;
  const ageMin = (now - device.lastSeenAt.getTime()) / 60_000;
  if (ageMin <= org.onlineThresholdMinutes) {
    return device.lastCollectorErrors.length > 0 || compareVer(device.agentVersion, org.minimumAgentVersion) < 0
      ? ("DEGRADED" as const)
      : ("HEALTHY" as const);
  }
  if (ageMin <= org.heartbeatIntervalMinutes * 6) return "DEGRADED" as const;
  return "OFFLINE" as const;
}

export function compareVer(a: string, b: string): number {
  const pa = a.split(".").map((x) => parseInt(x, 10) || 0);
  const pb = b.split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

export function coverageStatus(device: Device, org: Organization, now = Date.now()) {
  if (!device.lastAssessmentAt) return "NONE" as const;
  const ageH = (now - device.lastAssessmentAt.getTime()) / 3600_000;
  if (ageH > org.postureIntervalHours * 3) return "STALE" as const;
  if (device.coveragePercent >= 100) return "FULL" as const;
  return "PARTIAL" as const;
}

export async function openFindingCountsByDevice(deviceIds: string[]): Promise<Map<string, SeverityCounts>> {
  const map = new Map<string, SeverityCounts>();
  if (!deviceIds.length) return map;
  const rows = await db
    .select({ deviceId: securityFindingsTable.deviceId, severity: securityFindingsTable.severity, n: sql<number>`count(*)::int` })
    .from(securityFindingsTable)
    .where(and(inArray(securityFindingsTable.deviceId, deviceIds), inArray(securityFindingsTable.status, ["OPEN", "ACKNOWLEDGED"])))
    .groupBy(securityFindingsTable.deviceId, securityFindingsTable.severity);
  for (const r of rows) {
    const c = map.get(r.deviceId) ?? emptySeverity();
    c[r.severity] = r.n;
    map.set(r.deviceId, c);
  }
  return map;
}

export function serializeDevice(device: Device, org: Organization, open: SeverityCounts) {
  const now = Date.now();
  return {
    id: device.id,
    name: device.label ? `${device.name} (${device.label})` : device.name,
    osType: device.osType,
    osVersion: device.osName ? `${device.osName} ${device.osVersion}`.trim() : device.osVersion,
    osBuild: device.osBuild,
    architecture: device.architecture as "amd64" | "arm64" | "unknown",
    agentVersion: device.agentVersion,
    status: device.status,
    isOnline: isOnline(device, org, now),
    lastSeenAt: iso(device.lastSeenAt),
    lastAssessmentAt: iso(device.lastAssessmentAt),
    enrolledAt: device.enrolledAt.toISOString(),
    coverageStatus: coverageStatus(device, org, now),
    coveragePercent: device.coveragePercent,
    riskLevel: riskLevelFor(device.riskScore, device.coveragePercent),
    riskScore: device.riskScore,
    agentReliability: agentReliability(device, org, now),
    openFindings: open,
  };
}

export function serializeAssessment(a: Assessment, deviceName: string) {
  const cc = a.checkCounts;
  return {
    id: a.id,
    deviceId: a.deviceId,
    deviceName,
    trigger: a.trigger,
    status: a.status,
    startedAt: a.startedAt.toISOString(),
    completedAt: a.completedAt.toISOString(),
    receivedAt: a.receivedAt.toISOString(),
    collectorsRequested: a.collectorsRequested,
    collectorsSucceeded: a.collectorsSucceeded,
    collectorsFailed: a.collectorsFailed,
    riskScore: a.riskScore,
    coveragePercent: a.coveragePercent,
    checkCounts: {
      PASS: cc["PASS"] ?? 0,
      FAIL: cc["FAIL"] ?? 0,
      WARNING: cc["WARNING"] ?? 0,
      UNKNOWN: cc["UNKNOWN"] ?? 0,
      UNSUPPORTED: cc["UNSUPPORTED"] ?? 0,
      PERMISSION_DENIED: cc["PERMISSION_DENIED"] ?? 0,
      STALE: cc["STALE"] ?? 0,
    },
    agentVersion: a.agentVersion,
  };
}

export function serializeFinding(f: SecurityFinding, deviceName: string) {
  return {
    id: f.id,
    deviceId: f.deviceId,
    deviceName,
    ruleId: f.ruleId,
    title: f.title,
    description: f.description,
    severity: f.severity,
    confidence: f.confidence,
    evidence: f.evidence,
    detectionSource: f.detectionSource,
    status: f.status,
    firstSeenAt: f.firstSeenAt.toISOString(),
    lastSeenAt: f.lastSeenAt.toISOString(),
    remediation: f.remediation,
    assessmentId: f.assessmentId,
    collectorId: f.collectorId,
    rawStatus: f.rawStatus,
    collectorVersion: f.collectorVersion,
    statusChangedByEmail: f.statusChangedByEmail,
    statusChangedAt: iso(f.statusChangedAt),
  };
}

export async function deviceNameMap(orgId: string): Promise<Map<string, string>> {
  const rows = await db.select({ id: devicesTable.id, name: devicesTable.name, label: devicesTable.label }).from(devicesTable).where(eq(devicesTable.organizationId, orgId));
  return new Map(rows.map((r) => [r.id, r.label ? `${r.name} (${r.label})` : r.name]));
}

export async function latestAssessmentFor(deviceId: string) {
  const [a] = await db.select().from(assessmentsTable).where(eq(assessmentsTable.deviceId, deviceId)).orderBy(desc(assessmentsTable.receivedAt)).limit(1);
  return a ?? null;
}

export async function latestChecksFor(deviceId: string, assessmentId: string | null) {
  if (!assessmentId) return [];
  return db.select().from(assessmentChecksTable).where(and(eq(assessmentChecksTable.deviceId, deviceId), eq(assessmentChecksTable.assessmentId, assessmentId)));
}
