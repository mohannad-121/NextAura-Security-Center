import { and, desc, eq, inArray, sql } from "drizzle-orm";
import {
  db,
  devicesTable,
  assessmentsTable,
  securityFindingsTable,
  vulnerabilityMatchesTable,
  deviceHeartbeatsTable,
  agentRequestsTable,
  deviceEnrollmentRequestsTable,
  type Organization,
} from "@workspace/db";
import { agentReliability, emptySeverity, isOnline, serializeAssessment, deviceNameMap } from "./serializers";

export async function dashboardSummary(org: Organization) {
  const devices = await db.select().from(devicesTable).where(eq(devicesTable.organizationId, org.id));
  const active = devices.filter((d) => d.status === "ACTIVE");
  const now = Date.now();
  const online = active.filter((d) => isOnline(d, org, now)).length;

  const sev = emptySeverity();
  const sevRows = await db
    .select({ severity: securityFindingsTable.severity, n: sql<number>`count(*)::int` })
    .from(securityFindingsTable)
    .where(and(eq(securityFindingsTable.organizationId, org.id), inArray(securityFindingsTable.status, ["OPEN", "ACKNOWLEDGED"])))
    .groupBy(securityFindingsTable.severity);
  for (const r of sevRows) sev[r.severity] = r.n;

  const attentionRows = await db
    .select({ deviceId: securityFindingsTable.deviceId })
    .from(securityFindingsTable)
    .where(and(eq(securityFindingsTable.organizationId, org.id), eq(securityFindingsTable.status, "OPEN"), inArray(securityFindingsTable.severity, ["CRITICAL", "HIGH"])))
    .groupBy(securityFindingsTable.deviceId);
  const attention = new Set(attentionRows.map((r) => r.deviceId));
  for (const d of active) if (!d.lastAssessmentAt || agentReliability(d, org, now) === "OFFLINE") attention.add(d.id);

  const names = await deviceNameMap(org.id);
  const latest = await db.select().from(assessmentsTable).where(eq(assessmentsTable.organizationId, org.id)).orderBy(desc(assessmentsTable.receivedAt)).limit(8);

  const vulns = await db
    .select({ confidence: vulnerabilityMatchesTable.matchConfidence, kev: vulnerabilityMatchesTable.knownExploited, deviceId: vulnerabilityMatchesTable.deviceId })
    .from(vulnerabilityMatchesTable)
    .where(and(eq(vulnerabilityMatchesTable.organizationId, org.id), eq(vulnerabilityMatchesTable.current, true)));

  const reliability = { HEALTHY: 0, DEGRADED: 0, OFFLINE: 0, REVOKED: 0, NEVER_REPORTED: 0 };
  for (const d of devices) reliability[agentReliability(d, org, now)]++;

  return {
    generatedAt: new Date().toISOString(),
    onlineThresholdMinutes: org.onlineThresholdMinutes,
    totalDevices: active.length,
    onlineDevices: online,
    offlineDevices: active.length - online,
    devicesRequiringAttention: attention.size,
    neverAssessedDevices: active.filter((d) => !d.lastAssessmentAt).length,
    openFindingsBySeverity: sev,
    latestAssessments: latest.map((a) => serializeAssessment(a, names.get(a.deviceId) ?? "unknown")),
    vulnerabilities: {
      total: vulns.length,
      knownExploited: vulns.filter((v) => v.kev).length,
      confirmed: vulns.filter((v) => v.confidence === "CONFIRMED").length,
      probable: vulns.filter((v) => v.confidence === "PROBABLE").length,
      possible: vulns.filter((v) => v.confidence === "POSSIBLE").length,
      affectedDevices: new Set(vulns.map((v) => v.deviceId)).size,
    },
    agentReliability: reliability,
  };
}

export async function dashboardActivity(org: Organization, limit: number) {
  const names = await deviceNameMap(org.id);
  const [hb, as, en, rq, rv] = await Promise.all([
    db.select().from(deviceHeartbeatsTable).where(eq(deviceHeartbeatsTable.organizationId, org.id)).orderBy(desc(deviceHeartbeatsTable.receivedAt)).limit(limit),
    db.select().from(assessmentsTable).where(eq(assessmentsTable.organizationId, org.id)).orderBy(desc(assessmentsTable.receivedAt)).limit(limit),
    db.select().from(deviceEnrollmentRequestsTable).where(eq(deviceEnrollmentRequestsTable.organizationId, org.id)).orderBy(desc(deviceEnrollmentRequestsTable.createdAt)).limit(limit),
    db.select().from(agentRequestsTable).where(eq(agentRequestsTable.organizationId, org.id)).orderBy(desc(agentRequestsTable.createdAt)).limit(limit),
    db.select().from(devicesTable).where(and(eq(devicesTable.organizationId, org.id), eq(devicesTable.status, "REVOKED"))).orderBy(desc(devicesTable.revokedAt)).limit(limit),
  ]);
  type Ev = { id: string; type: "HEARTBEAT" | "ASSESSMENT" | "ENROLLMENT" | "REQUEST" | "REVOCATION"; occurredAt: string; deviceId: string | null; deviceName: string | null; summary: string };
  const events: Ev[] = [];
  // Collapse heartbeats to the latest per device to avoid flooding the feed.
  const seenHb = new Set<string>();
  for (const h of hb) {
    if (seenHb.has(h.deviceId)) continue;
    seenHb.add(h.deviceId);
    events.push({ id: h.id, type: "HEARTBEAT", occurredAt: h.receivedAt.toISOString(), deviceId: h.deviceId, deviceName: names.get(h.deviceId) ?? null, summary: `Heartbeat received (agent ${h.agentVersion}${h.collectorErrors.length ? `, ${h.collectorErrors.length} collector error(s)` : ""})` });
  }
  for (const a of as) events.push({ id: a.id, type: "ASSESSMENT", occurredAt: a.receivedAt.toISOString(), deviceId: a.deviceId, deviceName: names.get(a.deviceId) ?? null, summary: `${a.trigger.toLowerCase()} assessment ${a.status.toLowerCase()} — coverage ${a.coveragePercent}%, risk ${a.riskScore ?? "n/a"}` });
  for (const e of en) events.push({ id: e.id, type: "ENROLLMENT", occurredAt: (e.consumedAt ?? e.createdAt).toISOString(), deviceId: e.deviceId, deviceName: e.deviceId ? names.get(e.deviceId) ?? null : null, summary: e.status === "CONSUMED" ? `Device enrolled (${e.osType})` : `Enrollment code ${e.status.toLowerCase()} (${e.osType}) by ${e.createdByEmail}` });
  for (const r of rq) events.push({ id: r.id, type: "REQUEST", occurredAt: r.createdAt.toISOString(), deviceId: r.deviceId, deviceName: names.get(r.deviceId) ?? null, summary: `Assessment requested by ${r.requestedByEmail} (${r.collectors.join(", ")}) — ${r.status.toLowerCase()}` });
  for (const d of rv) if (d.revokedAt) events.push({ id: `rev-${d.id}`, type: "REVOCATION", occurredAt: d.revokedAt.toISOString(), deviceId: d.id, deviceName: names.get(d.id) ?? null, summary: "Device access revoked" });
  return events.sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)).slice(0, limit);
}
