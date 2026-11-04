import { and, eq, inArray, notInArray, sql } from "drizzle-orm";
import {
  db,
  assessmentsTable,
  assessmentChecksTable,
  devicesTable,
  securityFindingsTable,
  softwareInventoryTable,
  startupItemsTable,
  threatDetectionsTable,
  vulnerabilityMatchesTable,
  agentRequestsTable,
  type Device,
} from "@workspace/db";
import type { AssessmentBody } from "../routes/agent/contract";
import {
  buildContext,
  computeCoverage,
  computeRiskScore,
  evaluateRules,
  type Severity,
} from "./rules";
import { matchDeviceSoftware } from "./vulnerabilities";
import { audit } from "../lib/audit";
import { logger } from "../lib/logger";

export function normalizeName(s: string | null | undefined): string {
  return (s ?? "")
    .toLowerCase()
    .replace(/\(.*?\)/g, " ")
    .replace(/\b(x64|x86|64-bit|32-bit|amd64|arm64|version|v?\d+(\.\d+)+)\b/g, " ")
    .replace(/[^a-z0-9+#. ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export interface IngestResult {
  assessmentId: string;
  duplicate: boolean;
  riskScore: number | null;
  coveragePercent: number;
  findingsOpened: number;
  findingsResolved: number;
}

/**
 * Ingests one assessment transactionally: stores checks/inventory, evaluates
 * rules, reconciles findings (auto-resolve ones no longer observed by a
 * collector that ran successfully), updates the device snapshot.
 */
export async function ingestAssessment(device: Device, body: AssessmentBody): Promise<IngestResult> {
  const existing = await db
    .select({ id: assessmentsTable.id, riskScore: assessmentsTable.riskScore, coveragePercent: assessmentsTable.coveragePercent })
    .from(assessmentsTable)
    .where(and(eq(assessmentsTable.deviceId, device.id), eq(assessmentsTable.idempotencyKey, body.idempotencyKey)));
  if (existing[0]) {
    return {
      assessmentId: existing[0].id,
      duplicate: true,
      riskScore: existing[0].riskScore,
      coveragePercent: existing[0].coveragePercent,
      findingsOpened: 0,
      findingsResolved: 0,
    };
  }

  const requested = body.collectors.map((c) => c.collectorId);
  const succeeded = body.collectors.filter((c) => c.status === "OK").map((c) => c.collectorId);
  const failed = body.collectors.filter((c) => c.status !== "OK").map((c) => c.collectorId);
  const coveragePercent = computeCoverage(body.collectors, requested.length);
  const status = failed.length === 0 ? "COMPLETE" : succeeded.length === 0 ? "FAILED" : "PARTIAL";

  const checkCounts: Record<string, number> = {
    PASS: 0, FAIL: 0, WARNING: 0, UNKNOWN: 0, UNSUPPORTED: 0, PERMISSION_DENIED: 0, STALE: 0,
  };
  for (const col of body.collectors) for (const ch of col.checks) checkCounts[ch.status] = (checkCounts[ch.status] ?? 0) + 1;

  const sysCol = body.collectors.find((c) => c.collectorId === "SYSTEM_INFO" && c.system);
  const avCol = body.collectors.find((c) => c.collectorId === "ANTIVIRUS_STATUS");
  const swCol = body.collectors.find((c) => c.collectorId === "SOFTWARE_INVENTORY" && c.status === "OK");
  const stCol = body.collectors.find((c) => c.collectorId === "STARTUP_INVENTORY" && c.status === "OK");

  const result = await db.transaction(async (tx) => {
    const [assessment] = await tx
      .insert(assessmentsTable)
      .values({
        organizationId: device.organizationId,
        deviceId: device.id,
        idempotencyKey: body.idempotencyKey,
        trigger: body.trigger,
        status,
        agentVersion: body.agentVersion,
        startedAt: new Date(body.startedAt),
        completedAt: new Date(body.completedAt),
        collectorsRequested: requested,
        collectorsSucceeded: succeeded,
        collectorsFailed: failed,
        coveragePercent,
        checkCounts,
        agentRequestId: body.agentRequestId ?? null,
      })
      .returning();
    const assessmentId = assessment!.id;

    // Checks
    const checkRows = body.collectors.flatMap((col) =>
      col.checks.map((ch) => ({
        organizationId: device.organizationId,
        deviceId: device.id,
        assessmentId,
        collectorId: col.collectorId,
        checkId: ch.checkId,
        category: ch.category,
        title: ch.title,
        status: ch.status,
        evidence: ch.evidence,
        collectedAt: new Date(col.collectedAt),
        dataSource: ch.dataSource,
        confidence: ch.confidence,
        requiredPermissions: ch.requiredPermissions,
        unavailableReason: ch.unavailableReason ?? null,
        collectorVersion: col.collectorVersion,
        details: ch.details ?? {},
      })),
    );
    if (checkRows.length) await tx.insert(assessmentChecksTable).values(checkRows);

    // Software inventory (replace current snapshot)
    let softwareIds: { id: string; normalizedName: string; normalizedVendor: string | null; version: string | null; name: string; vendor: string | null }[] = [];
    if (swCol?.software) {
      await tx
        .update(softwareInventoryTable)
        .set({ current: false })
        .where(and(eq(softwareInventoryTable.deviceId, device.id), eq(softwareInventoryTable.current, true)));
      if (swCol.software.length) {
        softwareIds = await tx
          .insert(softwareInventoryTable)
          .values(
            swCol.software.map((s) => ({
              organizationId: device.organizationId,
              deviceId: device.id,
              assessmentId,
              name: s.name,
              normalizedName: normalizeName(s.name),
              vendor: s.vendor ?? null,
              normalizedVendor: s.vendor ? normalizeName(s.vendor) : null,
              version: s.version ?? null,
              installedAt: s.installedAt ? new Date(s.installedAt) : null,
              source: s.source,
              collectedAt: new Date(swCol.collectedAt),
              current: true,
            })),
          )
          .returning({
            id: softwareInventoryTable.id,
            normalizedName: softwareInventoryTable.normalizedName,
            normalizedVendor: softwareInventoryTable.normalizedVendor,
            version: softwareInventoryTable.version,
            name: softwareInventoryTable.name,
            vendor: softwareInventoryTable.vendor,
          });
      }
    }

    if (stCol?.startupItems) {
      await tx
        .update(startupItemsTable)
        .set({ current: false })
        .where(and(eq(startupItemsTable.deviceId, device.id), eq(startupItemsTable.current, true)));
      if (stCol.startupItems.length) {
        await tx.insert(startupItemsTable).values(
          stCol.startupItems.map((s) => ({
            organizationId: device.organizationId,
            deviceId: device.id,
            assessmentId,
            name: s.name,
            location: s.location,
            kind: s.kind,
            enabled: s.enabled ?? null,
            publisher: s.publisher ?? null,
            collectedAt: new Date(stCol.collectedAt),
            current: true,
          })),
        );
      }
    }

    if (avCol?.threats?.length) {
      for (const t of avCol.threats) {
        const dup = t.externalId
          ? await tx
              .select({ id: threatDetectionsTable.id })
              .from(threatDetectionsTable)
              .where(and(eq(threatDetectionsTable.deviceId, device.id), eq(threatDetectionsTable.externalId, t.externalId)))
          : [];
        if (dup.length) continue;
        await tx.insert(threatDetectionsTable).values({
          organizationId: device.organizationId,
          deviceId: device.id,
          assessmentId,
          externalId: t.externalId ?? null,
          threatName: t.threatName,
          severity: t.severity ?? null,
          detectedAt: t.detectedAt ? new Date(t.detectedAt) : null,
          actionTaken: t.actionTaken ?? null,
          product: t.product,
          source: t.source,
          collectedAt: new Date(avCol.collectedAt),
        });
      }
    }

    // Rules
    const ctx = buildContext({ osType: device.osType, deviceName: device.name, assessmentId, collectors: body.collectors });
    const hits = evaluateRules(ctx);
    const now = new Date();
    const seenFingerprints = new Set<string>();
    let opened = 0;
    for (const hit of hits) {
      const fp = `${hit.rule.ruleId}:${hit.fingerprint}`;
      seenFingerprints.add(fp);
      const res = await tx
        .insert(securityFindingsTable)
        .values({
          organizationId: device.organizationId,
          deviceId: device.id,
          ruleId: hit.rule.ruleId,
          fingerprint: fp,
          title: hit.title,
          description: hit.rule.description,
          severity: hit.severity,
          confidence: hit.confidence,
          evidence: hit.evidence,
          detectionSource: hit.detectionSource,
          remediation: hit.rule.remediation,
          status: "OPEN",
          firstSeenAt: now,
          lastSeenAt: now,
          assessmentId,
          collectorId: hit.collectorId,
          rawStatus: hit.rawStatus,
          collectorVersion: hit.collectorVersion,
          observedAt: new Date(hit.observedAt),
        })
        .onConflictDoUpdate({
          target: [securityFindingsTable.deviceId, securityFindingsTable.fingerprint],
          set: {
            lastSeenAt: now,
            evidence: hit.evidence,
            severity: hit.severity,
            confidence: hit.confidence,
            assessmentId,
            rawStatus: hit.rawStatus,
            collectorVersion: hit.collectorVersion,
            observedAt: new Date(hit.observedAt),
            // A RESOLVED finding that is observed again re-opens; ACK/FP are preserved.
            status: sql`CASE WHEN ${securityFindingsTable.status} = 'RESOLVED' THEN 'OPEN'::finding_status ELSE ${securityFindingsTable.status} END`,
          },
        })
        .returning({ firstSeenAt: securityFindingsTable.firstSeenAt });
      if (res[0] && res[0].firstSeenAt.getTime() === now.getTime()) opened++;
    }

    // Auto-resolve findings whose collector ran OK this time but no longer fires.
    const okCollectors = succeeded;
    let resolved = 0;
    if (okCollectors.length) {
      const candidates = await tx
        .select({ id: securityFindingsTable.id, fingerprint: securityFindingsTable.fingerprint, collectorId: securityFindingsTable.collectorId, ruleId: securityFindingsTable.ruleId })
        .from(securityFindingsTable)
        .where(
          and(
            eq(securityFindingsTable.deviceId, device.id),
            inArray(securityFindingsTable.status, ["OPEN", "ACKNOWLEDGED"]),
            notInArray(securityFindingsTable.ruleId, ["VULN_KEV", "VULN_CRITICAL", "AGENT_OFFLINE"]),
          ),
        );
      const toResolve = candidates.filter(
        (c) => !seenFingerprints.has(c.fingerprint) && c.collectorId && (okCollectors as string[]).includes(c.collectorId),
      );
      if (toResolve.length) {
        await tx
          .update(securityFindingsTable)
          .set({ status: "RESOLVED", statusChangedAt: now, statusChangedByEmail: "system", statusNote: "No longer observed in a successful assessment." })
          .where(inArray(securityFindingsTable.id, toResolve.map((c) => c.id)));
        resolved = toResolve.length;
      }
    }

    // Device snapshot
    const sys = sysCol?.system;
    await tx
      .update(devicesTable)
      .set({
        ...(sys
          ? {
              name: sys.hostname || device.name,
              osName: sys.osName,
              osVersion: sys.osVersion,
              osBuild: sys.osBuild ?? null,
              architecture: sys.architecture,
              cpuModel: sys.cpuModel ?? null,
              totalRamMb: sys.totalRamMb ?? null,
              hardwareModel: sys.model ?? null,
              serialRedacted: sys.serialRedacted ?? null,
            }
          : {}),
        agentVersion: body.agentVersion,
        lastAssessmentAt: now,
        lastAssessmentId: assessmentId,
        lastSeenAt: now,
        coveragePercent,
      })
      .where(eq(devicesTable.id, device.id));

    if (body.agentRequestId) {
      await tx
        .update(agentRequestsTable)
        .set({ status: "COMPLETED", completedAt: now })
        .where(and(eq(agentRequestsTable.id, body.agentRequestId), eq(agentRequestsTable.deviceId, device.id)));
    }

    return { assessmentId, opened, resolved, softwareIds };
  });

  // Vulnerability matching runs outside the transaction (uses cached intel only; never blocks on network).
  if (swCol?.software) {
    try {
      await matchDeviceSoftware(device, result.softwareIds);
    } catch (err) {
      logger.error({ err, deviceId: device.id }, "vulnerability matching failed");
    }
  }

  const riskScore = await recomputeDeviceRisk(device.id, result.assessmentId, coveragePercent);

  await audit({
    organizationId: device.organizationId,
    actorType: "DEVICE",
    actorId: device.id,
    actorLabel: device.name,
    action: "assessment.received",
    targetType: "assessment",
    targetId: result.assessmentId,
    details: { trigger: body.trigger, status, coveragePercent, opened: result.opened, resolved: result.resolved },
  });

  return {
    assessmentId: result.assessmentId,
    duplicate: false,
    riskScore,
    coveragePercent,
    findingsOpened: result.opened,
    findingsResolved: result.resolved,
  };
}

export async function recomputeDeviceRisk(deviceId: string, assessmentId: string | null, coveragePercent: number) {
  const open = await db
    .select({ severity: securityFindingsTable.severity })
    .from(securityFindingsTable)
    .where(and(eq(securityFindingsTable.deviceId, deviceId), inArray(securityFindingsTable.status, ["OPEN", "ACKNOWLEDGED"])));
  const riskScore = computeRiskScore(open as { severity: Severity }[], coveragePercent);
  await db.update(devicesTable).set({ riskScore }).where(eq(devicesTable.id, deviceId));
  if (assessmentId) await db.update(assessmentsTable).set({ riskScore }).where(eq(assessmentsTable.id, assessmentId));
  return riskScore;
}
