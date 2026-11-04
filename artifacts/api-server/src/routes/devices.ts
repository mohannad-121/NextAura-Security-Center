import { Router, type IRouter } from "express";
import { and, desc, eq, gt, ilike, or, sql } from "drizzle-orm";
import {
  db,
  devicesTable,
  deviceCredentialsTable,
  assessmentsTable,
  assessmentChecksTable,
  softwareInventoryTable,
  startupItemsTable,
  threatDetectionsTable,
  vulnerabilityMatchesTable,
  agentRequestsTable,
  type Device,
} from "@workspace/db";
import { RequestDeviceAssessmentBody } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, requireRole, ctx } from "../middlewares/auth";
import { badRequest, notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import {
  agentReliability,
  compareVer,
  emptySeverity,
  iso,
  latestAssessmentFor,
  openFindingCountsByDevice,
  serializeAssessment,
  serializeDevice,
} from "../services/serializers";
import { riskLevelFor } from "../services/rules";

const router: IRouter = Router();
router.use(requireOrg);

async function loadDevice(req: Parameters<Parameters<typeof asyncHandler>[0]>[0]): Promise<Device> {
  const { organization } = ctx(req);
  const id = String(req.params["id"]);
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw notFound("Device not found");
  const [d] = await db.select().from(devicesTable).where(and(eq(devicesTable.id, id), eq(devicesTable.organizationId, organization.id)));
  if (!d) throw notFound("Device not found");
  return d;
}

router.get(
  "/devices",
  asyncHandler(async (req, res) => {
    const { organization } = ctx(req);
    const q = req.query as Record<string, string | undefined>;
    const conds = [eq(devicesTable.organizationId, organization.id)];
    if (q["includeRevoked"] !== "true") conds.push(eq(devicesTable.status, "ACTIVE"));
    if (q["osType"] === "WINDOWS" || q["osType"] === "MACOS") conds.push(eq(devicesTable.osType, q["osType"]));
    if (q["search"]) {
      const s = `%${q["search"].replace(/[%_]/g, "")}%`;
      conds.push(or(ilike(devicesTable.name, s), ilike(devicesTable.label, s), ilike(devicesTable.osName, s), ilike(devicesTable.osVersion, s))!);
    }
    if (q["lastAssessmentAfter"]) {
      const d = new Date(q["lastAssessmentAfter"]);
      if (Number.isNaN(d.getTime())) throw badRequest("lastAssessmentAfter must be an ISO date");
      conds.push(gt(devicesTable.lastAssessmentAt, d));
    }
    const rows = await db.select().from(devicesTable).where(and(...conds)).orderBy(desc(devicesTable.lastSeenAt));
    const open = await openFindingCountsByDevice(rows.map((r) => r.id));
    let out = rows.map((d) => serializeDevice(d, organization, open.get(d.id) ?? emptySeverity()));
    if (q["online"] === "true") out = out.filter((d) => d.isOnline);
    if (q["online"] === "false") out = out.filter((d) => !d.isOnline);
    if (q["riskLevel"]) out = out.filter((d) => d.riskLevel === q["riskLevel"]);
    res.json(out);
  }),
);

router.get(
  "/devices/:id",
  asyncHandler(async (req, res) => {
    const { organization } = ctx(req);
    const device = await loadDevice(req);
    const open = await openFindingCountsByDevice([device.id]);
    const base = serializeDevice(device, organization, open.get(device.id) ?? emptySeverity());
    const latest = await latestAssessmentFor(device.id);
    const checks = latest ? await db.select().from(assessmentChecksTable).where(eq(assessmentChecksTable.assessmentId, latest.id)) : [];
    const osSupport = checks.find((c) => c.checkId === "OS_SUPPORT");
    const avRealtime = checks.find((c) => c.checkId === "AV_REALTIME");
    const avProductCheck = checks.find((c) => c.checkId === "AV_PRODUCT");
    const avDefs = checks.find((c) => c.checkId === "AV_DEFINITIONS");
    const avDetails = (avProductCheck?.details ?? {}) as Record<string, unknown>;
    const antivirusStatus = (typeof avDetails["status"] === "string" ? avDetails["status"] : latest ? "UNKNOWN" : "UNKNOWN") as
      | "ACTIVE" | "DISABLED" | "PASSIVE" | "THIRD_PARTY" | "UNKNOWN" | "UNSUPPORTED" | "PERMISSION_DENIED";
    const unknownCount = checks.filter((c) => c.status === "UNKNOWN" || c.status === "UNSUPPORTED" || c.status === "PERMISSION_DENIED").length;
    const failedCount = checks.filter((c) => c.status === "FAIL").length;
    res.json({
      ...base,
      hardware: { cpuModel: device.cpuModel, totalRamMb: device.totalRamMb, model: device.hardwareModel, serialRedacted: device.serialRedacted },
      operatingSystem: {
        name: device.osName,
        version: device.osVersion,
        build: device.osBuild,
        architecture: device.architecture,
        supportStatus: osSupport?.status ?? "UNKNOWN",
        supportEvidence: osSupport?.evidence ?? "OS support status has not been collected yet.",
      },
      antivirus: {
        product: typeof avDetails["product"] === "string" ? avDetails["product"] : null,
        status: antivirusStatus,
        realTimeProtection: avRealtime?.status ?? "UNKNOWN",
        definitionsAgeDays: typeof (avDefs?.details as Record<string, unknown> | undefined)?.["ageDays"] === "number" ? ((avDefs!.details as Record<string, number>)["ageDays"] as number) : null,
        lastDefinitionUpdate: typeof (avDefs?.details as Record<string, unknown> | undefined)?.["lastUpdate"] === "string" ? ((avDefs!.details as Record<string, string>)["lastUpdate"] as string) : null,
        source: avProductCheck?.dataSource ?? null,
        note: avProductCheck?.evidence ?? (latest ? "Antivirus collector did not report." : "No assessment received yet."),
      },
      agentHealth: {
        reliability: agentReliability(device, organization),
        lastHeartbeatAt: iso(device.lastSeenAt),
        heartbeatIntervalMinutes: organization.heartbeatIntervalMinutes,
        consecutiveMissedHeartbeats: device.lastSeenAt ? Math.max(0, Math.floor((Date.now() - device.lastSeenAt.getTime()) / (organization.heartbeatIntervalMinutes * 60_000)) - 1) : 0,
        lastCollectorErrors: device.lastCollectorErrors,
        agentVersion: device.agentVersion,
        supportedVersion: compareVer(device.agentVersion || "0", organization.minimumAgentVersion) >= 0,
      },
      latestAssessment: latest ? serializeAssessment(latest, base.name) : null,
      unknownCheckCount: unknownCount,
      failedCheckCount: failedCount,
      riskLevel: riskLevelFor(device.riskScore, device.coveragePercent),
    });
  }),
);

router.get(
  "/devices/:id/checks",
  asyncHandler(async (req, res) => {
    const device = await loadDevice(req);
    const latest = await latestAssessmentFor(device.id);
    const checks = latest ? await db.select().from(assessmentChecksTable).where(eq(assessmentChecksTable.assessmentId, latest.id)) : [];
    res.json(
      checks.map((c) => ({
        id: c.id,
        assessmentId: c.assessmentId,
        collectorId: c.collectorId,
        checkId: c.checkId,
        category: c.category,
        title: c.title,
        status: c.status,
        evidence: c.evidence,
        collectedAt: c.collectedAt.toISOString(),
        dataSource: c.dataSource,
        confidence: c.confidence,
        requiredPermissions: c.requiredPermissions,
        unavailableReason: c.unavailableReason,
        collectorVersion: c.collectorVersion,
      })),
    );
  }),
);

router.get(
  "/devices/:id/software",
  asyncHandler(async (req, res) => {
    const device = await loadDevice(req);
    const rows = await db
      .select({
        s: softwareInventoryTable,
        vulns: sql<number>`(select count(*)::int from vulnerability_matches v where v.software_id = ${softwareInventoryTable.id} and v.current = true)`,
      })
      .from(softwareInventoryTable)
      .where(and(eq(softwareInventoryTable.deviceId, device.id), eq(softwareInventoryTable.current, true)))
      .orderBy(softwareInventoryTable.name);
    res.json(rows.map(({ s, vulns }) => ({ id: s.id, name: s.name, vendor: s.vendor, version: s.version, installedAt: iso(s.installedAt), source: s.source, collectedAt: s.collectedAt.toISOString(), vulnerabilityCount: vulns })));
  }),
);

router.get(
  "/devices/:id/startup",
  asyncHandler(async (req, res) => {
    const device = await loadDevice(req);
    const rows = await db.select().from(startupItemsTable).where(and(eq(startupItemsTable.deviceId, device.id), eq(startupItemsTable.current, true))).orderBy(startupItemsTable.kind, startupItemsTable.name);
    res.json(rows.map((s) => ({ id: s.id, name: s.name, location: s.location, kind: s.kind, enabled: s.enabled, publisher: s.publisher, collectedAt: s.collectedAt.toISOString() })));
  }),
);

router.get(
  "/devices/:id/threats",
  asyncHandler(async (req, res) => {
    const device = await loadDevice(req);
    const rows = await db.select().from(threatDetectionsTable).where(eq(threatDetectionsTable.deviceId, device.id)).orderBy(desc(threatDetectionsTable.detectedAt));
    res.json(rows.map((t) => ({ id: t.id, threatName: t.threatName, severity: t.severity, detectedAt: iso(t.detectedAt), actionTaken: t.actionTaken, product: t.product, source: t.source, collectedAt: t.collectedAt.toISOString() })));
  }),
);

router.get(
  "/devices/:id/assessments",
  asyncHandler(async (req, res) => {
    const device = await loadDevice(req);
    const rows = await db.select().from(assessmentsTable).where(eq(assessmentsTable.deviceId, device.id)).orderBy(desc(assessmentsTable.receivedAt)).limit(50);
    res.json(rows.map((a) => serializeAssessment(a, device.name)));
  }),
);

function serializeRequest(r: typeof agentRequestsTable.$inferSelect) {
  return { id: r.id, deviceId: r.deviceId, collectors: r.collectors, status: r.status, requestedByEmail: r.requestedByEmail, createdAt: r.createdAt.toISOString(), expiresAt: r.expiresAt.toISOString(), deliveredAt: iso(r.deliveredAt), acknowledgedAt: iso(r.acknowledgedAt) };
}

router.get(
  "/devices/:id/assessment-requests",
  asyncHandler(async (req, res) => {
    const device = await loadDevice(req);
    const rows = await db.select().from(agentRequestsTable).where(eq(agentRequestsTable.deviceId, device.id)).orderBy(desc(agentRequestsTable.createdAt)).limit(20);
    res.json(rows.map(serializeRequest));
  }),
);

router.post(
  "/devices/:id/assessment-requests",
  requireRole("SECURITY_ANALYST"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const device = await loadDevice(req);
    if (device.status === "REVOKED") throw badRequest("Device is revoked");
    const body = RequestDeviceAssessmentBody.parse(req.body);
    const collectors = Array.from(new Set(body.collectors));
    if (!collectors.length) throw badRequest("Select at least one collector");
    const [pending] = await db
      .select({ id: agentRequestsTable.id })
      .from(agentRequestsTable)
      .where(and(eq(agentRequestsTable.deviceId, device.id), or(eq(agentRequestsTable.status, "PENDING"), eq(agentRequestsTable.status, "DELIVERED"), eq(agentRequestsTable.status, "ACKNOWLEDGED")), gt(agentRequestsTable.expiresAt, new Date())));
    if (pending) throw badRequest("An assessment request is already pending for this device");
    const [r] = await db
      .insert(agentRequestsTable)
      .values({ organizationId: a.organization.id, deviceId: device.id, collectors, requestedByUserId: a.userId, requestedByEmail: a.email, expiresAt: new Date(Date.now() + 24 * 3600_000) })
      .returning();
    await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "assessment.requested", targetType: "device", targetId: device.id, details: { collectors }, ipAddress: req.ip });
    res.status(201).json(serializeRequest(r!));
  }),
);

router.post(
  "/devices/:id/revoke",
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const device = await loadDevice(req);
    const now = new Date();
    await db.transaction(async (tx) => {
      await tx.update(devicesTable).set({ status: "REVOKED", revokedAt: now }).where(eq(devicesTable.id, device.id));
      await tx.update(deviceCredentialsTable).set({ revokedAt: now }).where(eq(deviceCredentialsTable.deviceId, device.id));
      await tx.update(agentRequestsTable).set({ status: "EXPIRED" }).where(and(eq(agentRequestsTable.deviceId, device.id), eq(agentRequestsTable.status, "PENDING")));
    });
    await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "device.revoked", targetType: "device", targetId: device.id, ipAddress: req.ip });
    const [updated] = await db.select().from(devicesTable).where(eq(devicesTable.id, device.id));
    const open = await openFindingCountsByDevice([device.id]);
    res.json(serializeDevice(updated!, a.organization, open.get(device.id) ?? emptySeverity()));
  }),
);

export default router;
