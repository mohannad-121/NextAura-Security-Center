/**
 * Agent API — /api/agent/v1
 * Auth: `Authorization: Bearer <device token>` (hash compared server-side).
 * Enrollment is the only unauthenticated endpoint and is rate-limited per IP.
 */
import {
  Router,
  type IRouter,
  type Request,
  type RequestHandler,
} from "express";
import {
  and,
  desc,
  eq,
  gt,
  inArray,
  isNull,
  lt,
  notInArray,
  or,
} from "drizzle-orm";
import {
  db,
  devicesTable,
  deviceCredentialsTable,
  deviceEnrollmentRequestsTable,
  deviceHeartbeatsTable,
  agentRequestsTable,
  agentRequestReplayTable,
  deviceScanScopesTable,
  scanFileEvidenceTable,
  scanJobDevicesTable,
  securityFindingsTable,
  assessmentsTable,
  organizationsTable,
  type Device,
  type Organization,
} from "@workspace/db";
import { asyncHandler } from "../../lib/asyncHandler";
import {
  badRequest,
  conflict,
  forbidden,
  unauthorized,
} from "../../lib/errors";
import { rateLimit } from "../../lib/rateLimit";
import {
  normalizeEnrollmentCode,
  randomToken,
  sha256Hex,
} from "../../lib/crypto";
import { audit } from "../../lib/audit";
import { ingestAssessment } from "../../services/assessments";
import { markTargetByRequest } from "../../services/scanJobs";
import {
  ackBodySchema,
  assessmentBodySchema,
  enrollBodySchema,
  fileEvidenceBodySchema,
  heartbeatBodySchema,
  AGENT_API_VERSION,
  DEVICE_TOKEN_PREFIX,
  DEVICE_TOKEN_TTL_DAYS,
} from "./contract";
import { enrollmentState } from "./enrollmentState";

const router: IRouter = Router();

interface DeviceAuth {
  device: Device;
  org: Organization;
  credentialId: string;
}

const ipKey = (req: Request) => req.ip ?? "unknown";

router.use((_req, res, next) => {
  res.setHeader("X-NextAura-Agent-API", AGENT_API_VERSION);
  next();
});

const requireDevice: RequestHandler = asyncHandler(async (req, _res, next) => {
  const header = req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token || !token.startsWith(DEVICE_TOKEN_PREFIX))
    throw unauthorized("Device token required");
  const hash = sha256Hex(token);
  const [row] = await db
    .select({
      cred: deviceCredentialsTable,
      device: devicesTable,
      org: organizationsTable,
    })
    .from(deviceCredentialsTable)
    .innerJoin(
      devicesTable,
      eq(devicesTable.id, deviceCredentialsTable.deviceId),
    )
    .innerJoin(
      organizationsTable,
      eq(organizationsTable.id, devicesTable.organizationId),
    )
    .where(eq(deviceCredentialsTable.tokenHash, hash));
  if (!row) throw unauthorized("Unknown device token");
  if (row.cred.revokedAt || row.device.status === "REVOKED")
    throw forbidden("Device access has been revoked");
  if (row.cred.expiresAt.getTime() < Date.now())
    throw unauthorized("Device token expired; re-enroll");
  await db
    .update(deviceCredentialsTable)
    .set({ lastUsedAt: new Date() })
    .where(eq(deviceCredentialsTable.id, row.cred.id));
  req.deviceAuth = {
    device: row.device,
    org: row.org,
    credentialId: row.cred.id,
  };
  next();
});

function agentConfig(org: Organization) {
  return {
    heartbeatIntervalMinutes: org.heartbeatIntervalMinutes,
    postureIntervalHours: org.postureIntervalHours,
    inventoryIntervalHours: org.inventoryIntervalHours,
    minimumAgentVersion: org.minimumAgentVersion,
  };
}

// ---------------------------------------------------------------------------
// POST /enroll
// ---------------------------------------------------------------------------
router.post(
  "/enroll",
  rateLimit({ windowMs: 10 * 60_000, max: 10, key: ipKey }),
  asyncHandler(async (req, res) => {
    const body = enrollBodySchema.parse(req.body);
    const codeHash = sha256Hex(normalizeEnrollmentCode(body.code));
    const [enr] = await db
      .select()
      .from(deviceEnrollmentRequestsTable)
      .where(eq(deviceEnrollmentRequestsTable.codeHash, codeHash));
    if (!enr) {
      // Constant-ish response regardless of why.
      throw unauthorized("Enrollment code is invalid or expired");
    }
    const state = enrollmentState(enr);
    if (state !== "VALID") {
      await db
        .update(deviceEnrollmentRequestsTable)
        .set({
          attemptCount: enr.attemptCount + 1,
          ...(state === "EXPIRED" && enr.status === "PENDING"
            ? { status: "EXPIRED" as const }
            : {}),
        })
        .where(eq(deviceEnrollmentRequestsTable.id, enr.id));
      throw unauthorized("Enrollment code is invalid or expired");
    }
    if (enr.osType !== body.osType)
      throw badRequest(
        `This code was issued for ${enr.osType}, but the agent reports ${body.osType}`,
      );
    const [org] = await db
      .select()
      .from(organizationsTable)
      .where(eq(organizationsTable.id, enr.organizationId));
    if (!org) throw unauthorized("Enrollment code is invalid or expired");
    if (!org.allowedOsTypes.includes(body.osType))
      throw forbidden(
        `${body.osType} devices are not allowed by organization policy`,
      );

    const token = DEVICE_TOKEN_PREFIX + randomToken(32);
    const expiresAt = new Date(Date.now() + DEVICE_TOKEN_TTL_DAYS * 86400_000);
    const result = await db.transaction(async (tx) => {
      const claimed = await tx
        .update(deviceEnrollmentRequestsTable)
        .set({ status: "CONSUMED", consumedAt: new Date() })
        .where(
          and(
            eq(deviceEnrollmentRequestsTable.id, enr.id),
            eq(deviceEnrollmentRequestsTable.status, "PENDING"),
          ),
        )
        .returning({ id: deviceEnrollmentRequestsTable.id });
      if (!claimed.length) throw conflict("Enrollment code was already used");
      const [device] = await tx
        .insert(devicesTable)
        .values({
          organizationId: org.id,
          name: body.system.hostname,
          label: enr.deviceLabel,
          osType: body.osType,
          osName: body.system.osName,
          osVersion: body.system.osVersion,
          osBuild: body.system.osBuild ?? null,
          architecture: body.system.architecture,
          cpuModel: body.system.cpuModel ?? null,
          totalRamMb: body.system.totalRamMb ?? null,
          hardwareModel: body.system.model ?? null,
          serialRedacted: body.system.serialRedacted ?? null,
          agentVersion: body.agentVersion,
          lastSeenAt: new Date(),
        })
        .returning();
      await tx.insert(deviceCredentialsTable).values({
        organizationId: org.id,
        deviceId: device!.id,
        tokenHash: sha256Hex(token),
        tokenPrefix: token.slice(0, 10),
        expiresAt,
      });
      await tx
        .update(deviceEnrollmentRequestsTable)
        .set({ deviceId: device!.id })
        .where(eq(deviceEnrollmentRequestsTable.id, enr.id));
      return device!;
    });
    await audit({
      organizationId: org.id,
      actorType: "DEVICE",
      actorId: result.id,
      actorLabel: result.name,
      action: "device.enrolled",
      targetType: "device",
      targetId: result.id,
      details: {
        osType: body.osType,
        agentVersion: body.agentVersion,
        enrollmentId: enr.id,
      },
      ipAddress: req.ip,
    });
    res.status(201).json({
      deviceId: result.id,
      deviceToken: token,
      tokenExpiresAt: expiresAt.toISOString(),
      organizationName: org.name,
      config: agentConfig(org),
      serverTime: new Date().toISOString(),
    });
  }),
);

// ---------------------------------------------------------------------------
// Authenticated endpoints
// ---------------------------------------------------------------------------
router.use(requireDevice);
router.use(
  rateLimit({
    windowMs: 60_000,
    max: 60,
    key: (req) => req.deviceAuth?.device.id ?? ipKey(req),
  }),
);

async function replaySeen(
  deviceId: string,
  requestId: string,
): Promise<boolean> {
  const inserted = await db
    .insert(agentRequestReplayTable)
    .values({ deviceId, requestId })
    .onConflictDoNothing()
    .returning({ requestId: agentRequestReplayTable.requestId });
  return inserted.length === 0;
}

router.post(
  "/heartbeat",
  asyncHandler(async (req, res) => {
    const { device, org } = req.deviceAuth!;
    const body = heartbeatBodySchema.parse(req.body);
    const skew = Math.abs(Date.now() - new Date(body.timestamp).getTime());
    if (skew > 15 * 60_000)
      throw badRequest("Agent clock skew exceeds 15 minutes");
    if (await replaySeen(device.id, `hb:${body.requestId}`)) {
      res.json({
        ok: true,
        duplicate: true,
        serverTime: new Date().toISOString(),
        config: agentConfig(org),
        pendingRequests: 0,
      });
      return;
    }
    await db.insert(deviceHeartbeatsTable).values({
      organizationId: org.id,
      deviceId: device.id,
      agentVersion: body.agentVersion,
      agentTimestamp: new Date(body.timestamp),
      uptimeSeconds: body.uptimeSeconds ?? null,
      collectorErrors: body.collectorErrors,
      requestId: body.requestId,
    });
    await db
      .update(devicesTable)
      .set({
        lastSeenAt: new Date(),
        agentVersion: body.agentVersion,
        lastCollectorErrors: body.collectorErrors,
        consecutiveMissedHeartbeats: 0,
      })
      .where(eq(devicesTable.id, device.id));
    if (body.scanScopes !== undefined) {
      const reportedIds = body.scanScopes.map((scope) => scope.id);
      await db.transaction(async (tx) => {
        for (const scope of body.scanScopes ?? []) {
          await tx
            .insert(deviceScanScopesTable)
            .values({
              organizationId: org.id,
              deviceId: device.id,
              scopeId: scope.id,
              label: scope.label,
              enabled: scope.enabled,
              revokedAt: scope.enabled ? null : new Date(),
              lastReportedAt: new Date(),
            })
            .onConflictDoUpdate({
              target: [
                deviceScanScopesTable.deviceId,
                deviceScanScopesTable.scopeId,
              ],
              set: {
                label: scope.label,
                enabled: scope.enabled,
                revokedAt: scope.enabled ? null : new Date(),
                lastReportedAt: new Date(),
              },
            });
        }
        const missingPredicate = reportedIds.length
          ? and(
              eq(deviceScanScopesTable.deviceId, device.id),
              notInArray(deviceScanScopesTable.scopeId, reportedIds),
            )
          : eq(deviceScanScopesTable.deviceId, device.id);
        await tx
          .update(deviceScanScopesTable)
          .set({ enabled: false, revokedAt: new Date() })
          .where(missingPredicate);
      });
    }
    const pending = await db
      .select({ id: agentRequestsTable.id })
      .from(agentRequestsTable)
      .where(
        and(
          eq(agentRequestsTable.deviceId, device.id),
          eq(agentRequestsTable.status, "PENDING"),
          gt(agentRequestsTable.expiresAt, new Date()),
        ),
      );
    res.json({
      ok: true,
      duplicate: false,
      serverTime: new Date().toISOString(),
      config: agentConfig(org),
      pendingRequests: pending.length,
    });
  }),
);

router.get(
  "/requests",
  asyncHandler(async (req, res) => {
    const { device } = req.deviceAuth!;
    const now = new Date();
    const expiring = await db
      .select({ id: agentRequestsTable.id })
      .from(agentRequestsTable)
      .where(
        and(
          eq(agentRequestsTable.deviceId, device.id),
          or(
            eq(agentRequestsTable.status, "PENDING"),
            eq(agentRequestsTable.status, "DELIVERED"),
          ),
          lt(agentRequestsTable.expiresAt, now),
        ),
      );
    await db
      .update(agentRequestsTable)
      .set({ status: "EXPIRED" })
      .where(
        and(
          eq(agentRequestsTable.deviceId, device.id),
          or(
            eq(agentRequestsTable.status, "PENDING"),
            eq(agentRequestsTable.status, "DELIVERED"),
          ),
          lt(agentRequestsTable.expiresAt, now),
        ),
      );
    for (const request of expiring) {
      await markTargetByRequest(request.id, {
        status: "EXPIRED",
        stage: "Expired before agent execution",
        completedAt: now,
      });
    }
    const rows = await db
      .select()
      .from(agentRequestsTable)
      .where(
        and(
          eq(agentRequestsTable.deviceId, device.id),
          or(
            eq(agentRequestsTable.status, "PENDING"),
            eq(agentRequestsTable.status, "DELIVERED"),
          ),
          isNull(agentRequestsTable.completedAt),
        ),
      )
      .orderBy(desc(agentRequestsTable.createdAt));
    const ids = rows.filter((r) => r.status === "PENDING").map((r) => r.id);
    for (const id of ids)
      await db
        .update(agentRequestsTable)
        .set({ status: "DELIVERED", deliveredAt: now })
        .where(eq(agentRequestsTable.id, id));
    for (const row of rows) {
      if (row.status === "PENDING") {
        await markTargetByRequest(row.id, {
          status: "WAITING_FOR_AGENT",
          stage: "Delivered to agent",
          deliveredAt: now,
        });
      }
    }
    res.json({
      requests: rows.map((r) => ({
        id: r.id,
        operation: r.operation,
        collectors: r.collectors,
        scopeId: r.scopeId,
        createdAt: r.createdAt.toISOString(),
        expiresAt: r.expiresAt.toISOString(),
      })),
      serverTime: now.toISOString(),
    });
  }),
);

router.post(
  "/requests/ack",
  asyncHandler(async (req, res) => {
    const { device } = req.deviceAuth!;
    const body = ackBodySchema.parse(req.body);
    const [r] = await db
      .select()
      .from(agentRequestsTable)
      .where(
        and(
          eq(agentRequestsTable.id, body.requestId),
          eq(agentRequestsTable.deviceId, device.id),
        ),
      );
    if (!r) throw badRequest("Unknown request");
    if (r.status === "COMPLETED" || r.status === "EXPIRED") {
      res.json({ ok: true, status: r.status });
      return;
    }
    await db
      .update(agentRequestsTable)
      .set(
        body.status === "ACKNOWLEDGED"
          ? { status: "ACKNOWLEDGED", acknowledgedAt: new Date() }
          : {
              status: "REJECTED",
              rejectionReason: body.reason ?? "rejected by agent",
              acknowledgedAt: new Date(),
            },
      )
      .where(eq(agentRequestsTable.id, r.id));
    await markTargetByRequest(
      r.id,
      body.status === "ACKNOWLEDGED"
        ? {
            status: "RUNNING",
            stage:
              r.operation === "FILE_SCOPE_SCAN"
                ? "Analyzing approved scope"
                : "Running collectors",
            startedAt: new Date(),
          }
        : {
            status: "FAILED",
            stage: "Rejected by agent",
            error: body.reason ?? "rejected by agent",
            completedAt: new Date(),
          },
    );
    res.json({ ok: true, status: body.status });
  }),
);

router.post(
  "/assessments",
  asyncHandler(async (req, res) => {
    const { device } = req.deviceAuth!;
    const body = assessmentBodySchema.parse(req.body);
    const ids = new Set(body.collectors.map((c) => c.collectorId));
    if (ids.size !== body.collectors.length)
      throw badRequest("Duplicate collector in payload");
    if (new Date(body.completedAt) < new Date(body.startedAt))
      throw badRequest("completedAt precedes startedAt");
    if (body.agentRequestId) {
      const [request] = await db
        .select()
        .from(agentRequestsTable)
        .where(
          and(
            eq(agentRequestsTable.id, body.agentRequestId),
            eq(agentRequestsTable.deviceId, device.id),
          ),
        );
      if (!request || request.operation !== "ASSESSMENT")
        throw badRequest("Unknown assessment request");
      if (request.status === "EXPIRED" || request.status === "REJECTED")
        throw badRequest("Assessment request is no longer active");
      if (request.status === "COMPLETED") {
        const [existing] = await db
          .select({ id: assessmentsTable.id })
          .from(assessmentsTable)
          .where(
            and(
              eq(assessmentsTable.deviceId, device.id),
              eq(assessmentsTable.agentRequestId, request.id),
              eq(assessmentsTable.idempotencyKey, body.idempotencyKey),
            ),
          );
        if (!existing)
          throw badRequest("Assessment request is already completed");
      }
      const requested = new Set(request.collectors);
      if (
        body.collectors.some(
          (collector) => !requested.has(collector.collectorId),
        )
      )
        throw badRequest(
          "Assessment contains a collector that was not requested",
        );
    }
    const result = await ingestAssessment(device, body);
    if (body.agentRequestId) {
      const succeeded = body.collectors.filter(
        (collector) => collector.status === "OK",
      ).length;
      const status =
        succeeded === body.collectors.length
          ? "COMPLETED"
          : succeeded > 0
            ? "PARTIAL"
            : "FAILED";
      await markTargetByRequest(body.agentRequestId, {
        status,
        stage:
          status === "COMPLETED"
            ? "Assessment complete"
            : "Assessment completed with collector gaps",
        collectorFailures: body.collectors
          .filter((collector) => collector.status !== "OK")
          .map((collector) => ({
            collectorId: collector.collectorId,
            reason: collector.error ?? collector.status,
          })),
        completedAt: new Date(),
      });
    }
    res.status(result.duplicate ? 200 : 201).json({
      ok: true,
      assessmentId: result.assessmentId,
      duplicate: result.duplicate,
      riskScore: result.riskScore,
      coveragePercent: result.coveragePercent,
      findingsOpened: result.findingsOpened,
      findingsResolved: result.findingsResolved,
      serverTime: new Date().toISOString(),
    });
  }),
);

router.post(
  "/file-evidence",
  asyncHandler(async (req, res) => {
    const { device, org } = req.deviceAuth!;
    const body = fileEvidenceBodySchema.parse(req.body);
    const [request] = await db
      .select()
      .from(agentRequestsTable)
      .where(
        and(
          eq(agentRequestsTable.id, body.agentRequestId),
          eq(agentRequestsTable.deviceId, device.id),
        ),
      );
    if (
      !request ||
      request.operation !== "FILE_SCOPE_SCAN" ||
      !request.scanJobId
    )
      throw badRequest("Unknown file assessment request");
    if (request.scopeId !== body.scopeId)
      throw badRequest("Scope ID does not match the request");
    if (request.status === "EXPIRED" || request.status === "REJECTED")
      throw badRequest("File assessment request is no longer active");
    const replayKey = `file:${body.idempotencyKey}`;
    if (request.status === "COMPLETED") {
      const [existingReplay] = await db
        .select({ requestId: agentRequestReplayTable.requestId })
        .from(agentRequestReplayTable)
        .where(
          and(
            eq(agentRequestReplayTable.deviceId, device.id),
            eq(agentRequestReplayTable.requestId, replayKey),
          ),
        );
      if (existingReplay) {
        res.json({ ok: true, duplicate: true, accepted: 0 });
        return;
      }
      throw badRequest("File assessment request is already completed");
    }
    if (request.status !== "ACKNOWLEDGED")
      throw badRequest("File assessment request was not acknowledged");
    const ingestion = await db.transaction(async (tx) => {
      const replay = await tx
        .insert(agentRequestReplayTable)
        .values({ deviceId: device.id, requestId: replayKey })
        .onConflictDoNothing()
        .returning({ requestId: agentRequestReplayTable.requestId });
      if (!replay.length) return { duplicate: true };
      if (body.evidence.length) {
        await tx
          .insert(scanFileEvidenceTable)
          .values(
            body.evidence.map((item) => ({
              organizationId: org.id,
              deviceId: device.id,
              scanJobId: request.scanJobId!,
              agentRequestId: request.id,
              evidenceKey: item.evidenceKey,
              fileName: item.result.fileName,
              relativePathHash: item.relativePathHash,
              sha256: item.result.sha256,
              sizeBytes: item.result.sizeBytes,
              detectedType: item.result.detectedType,
              classification: item.result.classification,
              severity: item.severity,
              confidence: item.confidence,
              detectorId: item.detectorId,
              detectorVersion: item.detectorVersion,
              evidenceSource: item.evidenceSource,
              signatureMetadata: item.result.signatureMetadata,
              indicators: item.result.indicators,
              archiveSummary: item.result.archive ?? null,
              peMetadata: item.result.pe ?? null,
              limitations: [...item.result.limitations, ...body.limitations],
              observedAt: new Date(item.observedAt),
            })),
          )
          .onConflictDoNothing();
        for (const item of body.evidence.filter((entry) =>
          ["CONFIRMED_DETECTION", "SUSPICIOUS_INDICATOR"].includes(
            entry.result.classification,
          ),
        )) {
          const fingerprint = `STATIC_FILE:${item.result.sha256}`;
          const evidence = `${item.result.classification}: ${item.result.fileName} (${item.result.detectedType}) SHA-256 ${item.result.sha256}; detector ${item.detectorId} ${item.detectorVersion}. File content and plaintext path were not uploaded.`;
          await tx
            .insert(securityFindingsTable)
            .values({
              organizationId: org.id,
              deviceId: device.id,
              ruleId: "STATIC_FILE_EVIDENCE",
              fingerprint,
              title: `Suspicious file evidence: ${item.result.fileName}`,
              description:
                "Authenticated bounded static analysis reported suspicious or confirmed file metadata in a locally approved scope.",
              severity: item.severity,
              confidence: item.confidence,
              evidence,
              detectionSource: item.detectorId,
              remediation:
                "Preserve the original without opening it, validate the hash and signer with approved tools, and correlate the device evidence in an incident. NextAura does not quarantine or delete it.",
              collectorId: item.detectorId,
              rawStatus: item.result.classification,
              collectorVersion: item.detectorVersion,
              observedAt: new Date(item.observedAt),
            })
            .onConflictDoUpdate({
              target: [
                securityFindingsTable.deviceId,
                securityFindingsTable.fingerprint,
              ],
              set: {
                severity: item.severity,
                confidence: item.confidence,
                evidence,
                lastSeenAt: new Date(),
                observedAt: new Date(item.observedAt),
              },
            });
        }
      }
      await tx
        .update(agentRequestsTable)
        .set({ status: "COMPLETED", completedAt: new Date() })
        .where(eq(agentRequestsTable.id, request.id));
      await tx
        .update(scanJobDevicesTable)
        .set({
          status: body.partial ? "PARTIAL" : "COMPLETED",
          stage: body.partial
            ? "Completed with visibility gaps"
            : "File assessment complete",
          filesObserved: body.filesObserved,
          evidenceCount: body.evidence.length,
          completedAt: new Date(),
        })
        .where(eq(scanJobDevicesTable.agentRequestId, request.id));
      return { duplicate: false };
    });
    if (ingestion.duplicate) {
      res.json({ ok: true, duplicate: true, accepted: 0 });
      return;
    }
    await markTargetByRequest(request.id, {});
    await audit({
      organizationId: org.id,
      actorType: "DEVICE",
      actorId: device.id,
      actorLabel: device.name,
      action: "scan.file_evidence_received",
      targetType: "scan_job",
      targetId: request.scanJobId,
      details: {
        accepted: body.evidence.length,
        filesObserved: body.filesObserved,
        partial: body.partial,
      },
    });
    res
      .status(201)
      .json({ ok: true, duplicate: false, accepted: body.evidence.length });
  }),
);

router.get(
  "/config",
  asyncHandler(async (req, res) => {
    const { org, device } = req.deviceAuth!;
    res.json({
      deviceId: device.id,
      organizationName: org.name,
      config: agentConfig(org),
      serverTime: new Date().toISOString(),
    });
  }),
);

export default router;
