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
import { and, desc, eq, gt, isNull, lt, or } from "drizzle-orm";
import {
  db,
  devicesTable,
  deviceCredentialsTable,
  deviceEnrollmentRequestsTable,
  deviceHeartbeatsTable,
  agentRequestsTable,
  agentRequestReplayTable,
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
import {
  ackBodySchema,
  assessmentBodySchema,
  enrollBodySchema,
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
    res.json({
      requests: rows.map((r) => ({
        id: r.id,
        collectors: r.collectors,
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
    const result = await ingestAssessment(device, body);
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
