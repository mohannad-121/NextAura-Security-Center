import { Router, type IRouter } from "express";
import { and, desc, eq, gt, inArray, lt } from "drizzle-orm";
import { z } from "zod";
import PDFDocument from "pdfkit";
import {
  agentRequestsTable,
  db,
  devicesTable,
  deviceScanScopesTable,
  scanFileEvidenceTable,
  scanJobDevicesTable,
  scanJobsTable,
} from "@workspace/db";
import { asyncHandler } from "../lib/asyncHandler";
import { audit } from "../lib/audit";
import { badRequest, notFound } from "../lib/errors";
import { ctx, requireOrg, requireRole } from "../middlewares/auth";
import { markTargetByRequest, recomputeScanJob } from "../services/scanJobs";

const collector = z.enum([
  "SYSTEM_INFO",
  "SECURITY_POSTURE",
  "ANTIVIRUS_STATUS",
  "SOFTWARE_INVENTORY",
  "STARTUP_INVENTORY",
  "SAFE_NETWORK_SUMMARY",
]);
const createSchema = z
  .object({
    scanType: z.enum(["SECURITY_ASSESSMENT", "APPROVED_SCOPE_FILES"]),
    collectors: z.array(collector).max(6).default([]),
    targets: z
      .array(
        z.object({
          deviceId: z.string().uuid(),
          scopeId: z
            .string()
            .regex(/^scope_[0-9a-f]{32}$/)
            .optional(),
        }),
      )
      .min(1)
      .max(500),
    expiresInHours: z.number().int().min(1).max(24).default(24),
  })
  .superRefine((body, refinement) => {
    if (body.scanType === "SECURITY_ASSESSMENT" && !body.collectors.length)
      refinement.addIssue({
        code: "custom",
        message: "Select at least one fixed collector",
        path: ["collectors"],
      });
    if (
      body.scanType === "APPROVED_SCOPE_FILES" &&
      body.targets.some((target) => !target.scopeId)
    )
      refinement.addIssue({
        code: "custom",
        message: "Every file-scan target requires a locally reported scope ID",
        path: ["targets"],
      });
  });

const router: IRouter = Router();
router.use(requireOrg);

function iso(value: Date | null) {
  return value?.toISOString() ?? null;
}

async function requireJob(id: string, organizationId: string) {
  const [job] = await db
    .select()
    .from(scanJobsTable)
    .where(
      and(
        eq(scanJobsTable.id, id),
        eq(scanJobsTable.organizationId, organizationId),
      ),
    );
  if (!job) throw notFound("Scan job not found");
  return job;
}

router.get(
  "/scan-scopes",
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const rows = await db
      .select({
        deviceId: deviceScanScopesTable.deviceId,
        deviceName: devicesTable.name,
        scopeId: deviceScanScopesTable.scopeId,
        label: deviceScanScopesTable.label,
        enabled: deviceScanScopesTable.enabled,
        lastReportedAt: deviceScanScopesTable.lastReportedAt,
      })
      .from(deviceScanScopesTable)
      .innerJoin(
        devicesTable,
        eq(devicesTable.id, deviceScanScopesTable.deviceId),
      )
      .where(
        and(
          eq(deviceScanScopesTable.organizationId, a.organization.id),
          eq(deviceScanScopesTable.enabled, true),
        ),
      )
      .orderBy(devicesTable.name, deviceScanScopesTable.label);
    res.json(
      rows.map((row) => ({
        ...row,
        lastReportedAt: row.lastReportedAt.toISOString(),
      })),
    );
  }),
);

router.get(
  "/scan-jobs",
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const expired = await db
      .select({ id: agentRequestsTable.id })
      .from(agentRequestsTable)
      .where(
        and(
          eq(agentRequestsTable.organizationId, a.organization.id),
          inArray(agentRequestsTable.status, ["PENDING", "DELIVERED"]),
          lt(agentRequestsTable.expiresAt, new Date()),
        ),
      );
    if (expired.length) {
      await db
        .update(agentRequestsTable)
        .set({ status: "EXPIRED", completedAt: new Date() })
        .where(
          inArray(
            agentRequestsTable.id,
            expired.map((request) => request.id),
          ),
        );
      for (const request of expired)
        await markTargetByRequest(request.id, {
          status: "EXPIRED",
          stage: "Expired before agent execution",
          completedAt: new Date(),
        });
    }
    const jobs = await db
      .select()
      .from(scanJobsTable)
      .where(eq(scanJobsTable.organizationId, a.organization.id))
      .orderBy(desc(scanJobsTable.createdAt))
      .limit(200);
    const jobIds = jobs.map((job) => job.id);
    const targets = jobIds.length
      ? await db
          .select({
            scanJobId: scanJobDevicesTable.scanJobId,
            status: scanJobDevicesTable.status,
          })
          .from(scanJobDevicesTable)
          .where(inArray(scanJobDevicesTable.scanJobId, jobIds))
      : [];
    res.json(
      jobs.map((job) => ({
        ...job,
        createdAt: job.createdAt.toISOString(),
        expiresAt: job.expiresAt.toISOString(),
        completedAt: iso(job.completedAt),
        targets: targets
          .filter((target) => target.scanJobId === job.id)
          .reduce<Record<string, number>>((out, target) => {
            out[target.status] = (out[target.status] ?? 0) + 1;
            return out;
          }, {}),
      })),
    );
  }),
);

router.post(
  "/scan-jobs",
  requireRole("SECURITY_ANALYST"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const body = createSchema.parse(req.body);
    const uniqueTargets = new Map(
      body.targets.map((target) => [target.deviceId, target]),
    );
    if (uniqueTargets.size !== body.targets.length)
      throw badRequest("Each device may appear only once per scan job");
    const deviceIds = [...uniqueTargets.keys()];
    const devices = await db
      .select()
      .from(devicesTable)
      .where(
        and(
          eq(devicesTable.organizationId, a.organization.id),
          inArray(devicesTable.id, deviceIds),
          eq(devicesTable.status, "ACTIVE"),
        ),
      );
    if (devices.length !== deviceIds.length)
      throw badRequest(
        "Every target must be an active device in the current organization",
      );
    const [active] = await db
      .select({ id: agentRequestsTable.id })
      .from(agentRequestsTable)
      .where(
        and(
          inArray(agentRequestsTable.deviceId, deviceIds),
          inArray(agentRequestsTable.status, [
            "PENDING",
            "DELIVERED",
            "ACKNOWLEDGED",
          ]),
          gt(agentRequestsTable.expiresAt, new Date()),
        ),
      );
    if (active)
      throw badRequest(
        "At least one selected device already has an active assessment request",
      );
    if (body.scanType === "APPROVED_SCOPE_FILES") {
      const scopes = await db
        .select({
          deviceId: deviceScanScopesTable.deviceId,
          scopeId: deviceScanScopesTable.scopeId,
        })
        .from(deviceScanScopesTable)
        .where(
          and(
            eq(deviceScanScopesTable.organizationId, a.organization.id),
            inArray(deviceScanScopesTable.deviceId, deviceIds),
            eq(deviceScanScopesTable.enabled, true),
          ),
        );
      const allowed = new Set(
        scopes.map((scope) => `${scope.deviceId}:${scope.scopeId}`),
      );
      if (
        body.targets.some(
          (target) => !allowed.has(`${target.deviceId}:${target.scopeId}`),
        )
      )
        throw badRequest(
          "An approved scope is unknown, revoked, or belongs to another device",
        );
    }
    const expiresAt = new Date(Date.now() + body.expiresInHours * 3600_000);
    const job = await db.transaction(async (tx) => {
      const [created] = await tx
        .insert(scanJobsTable)
        .values({
          organizationId: a.organization.id,
          scanType: body.scanType,
          status: "WAITING_FOR_AGENT",
          collectors:
            body.scanType === "SECURITY_ASSESSMENT"
              ? [...new Set(body.collectors)]
              : [],
          requestedByUserId: a.userId,
          requestedByEmail: a.email,
          expiresAt,
        })
        .returning();
      for (const target of body.targets) {
        const operation =
          body.scanType === "SECURITY_ASSESSMENT"
            ? "ASSESSMENT"
            : "FILE_SCOPE_SCAN";
        const [request] = await tx
          .insert(agentRequestsTable)
          .values({
            organizationId: a.organization.id,
            deviceId: target.deviceId,
            collectors:
              operation === "ASSESSMENT" ? [...new Set(body.collectors)] : [],
            operation,
            scopeId: operation === "FILE_SCOPE_SCAN" ? target.scopeId! : null,
            scanJobId: created!.id,
            requestedByUserId: a.userId,
            requestedByEmail: a.email,
            expiresAt,
          })
          .returning();
        await tx.insert(scanJobDevicesTable).values({
          scanJobId: created!.id,
          organizationId: a.organization.id,
          deviceId: target.deviceId,
          agentRequestId: request!.id,
          operation,
          scopeId: operation === "FILE_SCOPE_SCAN" ? target.scopeId! : null,
          status: "WAITING_FOR_AGENT",
        });
      }
      return created!;
    });
    await audit({
      organizationId: a.organization.id,
      actorType: "USER",
      actorId: a.userId,
      actorLabel: a.email,
      action: "scan.created",
      targetType: "scan_job",
      targetId: job.id,
      details: {
        scanType: body.scanType,
        targets: body.targets.length,
        collectors: body.collectors,
      },
      ipAddress: req.ip,
    });
    res.status(201).json({
      ...job,
      createdAt: job.createdAt.toISOString(),
      expiresAt: job.expiresAt.toISOString(),
    });
  }),
);

router.get(
  "/scan-jobs/:id",
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const job = await requireJob(String(req.params.id), a.organization.id);
    const targets = await db
      .select({
        id: scanJobDevicesTable.id,
        deviceId: scanJobDevicesTable.deviceId,
        deviceName: devicesTable.name,
        osType: devicesTable.osType,
        status: scanJobDevicesTable.status,
        stage: scanJobDevicesTable.stage,
        scopeId: scanJobDevicesTable.scopeId,
        filesObserved: scanJobDevicesTable.filesObserved,
        evidenceCount: scanJobDevicesTable.evidenceCount,
        collectorFailures: scanJobDevicesTable.collectorFailures,
        deliveredAt: scanJobDevicesTable.deliveredAt,
        startedAt: scanJobDevicesTable.startedAt,
        completedAt: scanJobDevicesTable.completedAt,
        error: scanJobDevicesTable.error,
      })
      .from(scanJobDevicesTable)
      .innerJoin(
        devicesTable,
        eq(devicesTable.id, scanJobDevicesTable.deviceId),
      )
      .where(
        and(
          eq(scanJobDevicesTable.scanJobId, job.id),
          eq(scanJobDevicesTable.organizationId, a.organization.id),
        ),
      );
    const evidence = await db
      .select()
      .from(scanFileEvidenceTable)
      .where(
        and(
          eq(scanFileEvidenceTable.scanJobId, job.id),
          eq(scanFileEvidenceTable.organizationId, a.organization.id),
        ),
      )
      .orderBy(desc(scanFileEvidenceTable.observedAt))
      .limit(2000);
    res.json({
      job: {
        ...job,
        createdAt: job.createdAt.toISOString(),
        expiresAt: job.expiresAt.toISOString(),
        completedAt: iso(job.completedAt),
      },
      targets: targets.map((target) => ({
        ...target,
        deliveredAt: iso(target.deliveredAt),
        startedAt: iso(target.startedAt),
        completedAt: iso(target.completedAt),
      })),
      evidence: evidence.map((item) => ({
        ...item,
        observedAt: item.observedAt.toISOString(),
        createdAt: item.createdAt.toISOString(),
      })),
    });
  }),
);

router.post(
  "/scan-jobs/:id/cancel",
  requireRole("SECURITY_ANALYST"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const job = await requireJob(String(req.params.id), a.organization.id);
    const cancellable = await db
      .select({
        id: scanJobDevicesTable.id,
        requestId: scanJobDevicesTable.agentRequestId,
      })
      .from(scanJobDevicesTable)
      .where(
        and(
          eq(scanJobDevicesTable.scanJobId, job.id),
          inArray(scanJobDevicesTable.status, ["QUEUED", "WAITING_FOR_AGENT"]),
        ),
      );
    await db.transaction(async (tx) => {
      await tx
        .update(scanJobsTable)
        .set({ cancellationRequestedAt: new Date() })
        .where(eq(scanJobsTable.id, job.id));
      if (cancellable.length) {
        await tx
          .update(scanJobDevicesTable)
          .set({
            status: "CANCELLED",
            stage: "Cancelled before agent execution",
            completedAt: new Date(),
          })
          .where(
            inArray(
              scanJobDevicesTable.id,
              cancellable.map((target) => target.id),
            ),
          );
        const requestIds = cancellable
          .map((target) => target.requestId)
          .filter((value): value is string => !!value);
        if (requestIds.length)
          await tx
            .update(agentRequestsTable)
            .set({ status: "EXPIRED", completedAt: new Date() })
            .where(inArray(agentRequestsTable.id, requestIds));
      }
    });
    await recomputeScanJob(job.id);
    await audit({
      organizationId: a.organization.id,
      actorType: "USER",
      actorId: a.userId,
      actorLabel: a.email,
      action: "scan.cancellation_requested",
      targetType: "scan_job",
      targetId: job.id,
      details: { cancelledBeforeExecution: cancellable.length },
      ipAddress: req.ip,
    });
    res.json({
      ok: true,
      cancelledBeforeExecution: cancellable.length,
      note: "Already-running read-only collectors are not force-terminated.",
    });
  }),
);

router.get(
  "/scan-jobs/:id/report",
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const job = await requireJob(String(req.params.id), a.organization.id);
    const targets = await db
      .select({
        name: devicesTable.name,
        status: scanJobDevicesTable.status,
        stage: scanJobDevicesTable.stage,
        evidenceCount: scanJobDevicesTable.evidenceCount,
        filesObserved: scanJobDevicesTable.filesObserved,
      })
      .from(scanJobDevicesTable)
      .innerJoin(
        devicesTable,
        eq(devicesTable.id, scanJobDevicesTable.deviceId),
      )
      .where(
        and(
          eq(scanJobDevicesTable.scanJobId, job.id),
          eq(scanJobDevicesTable.organizationId, a.organization.id),
        ),
      );
    const evidence = await db
      .select()
      .from(scanFileEvidenceTable)
      .where(
        and(
          eq(scanFileEvidenceTable.scanJobId, job.id),
          eq(scanFileEvidenceTable.organizationId, a.organization.id),
        ),
      )
      .limit(1000);
    const chunks: Buffer[] = [];
    const pdf = new PDFDocument({ margin: 50, size: "A4" });
    pdf.on("data", (chunk: Buffer) => chunks.push(chunk));
    const done = new Promise<Buffer>((resolve) =>
      pdf.on("end", () => resolve(Buffer.concat(chunks))),
    );
    pdf.fontSize(20).text("NextAura Scan Evidence Report");
    pdf.moveDown().fontSize(10).text(`Organization: ${a.organization.name}`);
    pdf.text(`Scan: ${job.id}`);
    pdf.text(`Type: ${job.scanType}`);
    pdf.text(`Status: ${job.status}`);
    pdf.text(`Created: ${job.createdAt.toISOString()}`);
    pdf.moveDown().fontSize(14).text("Device results");
    for (const target of targets)
      pdf
        .fontSize(9)
        .text(
          `${target.name}: ${target.status} — ${target.stage}; observed ${target.filesObserved}, evidence ${target.evidenceCount}`,
        );
    pdf.moveDown().fontSize(14).text("File evidence");
    for (const item of evidence)
      pdf
        .fontSize(8)
        .text(
          `${item.classification} ${item.severity} ${item.fileName} SHA-256 ${item.sha256} (${item.detectorId} ${item.detectorVersion})`,
        );
    pdf
      .moveDown()
      .fontSize(9)
      .text(
        "Limitations: This report contains bounded read-only evidence. NO_FINDINGS_OBSERVED is not proof that an endpoint or file is safe.",
      );
    pdf.end();
    const buffer = await done;
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="nextaura-scan-${job.id}.pdf"`,
    );
    res.send(buffer);
  }),
);

export default router;
