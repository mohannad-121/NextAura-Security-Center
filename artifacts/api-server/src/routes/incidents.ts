import { Router, type IRouter } from "express";
import { and, desc, eq, inArray } from "drizzle-orm";
import { z } from "zod";
import {
  db,
  devicesTable,
  incidentDevicesTable,
  incidentFileEvidenceTable,
  incidentFindingsTable,
  incidentsTable,
  incidentTimelineTable,
  securityFindingsTable,
} from "@workspace/db";
import { asyncHandler } from "../lib/asyncHandler";
import { badRequest, notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import { ctx, requireOrg, requireRole } from "../middlewares/auth";
import { buildIncidentPdf } from "../services/incidentReport";

const severity = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
const confidence = z.enum(["HIGH", "MEDIUM", "LOW"]);
const incidentStatus = z.enum(["OPEN", "INVESTIGATING", "CONTAINED", "CLOSED"]);
const classification = z.enum([
  "CONFIRMED_DETECTION",
  "SUSPICIOUS_INDICATOR",
  "INCONCLUSIVE",
  "NO_FINDINGS_OBSERVED",
  "UNSUPPORTED",
]);
const text = (max: number) => z.string().trim().max(max);
const createSchema = z.object({
  title: text(200).min(1),
  severity,
  confidence: confidence.default("MEDIUM"),
  summary: text(5000).default(""),
  deviceIds: z.array(z.string().uuid()).max(100).default([]),
  findingIds: z.array(z.string().uuid()).max(200).default([]),
  evidenceLimitations: z.array(text(1000)).max(100).default([]),
  recommendedActions: z.array(text(1000)).max(100).default([]),
});
const updateSchema = z.object({
  status: incidentStatus.optional(),
  severity: severity.optional(),
  confidence: confidence.optional(),
  summary: text(5000).optional(),
  assignedToEmail: text(320).email().nullable().optional(),
  evidenceLimitations: z.array(text(1000)).max(100).optional(),
  recommendedActions: z.array(text(1000)).max(100).optional(),
});
const fileSchema = z.object({
  fileName: text(300).min(1),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  sizeBytes: z
    .number()
    .int()
    .nonnegative()
    .max(512 * 1024 * 1024),
  detectedType: text(80),
  classification,
  signatureMetadata: text(120).default("UNKNOWN"),
  reputation: z.record(z.unknown()).default({}),
  indicators: z.array(z.unknown()).max(200).default([]),
  archive: z.record(z.unknown()).nullable().optional(),
  limitations: z.array(text(1000)).max(100).default([]),
  source: text(200).default("nextaura-agent inspect-file"),
  observedAt: z
    .string()
    .datetime({ offset: true })
    .default(() => new Date().toISOString()),
});
const timelineSchema = z.object({
  occurredAt: z.string().datetime({ offset: true }),
  eventType: text(80),
  title: text(300),
  evidence: text(5000),
  source: text(200),
});

const router: IRouter = Router();
router.use(requireOrg);

async function requireIncident(id: string, organizationId: string) {
  const [incident] = await db
    .select()
    .from(incidentsTable)
    .where(
      and(
        eq(incidentsTable.id, id),
        eq(incidentsTable.organizationId, organizationId),
      ),
    );
  if (!incident) throw notFound("Incident not found");
  return incident;
}

router.get(
  "/incidents",
  asyncHandler(async (req, res) => {
    const { organization } = ctx(req);
    const rows = await db
      .select()
      .from(incidentsTable)
      .where(eq(incidentsTable.organizationId, organization.id))
      .orderBy(desc(incidentsTable.updatedAt))
      .limit(500);
    res.json(
      rows.map((i) => ({
        ...i,
        createdAt: i.createdAt.toISOString(),
        updatedAt: i.updatedAt.toISOString(),
        closedAt: i.closedAt?.toISOString() ?? null,
      })),
    );
  }),
);

router.post(
  "/incidents",
  requireRole("SECURITY_ANALYST"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const body = createSchema.parse(req.body);
    const devices = body.deviceIds.length
      ? await db
          .select({ id: devicesTable.id })
          .from(devicesTable)
          .where(
            and(
              eq(devicesTable.organizationId, a.organization.id),
              inArray(devicesTable.id, body.deviceIds),
            ),
          )
      : [];
    const findings = body.findingIds.length
      ? await db
          .select({ id: securityFindingsTable.id })
          .from(securityFindingsTable)
          .where(
            and(
              eq(securityFindingsTable.organizationId, a.organization.id),
              inArray(securityFindingsTable.id, body.findingIds),
            ),
          )
      : [];
    if (
      devices.length !== new Set(body.deviceIds).size ||
      findings.length !== new Set(body.findingIds).size
    )
      throw badRequest(
        "All associated devices and findings must belong to the active organization",
      );
    const incident = await db.transaction(async (tx) => {
      const [created] = await tx
        .insert(incidentsTable)
        .values({
          organizationId: a.organization.id,
          title: body.title,
          severity: body.severity,
          confidence: body.confidence,
          summary: body.summary,
          evidenceLimitations: body.evidenceLimitations,
          recommendedActions: body.recommendedActions,
          createdByUserId: a.userId,
          createdByEmail: a.email,
        })
        .returning();
      if (devices.length)
        await tx
          .insert(incidentDevicesTable)
          .values(
            devices.map((d) => ({ incidentId: created!.id, deviceId: d.id })),
          );
      if (findings.length)
        await tx
          .insert(incidentFindingsTable)
          .values(
            findings.map((f) => ({ incidentId: created!.id, findingId: f.id })),
          );
      return created!;
    });
    await audit({
      organizationId: a.organization.id,
      actorType: "USER",
      actorId: a.userId,
      actorLabel: a.email,
      action: "incident.created",
      targetType: "incident",
      targetId: incident.id,
      details: {
        severity: incident.severity,
        devices: devices.length,
        findings: findings.length,
      },
      ipAddress: req.ip,
    });
    res.status(201).json(incident);
  }),
);

router.get(
  "/incidents/:id",
  asyncHandler(async (req, res) => {
    const { organization } = ctx(req);
    const incident = await requireIncident(
      String(req.params.id),
      organization.id,
    );
    const [devices, findings, files, timeline] = await Promise.all([
      db
        .select({
          id: devicesTable.id,
          name: devicesTable.name,
          osType: devicesTable.osType,
        })
        .from(incidentDevicesTable)
        .innerJoin(
          devicesTable,
          eq(devicesTable.id, incidentDevicesTable.deviceId),
        )
        .where(eq(incidentDevicesTable.incidentId, incident.id)),
      db
        .select({
          id: securityFindingsTable.id,
          title: securityFindingsTable.title,
          severity: securityFindingsTable.severity,
          evidence: securityFindingsTable.evidence,
          status: securityFindingsTable.status,
        })
        .from(incidentFindingsTable)
        .innerJoin(
          securityFindingsTable,
          eq(securityFindingsTable.id, incidentFindingsTable.findingId),
        )
        .where(eq(incidentFindingsTable.incidentId, incident.id)),
      db
        .select()
        .from(incidentFileEvidenceTable)
        .where(eq(incidentFileEvidenceTable.incidentId, incident.id))
        .orderBy(desc(incidentFileEvidenceTable.observedAt)),
      db
        .select()
        .from(incidentTimelineTable)
        .where(eq(incidentTimelineTable.incidentId, incident.id))
        .orderBy(incidentTimelineTable.occurredAt),
    ]);
    res.json({ incident, devices, findings, files, timeline });
  }),
);

router.patch(
  "/incidents/:id",
  requireRole("SECURITY_ANALYST"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const id = String(req.params.id);
    const existing = await requireIncident(id, a.organization.id);
    const body = updateSchema.parse(req.body);
    const [updated] = await db
      .update(incidentsTable)
      .set({
        ...body,
        closedAt:
          body.status === "CLOSED"
            ? new Date()
            : body.status
              ? null
              : existing.closedAt,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(incidentsTable.id, id),
          eq(incidentsTable.organizationId, a.organization.id),
        ),
      )
      .returning();
    await audit({
      organizationId: a.organization.id,
      actorType: "USER",
      actorId: a.userId,
      actorLabel: a.email,
      action: "incident.updated",
      targetType: "incident",
      targetId: id,
      details: { previousStatus: existing.status, status: updated!.status },
      ipAddress: req.ip,
    });
    res.json(updated);
  }),
);

router.post(
  "/incidents/:id/files",
  requireRole("SECURITY_ANALYST"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const incident = await requireIncident(
      String(req.params.id),
      a.organization.id,
    );
    const body = fileSchema.parse(req.body);
    const [row] = await db
      .insert(incidentFileEvidenceTable)
      .values({
        incidentId: incident.id,
        fileName: body.fileName,
        sha256: body.sha256,
        sizeBytes: body.sizeBytes,
        detectedType: body.detectedType,
        classification: body.classification,
        signatureMetadata: body.signatureMetadata,
        reputation: body.reputation,
        indicators: body.indicators,
        archiveSummary: body.archive ?? null,
        limitations: body.limitations,
        source: body.source,
        observedAt: new Date(body.observedAt),
      })
      .returning();
    await db
      .update(incidentsTable)
      .set({ updatedAt: new Date() })
      .where(eq(incidentsTable.id, incident.id));
    await audit({
      organizationId: a.organization.id,
      actorType: "USER",
      actorId: a.userId,
      actorLabel: a.email,
      action: "incident.file_evidence_added",
      targetType: "incident",
      targetId: incident.id,
      details: {
        sha256: body.sha256,
        classification: body.classification,
        detectedType: body.detectedType,
      },
      ipAddress: req.ip,
    });
    res.status(201).json(row);
  }),
);

router.post(
  "/incidents/:id/timeline",
  requireRole("SECURITY_ANALYST"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const incident = await requireIncident(
      String(req.params.id),
      a.organization.id,
    );
    const body = timelineSchema.parse(req.body);
    const [row] = await db
      .insert(incidentTimelineTable)
      .values({
        incidentId: incident.id,
        occurredAt: new Date(body.occurredAt),
        eventType: body.eventType,
        title: body.title,
        evidence: body.evidence,
        source: body.source,
      })
      .returning();
    await db
      .update(incidentsTable)
      .set({ updatedAt: new Date() })
      .where(eq(incidentsTable.id, incident.id));
    await audit({
      organizationId: a.organization.id,
      actorType: "USER",
      actorId: a.userId,
      actorLabel: a.email,
      action: "incident.timeline_event_added",
      targetType: "incident",
      targetId: incident.id,
      details: {
        eventType: body.eventType,
        occurredAt: body.occurredAt,
        source: body.source,
      },
      ipAddress: req.ip,
    });
    res.status(201).json(row);
  }),
);

router.get(
  "/incidents/:id/report",
  asyncHandler(async (req, res) => {
    const { organization } = ctx(req);
    const incident = await requireIncident(
      String(req.params.id),
      organization.id,
    );
    const [devices, findings, files, timeline] = await Promise.all([
      db
        .select({ name: devicesTable.name, osType: devicesTable.osType })
        .from(incidentDevicesTable)
        .innerJoin(
          devicesTable,
          eq(devicesTable.id, incidentDevicesTable.deviceId),
        )
        .where(eq(incidentDevicesTable.incidentId, incident.id)),
      db
        .select({
          title: securityFindingsTable.title,
          severity: securityFindingsTable.severity,
          evidence: securityFindingsTable.evidence,
        })
        .from(incidentFindingsTable)
        .innerJoin(
          securityFindingsTable,
          eq(securityFindingsTable.id, incidentFindingsTable.findingId),
        )
        .where(eq(incidentFindingsTable.incidentId, incident.id)),
      db
        .select()
        .from(incidentFileEvidenceTable)
        .where(eq(incidentFileEvidenceTable.incidentId, incident.id)),
      db
        .select()
        .from(incidentTimelineTable)
        .where(eq(incidentTimelineTable.incidentId, incident.id))
        .orderBy(incidentTimelineTable.occurredAt),
    ]);
    const pdf = await buildIncidentPdf({
      title: incident.title,
      severity: incident.severity,
      status: incident.status,
      confidence: incident.confidence,
      summary: incident.summary,
      organizationName: organization.name,
      devices,
      findings,
      files: files.map((f) => ({
        fileName: f.fileName,
        sha256: f.sha256,
        detectedType: f.detectedType,
        classification: f.classification,
        signatureMetadata: f.signatureMetadata,
        limitations: f.limitations,
      })),
      timeline,
      limitations: incident.evidenceLimitations,
      actions: incident.recommendedActions,
    });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="nextaura-incident-${incident.id}.pdf"`,
    );
    res.send(pdf);
  }),
);

export default router;
