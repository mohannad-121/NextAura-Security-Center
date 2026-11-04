import { Router, type IRouter } from "express";
import { and, desc, eq } from "drizzle-orm";
import { db, reportExportsTable, devicesTable } from "@workspace/db";
import { CreateReportBody } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, requireRole, ctx } from "../middlewares/auth";
import { badRequest, notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import { buildDevicePdf, buildFindingsCsv, buildOrganizationPdf } from "../services/reports";
import { deviceNameMap } from "../services/serializers";
import { logger } from "../lib/logger";

const router: IRouter = Router();
router.use(requireOrg);

function serialize(r: typeof reportExportsTable.$inferSelect, deviceName: string | null) {
  return {
    id: r.id, type: r.type, deviceId: r.deviceId, deviceName, status: r.status, format: r.type === "FINDINGS_CSV" ? "CSV" : "PDF",
    createdByEmail: r.generatedByEmail, createdAt: r.createdAt.toISOString(), completedAt: r.status === "COMPLETED" ? r.createdAt.toISOString() : null,
    downloadPath: r.status === "COMPLETED" ? `/api/reports/${r.id}/download` : null, sizeBytes: r.status === "COMPLETED" ? r.sizeBytes : null, error: r.errorMessage,
    summary: r.type === "DEVICE_PDF" ? `Device report for ${deviceName ?? "unknown device"}` : r.type === "ORGANIZATION_PDF" ? "Organization security summary" : "All findings (CSV)",
  };
}

router.get("/reports", asyncHandler(async (req, res) => {
  const { organization } = ctx(req);
  const names = await deviceNameMap(organization.id);
  const rows = await db.select({
    id: reportExportsTable.id, type: reportExportsTable.type, deviceId: reportExportsTable.deviceId, status: reportExportsTable.status, sizeBytes: reportExportsTable.sizeBytes,
    generatedByEmail: reportExportsTable.generatedByEmail, createdAt: reportExportsTable.createdAt, errorMessage: reportExportsTable.errorMessage,
  }).from(reportExportsTable).where(eq(reportExportsTable.organizationId, organization.id)).orderBy(desc(reportExportsTable.createdAt)).limit(100);
  res.json(rows.map((r) => serialize({ ...r, organizationId: organization.id, fileName: "", mimeType: "", content: "", generatedByUserId: "" }, r.deviceId ? names.get(r.deviceId) ?? null : null)));
}));

router.post("/reports", requireRole("SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const body = CreateReportBody.parse(req.body);
  let deviceName: string | null = null;
  let buffer: Buffer | null = null;
  let fileName = "";
  let mimeType = "";
  let error: string | null = null;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  try {
    if (body.type === "DEVICE_PDF") {
      if (!body.deviceId) throw badRequest("deviceId is required for a device report");
      const [device] = await db.select().from(devicesTable).where(and(eq(devicesTable.id, body.deviceId), eq(devicesTable.organizationId, a.organization.id)));
      if (!device) throw notFound("Device not found");
      deviceName = device.name;
      buffer = await buildDevicePdf(a.organization, device);
      fileName = `nextaura-device-${device.name}-${stamp}.pdf`;
      mimeType = "application/pdf";
    } else if (body.type === "ORGANIZATION_PDF") {
      buffer = await buildOrganizationPdf(a.organization);
      fileName = `nextaura-organization-${a.organization.slug}-${stamp}.pdf`;
      mimeType = "application/pdf";
    } else {
      buffer = await buildFindingsCsv(a.organization);
      fileName = `nextaura-findings-${a.organization.slug}-${stamp}.csv`;
      mimeType = "text/csv";
    }
  } catch (err) {
    if (err && typeof err === "object" && "status" in err) throw err;
    logger.error({ err }, "report generation failed");
    error = err instanceof Error ? err.message : "Report generation failed";
  }
  const [row] = await db.insert(reportExportsTable).values({
    organizationId: a.organization.id, type: body.type, status: buffer ? "COMPLETED" : "FAILED", deviceId: body.deviceId ?? null,
    fileName: fileName || "failed", mimeType: mimeType || "application/octet-stream", sizeBytes: buffer?.length ?? 0, content: buffer ? buffer.toString("base64") : "",
    generatedByUserId: a.userId, generatedByEmail: a.email, errorMessage: error,
  }).returning();
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "report.generated", targetType: "report", targetId: row!.id, details: { type: body.type, status: row!.status }, ipAddress: req.ip });
  res.status(201).json(serialize(row!, deviceName));
}));

router.get("/reports/:id/download", asyncHandler(async (req, res) => {
  const { organization } = ctx(req);
  const [r] = await db.select().from(reportExportsTable).where(and(eq(reportExportsTable.id, String(req.params["id"])), eq(reportExportsTable.organizationId, organization.id)));
  if (!r || r.status !== "COMPLETED") throw notFound("Report not found");
  res.setHeader("Content-Type", r.mimeType);
  res.setHeader("Content-Disposition", `attachment; filename="${r.fileName.replace(/[^A-Za-z0-9._-]/g, "_")}"`);
  res.send(Buffer.from(r.content, "base64"));
}));

export default router;
