import { Router, type IRouter } from "express";
import { and, desc, eq, ilike, or } from "drizzle-orm";
import { db, securityFindingsTable, devicesTable } from "@workspace/db";
import { ListFindingsQueryParams, UpdateFindingBody } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, requireRole, ctx } from "../middlewares/auth";
import { notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import { serializeFinding } from "../services/serializers";
import { recomputeDeviceRisk } from "../services/assessments";

const router: IRouter = Router();
router.use(requireOrg);

router.get("/findings", asyncHandler(async (req, res) => {
  const { organization } = ctx(req);
  const q = ListFindingsQueryParams.parse(req.query);
  const conds = [eq(securityFindingsTable.organizationId, organization.id)];
  if (q.severity) conds.push(eq(securityFindingsTable.severity, q.severity));
  if (q.status) conds.push(eq(securityFindingsTable.status, q.status));
  if (q.deviceId) conds.push(eq(securityFindingsTable.deviceId, q.deviceId));
  if (q.search) {
    const s = `%${q.search.replace(/[%_]/g, "")}%`;
    conds.push(or(ilike(securityFindingsTable.title, s), ilike(securityFindingsTable.evidence, s), ilike(securityFindingsTable.ruleId, s), ilike(devicesTable.name, s))!);
  }
  const rows = await db
    .select({ f: securityFindingsTable, deviceName: devicesTable.name })
    .from(securityFindingsTable)
    .innerJoin(devicesTable, eq(devicesTable.id, securityFindingsTable.deviceId))
    .where(and(...conds))
    .orderBy(desc(securityFindingsTable.lastSeenAt))
    .limit(1000);
  res.json(rows.map(({ f, deviceName }) => serializeFinding(f, deviceName)));
}));

router.get("/findings/:id", asyncHandler(async (req, res) => {
  const { organization } = ctx(req);
  const [row] = await db
    .select({ f: securityFindingsTable, deviceName: devicesTable.name })
    .from(securityFindingsTable)
    .innerJoin(devicesTable, eq(devicesTable.id, securityFindingsTable.deviceId))
    .where(and(eq(securityFindingsTable.id, String(req.params["id"])), eq(securityFindingsTable.organizationId, organization.id)));
  if (!row) throw notFound("Finding not found");
  res.json(serializeFinding(row.f, row.deviceName));
}));

router.patch("/findings/:id", requireRole("SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const body = UpdateFindingBody.parse(req.body);
  const [existing] = await db.select().from(securityFindingsTable).where(and(eq(securityFindingsTable.id, String(req.params["id"])), eq(securityFindingsTable.organizationId, a.organization.id)));
  if (!existing) throw notFound("Finding not found");
  const [updated] = await db
    .update(securityFindingsTable)
    .set({ status: body.status, statusNote: body.note ?? null, statusChangedAt: new Date(), statusChangedByUserId: a.userId, statusChangedByEmail: a.email })
    .where(eq(securityFindingsTable.id, existing.id))
    .returning();
  const [device] = await db.select().from(devicesTable).where(eq(devicesTable.id, existing.deviceId));
  await recomputeDeviceRisk(existing.deviceId, null, device?.coveragePercent ?? 0);
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "finding.status_changed", targetType: "finding", targetId: existing.id, details: { from: existing.status, to: body.status, note: body.note ?? null, ruleId: existing.ruleId }, ipAddress: req.ip });
  res.json(serializeFinding(updated!, device?.name ?? "unknown"));
}));

export default router;
