import { Router, type IRouter } from "express";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import {
  db, organizationsTable, organizationMembersTable, userProfilesTable, auditLogsTable,
  devicesTable, assessmentsTable, securityFindingsTable, deviceCredentialsTable, deviceEnrollmentRequestsTable, agentRequestsTable, reportExportsTable, emailDomainAuditsTable,
} from "@workspace/db";
import { UpdateOrganizationSettingsBody, AddMemberBody, UpdateMemberBody, RequestDataDeletionBody, ListAuditLogsQueryParams } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, requireRole, ctx } from "../middlewares/auth";
import { badRequest, conflict, forbidden, notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import { iso } from "../services/serializers";

const router: IRouter = Router();
router.use(requireOrg);

function serializeOrg(o: typeof organizationsTable.$inferSelect) {
  return {
    id: o.id, name: o.name, slug: o.slug, createdAt: o.createdAt.toISOString(), retentionDays: o.retentionDays, heartbeatIntervalMinutes: o.heartbeatIntervalMinutes,
    postureIntervalHours: o.postureIntervalHours, inventoryIntervalHours: o.inventoryIntervalHours, enrollmentCodeTtlMinutes: o.enrollmentCodeTtlMinutes,
    onlineThresholdMinutes: o.onlineThresholdMinutes, allowedOsTypes: o.allowedOsTypes, minimumAgentVersion: o.minimumAgentVersion, requireMfa: o.requireMfa, demoMode: o.isDemo,
  };
}

router.get("/settings/organization", (req, res) => { res.json(serializeOrg(ctx(req).organization)); });

router.patch("/settings/organization", requireRole("ADMIN"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const body = UpdateOrganizationSettingsBody.parse(req.body);
  if (body.allowedOsTypes && body.allowedOsTypes.length === 0) throw badRequest("At least one OS type must be allowed");
  const patch: Partial<typeof organizationsTable.$inferInsert> = { ...body, allowedOsTypes: body.allowedOsTypes ? Array.from(new Set(body.allowedOsTypes)) : undefined };
  if (body.onlineThresholdMinutes && body.heartbeatIntervalMinutes === undefined && body.onlineThresholdMinutes < a.organization.heartbeatIntervalMinutes) throw badRequest("Online threshold must be at least the heartbeat interval");
  const [o] = await db.update(organizationsTable).set(patch).where(eq(organizationsTable.id, a.organization.id)).returning();
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "settings.updated", targetType: "organization", targetId: a.organization.id, details: body as Record<string, unknown>, ipAddress: req.ip });
  res.json(serializeOrg(o!));
}));

async function listMembers(orgId: string, currentUserId: string) {
  const rows = await db
    .select({ m: organizationMembersTable, p: userProfilesTable })
    .from(organizationMembersTable)
    .leftJoin(userProfilesTable, eq(userProfilesTable.userId, organizationMembersTable.userId))
    .where(eq(organizationMembersTable.organizationId, orgId))
    .orderBy(organizationMembersTable.createdAt);
  return rows.map(({ m, p }) => ({ id: m.id, email: m.email, name: p?.name ?? null, role: m.role, userId: m.userId, createdAt: m.createdAt.toISOString(), lastSignInAt: iso(p?.lastSignInAt), isCurrentUser: m.userId === currentUserId }));
}

router.get("/settings/members", asyncHandler(async (req, res) => {
  const a = ctx(req);
  res.json(await listMembers(a.organization.id, a.userId));
}));

router.post("/settings/members", requireRole("ADMIN"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const body = AddMemberBody.parse(req.body);
  const email = body.email.trim().toLowerCase();
  if (body.role === "OWNER" && a.role !== "OWNER") throw forbidden("Only owners can assign the OWNER role");
  const [exists] = await db.select({ id: organizationMembersTable.id }).from(organizationMembersTable).where(and(eq(organizationMembersTable.organizationId, a.organization.id), eq(organizationMembersTable.email, email)));
  if (exists) throw conflict("That email is already a member");
  const [profile] = await db.select({ userId: userProfilesTable.userId }).from(userProfilesTable).where(eq(userProfilesTable.email, email));
  await db.insert(organizationMembersTable).values({ organizationId: a.organization.id, email, role: body.role, userId: profile?.userId ?? null });
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "member.added", targetType: "member", targetId: email, details: { role: body.role }, ipAddress: req.ip });
  res.status(201).json(await listMembers(a.organization.id, a.userId));
}));

router.patch("/settings/members/:id", requireRole("ADMIN"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const body = UpdateMemberBody.parse(req.body);
  const [m] = await db.select().from(organizationMembersTable).where(and(eq(organizationMembersTable.id, String(req.params["id"])), eq(organizationMembersTable.organizationId, a.organization.id)));
  if (!m) throw notFound("Member not found");
  if ((m.role === "OWNER" || body.role === "OWNER") && a.role !== "OWNER") throw forbidden("Only owners can change OWNER membership");
  if (m.role === "OWNER" && body.role !== "OWNER") {
    const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(organizationMembersTable).where(and(eq(organizationMembersTable.organizationId, a.organization.id), eq(organizationMembersTable.role, "OWNER")));
    if (n <= 1) throw badRequest("An organization must keep at least one owner");
  }
  await db.update(organizationMembersTable).set({ role: body.role }).where(eq(organizationMembersTable.id, m.id));
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "member.role_changed", targetType: "member", targetId: m.email, details: { from: m.role, to: body.role }, ipAddress: req.ip });
  res.json(await listMembers(a.organization.id, a.userId));
}));

router.delete("/settings/members/:id", requireRole("ADMIN"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const [m] = await db.select().from(organizationMembersTable).where(and(eq(organizationMembersTable.id, String(req.params["id"])), eq(organizationMembersTable.organizationId, a.organization.id)));
  if (!m) throw notFound("Member not found");
  if (m.role === "OWNER") {
    if (a.role !== "OWNER") throw forbidden("Only owners can remove owners");
    const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(organizationMembersTable).where(and(eq(organizationMembersTable.organizationId, a.organization.id), eq(organizationMembersTable.role, "OWNER")));
    if (n <= 1) throw badRequest("An organization must keep at least one owner");
  }
  await db.delete(organizationMembersTable).where(eq(organizationMembersTable.id, m.id));
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "member.removed", targetType: "member", targetId: m.email, ipAddress: req.ip });
  res.status(204).end();
}));

router.post("/settings/data-deletion", requireRole("OWNER"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const body = RequestDataDeletionBody.parse(req.body);
  if (body.confirmation.trim() !== a.organization.slug) throw badRequest("Type the organization slug exactly to confirm");
  const orgId = a.organization.id;
  const counts = await db.transaction(async (tx) => {
    const [{ n: assessments }] = await tx.select({ n: sql<number>`count(*)::int` }).from(assessmentsTable).where(eq(assessmentsTable.organizationId, orgId));
    const [{ n: findings }] = await tx.select({ n: sql<number>`count(*)::int` }).from(securityFindingsTable).where(eq(securityFindingsTable.organizationId, orgId));
    const [{ n: devices }] = await tx.select({ n: sql<number>`count(*)::int` }).from(devicesTable).where(eq(devicesTable.organizationId, orgId));
    // Device cascade removes checks, inventory, findings, vulns, heartbeats, requests, credentials.
    await tx.delete(deviceCredentialsTable).where(eq(deviceCredentialsTable.organizationId, orgId));
    await tx.delete(agentRequestsTable).where(eq(agentRequestsTable.organizationId, orgId));
    await tx.delete(devicesTable).where(eq(devicesTable.organizationId, orgId));
    await tx.delete(deviceEnrollmentRequestsTable).where(eq(deviceEnrollmentRequestsTable.organizationId, orgId));
    await tx.delete(reportExportsTable).where(eq(reportExportsTable.organizationId, orgId));
    await tx.delete(emailDomainAuditsTable).where(eq(emailDomainAuditsTable.organizationId, orgId));
    return { assessments, findings, devices };
  });
  await audit({ organizationId: orgId, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "data.deleted", targetType: "organization", targetId: orgId, details: counts, ipAddress: req.ip });
  res.json({ deletedAssessments: counts.assessments, deletedFindings: counts.findings, deletedDevices: counts.devices, completedAt: new Date().toISOString() });
}));

router.get("/audit-logs", requireRole("ADMIN"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const q = ListAuditLogsQueryParams.parse(req.query);
  const rows = await db.select().from(auditLogsTable).where(eq(auditLogsTable.organizationId, a.organization.id)).orderBy(desc(auditLogsTable.createdAt)).limit(q.limit);
  const deviceIds = rows.filter((r) => r.targetType === "device" && r.targetId).map((r) => r.targetId!);
  const names = deviceIds.length ? new Map((await db.select({ id: devicesTable.id, name: devicesTable.name }).from(devicesTable).where(inArray(devicesTable.id, deviceIds))).map((d) => [d.id, d.name])) : new Map<string, string>();
  res.json(rows.map((r) => ({
    id: r.id, action: r.action, actorEmail: r.actorType === "USER" ? r.actorLabel : null, actorType: r.actorType, targetType: r.targetType, targetId: r.targetId,
    targetLabel: r.targetType === "device" ? names.get(r.targetId ?? "") ?? null : r.targetType === "member" ? r.targetId : r.actorType === "DEVICE" ? r.actorLabel : null,
    details: JSON.stringify(r.details), createdAt: r.createdAt.toISOString(),
  })));
}));

export default router;
