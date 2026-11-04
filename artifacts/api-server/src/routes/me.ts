import { Router, type IRouter } from "express";
import { eq } from "drizzle-orm";
import { db, organizationsTable, organizationMembersTable, userProfilesTable } from "@workspace/db";
import { SelectOrganizationBody, CreateOrganizationBody } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireIdentity, loadMemberships } from "../middlewares/auth";
import { conflict, forbidden } from "../lib/errors";
import { audit } from "../lib/audit";

const router: IRouter = Router();

async function buildMe(userId: string, email: string, name: string | null) {
  const memberships = await loadMemberships(userId, email);
  const [profile] = await db.select().from(userProfilesTable).where(eq(userProfilesTable.userId, userId));
  const organizations = memberships.map((m) => ({ id: m.organization.id, name: m.organization.name, slug: m.organization.slug, role: m.role }));
  const current = organizations.find((o) => o.id === profile?.currentOrganizationId) ?? organizations[0] ?? null;
  const currentOrg = memberships.find((m) => m.organization.id === current?.id)?.organization;
  return { userId, email, name: name ?? email, organizations, currentOrganization: current, demoMode: currentOrg?.isDemo ?? false };
}

router.get("/me", requireIdentity, asyncHandler(async (req, res) => {
  const { userId, email, name } = req.identity!;
  res.json(await buildMe(userId, email, name));
}));

router.put("/me/organization", requireIdentity, asyncHandler(async (req, res) => {
  const { userId, email, name } = req.identity!;
  const body = SelectOrganizationBody.parse(req.body);
  const memberships = await loadMemberships(userId, email);
  if (!memberships.some((m) => m.organization.id === body.organizationId)) throw forbidden("Not a member of that organization");
  await db.update(userProfilesTable).set({ currentOrganizationId: body.organizationId }).where(eq(userProfilesTable.userId, userId));
  res.json(await buildMe(userId, email, name));
}));

function slugify(name: string) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "org";
}

router.post("/organizations", requireIdentity, asyncHandler(async (req, res) => {
  const { userId, email, name } = req.identity!;
  const body = CreateOrganizationBody.parse(req.body);
  const base = slugify(body.name);
  let slug = base;
  for (let i = 2; i < 50; i++) {
    const [exists] = await db.select({ id: organizationsTable.id }).from(organizationsTable).where(eq(organizationsTable.slug, slug));
    if (!exists) break;
    slug = `${base}-${i}`;
  }
  const [exists] = await db.select({ id: organizationsTable.id }).from(organizationsTable).where(eq(organizationsTable.slug, slug));
  if (exists) throw conflict("Could not allocate a unique slug");
  const org = await db.transaction(async (tx) => {
    const [o] = await tx.insert(organizationsTable).values({ name: body.name.trim(), slug }).returning();
    await tx.insert(organizationMembersTable).values({ organizationId: o!.id, email, userId, role: "OWNER" });
    await tx.update(userProfilesTable).set({ currentOrganizationId: o!.id }).where(eq(userProfilesTable.userId, userId));
    return o!;
  });
  await audit({ organizationId: org.id, actorType: "USER", actorId: userId, actorLabel: email, action: "organization.created", targetType: "organization", targetId: org.id, ipAddress: req.ip });
  res.status(201).json(await buildMe(userId, email, name));
}));

export default router;
