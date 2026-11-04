import type { Request, RequestHandler } from "express";
import { getAuth, clerkClient } from "@clerk/express";
import { and, eq, isNull, or } from "drizzle-orm";
import {
  db,
  organizationMembersTable,
  organizationsTable,
  userProfilesTable,
  type Organization,
} from "@workspace/db";
import { forbidden, unauthorized } from "../lib/errors";
import { asyncHandler } from "../lib/asyncHandler";

export type Role = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export interface AuthContext {
  userId: string;
  email: string;
  name: string | null;
  organization: Organization;
  role: Role;
  memberId: string;
}


const ROLE_RANK: Record<Role, number> = {
  VIEWER: 0,
  SECURITY_ANALYST: 1,
  ADMIN: 2,
  OWNER: 3,
};

export function roleAtLeast(role: Role, min: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

const identityCache = new Map<string, { email: string; name: string | null; at: number }>();

async function resolveIdentity(userId: string) {
  const cached = identityCache.get(userId);
  if (cached && Date.now() - cached.at < 5 * 60_000) return cached;
  const user = await clerkClient.users.getUser(userId);
  const primary =
    user.emailAddresses.find((e) => e.id === user.primaryEmailAddressId) ??
    user.emailAddresses[0];
  const email = (primary?.emailAddress ?? "").toLowerCase();
  if (!email) throw unauthorized("Account has no email address");
  const name = [user.firstName, user.lastName].filter(Boolean).join(" ") || null;
  const entry = { email, name, at: Date.now() };
  identityCache.set(userId, entry);
  return entry;
}

/** Requires a signed-in identity (Clerk session). Does NOT require an organization. */
export const requireIdentity: RequestHandler = asyncHandler(async (req, _res, next) => {
  const auth = getAuth(req);
  const userId = auth?.userId;
  if (!userId) throw unauthorized();
  const { email, name } = await resolveIdentity(userId);
  req.identity = { userId, email, name };

  // Upsert profile and claim any pre-authorized memberships by email.
  await db
    .insert(userProfilesTable)
    .values({ userId, email, name, lastSignInAt: new Date() })
    .onConflictDoUpdate({
      target: userProfilesTable.userId,
      set: { email, name, lastSignInAt: new Date() },
    });
  await db
    .update(organizationMembersTable)
    .set({ userId })
    .where(and(eq(organizationMembersTable.email, email), isNull(organizationMembersTable.userId)));
  next();
});

export async function loadMemberships(userId: string, email: string) {
  return db
    .select({
      memberId: organizationMembersTable.id,
      role: organizationMembersTable.role,
      organization: organizationsTable,
    })
    .from(organizationMembersTable)
    .innerJoin(organizationsTable, eq(organizationsTable.id, organizationMembersTable.organizationId))
    .where(or(eq(organizationMembersTable.userId, userId), eq(organizationMembersTable.email, email)));
}

/** Requires identity + an active organization membership. Populates req.auth. */
export const requireOrg: RequestHandler = asyncHandler(async (req, res, next) => {
  if (!req.identity) {
    await new Promise<void>((resolve, reject) =>
      requireIdentity(req, res, (err?: unknown) => (err ? reject(err) : resolve())),
    );
  }
  const { userId, email, name } = req.identity!;
  const memberships = await loadMemberships(userId, email);
  if (memberships.length === 0) throw forbidden("You are not a member of any organization");

  const [profile] = await db
    .select({ currentOrganizationId: userProfilesTable.currentOrganizationId })
    .from(userProfilesTable)
    .where(eq(userProfilesTable.userId, userId));
  let current = memberships.find((m) => m.organization.id === profile?.currentOrganizationId);
  if (!current) {
    current = memberships[0]!;
    await db
      .update(userProfilesTable)
      .set({ currentOrganizationId: current.organization.id })
      .where(eq(userProfilesTable.userId, userId));
  }
  req.auth = {
    userId,
    email,
    name,
    organization: current.organization,
    role: current.role,
    memberId: current.memberId,
  };
  next();
});

export const requireRole =
  (min: Role): RequestHandler =>
  (req, _res, next) => {
    if (!req.auth) return next(unauthorized());
    if (!roleAtLeast(req.auth.role, min)) return next(forbidden(`Requires ${min} role or higher`));
    next();
  };

export function ctx(req: Request): AuthContext {
  if (!req.auth) throw unauthorized();
  return req.auth;
}
