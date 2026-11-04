import { Router, type IRouter } from "express";
import { desc, eq } from "drizzle-orm";
import { db, emailDomainAuditsTable } from "@workspace/db";
import { RunEmailDomainAuditBody } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, requireRole, ctx } from "../middlewares/auth";
import { badRequest } from "../lib/errors";
import { audit } from "../lib/audit";
import { rateLimit } from "../lib/rateLimit";
import { normalizeDomain, runEmailAudit } from "../services/emailSecurity";

const router: IRouter = Router();
router.use(requireOrg);

type Stored = { spf: unknown; dmarc: unknown; dkim: unknown[]; mx: string[] };

function serialize(r: typeof emailDomainAuditsTable.$inferSelect) {
  const c = (r.checks as unknown as [Stored])[0] ?? { spf: null, dmarc: null, dkim: [], mx: [] };
  return { id: r.id, domain: r.domain, checkedAt: r.createdAt.toISOString(), checkedByEmail: r.runByEmail, spf: c.spf, dmarc: c.dmarc, dkim: c.dkim, mx: c.mx, overallStatus: r.overallStatus, limitations: r.limitations };
}

router.get("/email-security", asyncHandler(async (req, res) => {
  const { organization } = ctx(req);
  const rows = await db.select().from(emailDomainAuditsTable).where(eq(emailDomainAuditsTable.organizationId, organization.id)).orderBy(desc(emailDomainAuditsTable.createdAt)).limit(50);
  res.json(rows.map(serialize));
}));

router.post("/email-security", requireRole("SECURITY_ANALYST"), rateLimit({ windowMs: 60_000, max: 10, key: (req) => req.auth?.organization.id ?? "anon" }), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const body = RunEmailDomainAuditBody.parse(req.body);
  const domain = normalizeDomain(body.domain);
  if (!domain) throw badRequest("Enter a valid domain name such as example.com");
  const selectors = (body.dkimSelectors ?? []).map((s) => s.trim().toLowerCase()).filter((s) => /^[a-z0-9._-]{1,63}$/.test(s));
  const result = await runEmailAudit(domain, selectors);
  const [row] = await db.insert(emailDomainAuditsTable).values({
    organizationId: a.organization.id, domain, overallStatus: result.overallStatus,
    checks: [{ spf: result.spf, dmarc: result.dmarc, dkim: result.dkim, mx: result.mx }], dkimSelectors: selectors, limitations: result.limitations, runByUserId: a.userId, runByEmail: a.email,
  }).returning();
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "email_audit.run", targetType: "domain", targetId: domain, details: { overallStatus: result.overallStatus }, ipAddress: req.ip });
  res.status(201).json(serialize(row!));
}));

export default router;
