import { Router, type IRouter } from "express";
import { and, desc, eq, ilike, or } from "drizzle-orm";
import { db, vulnerabilityMatchesTable, devicesTable } from "@workspace/db";
import { ListVulnerabilitiesQueryParams } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, requireRole, ctx } from "../middlewares/auth";
import { tooMany } from "../lib/errors";
import { audit } from "../lib/audit";
import { intelligenceStatus, refreshIntelligence } from "../services/vulnerabilities";
import { iso } from "../services/serializers";

const router: IRouter = Router();
router.use(requireOrg);

router.get("/vulnerabilities", asyncHandler(async (req, res) => {
  const { organization } = ctx(req);
  const q = ListVulnerabilitiesQueryParams.parse(req.query);
  const conds = [eq(vulnerabilityMatchesTable.organizationId, organization.id), eq(vulnerabilityMatchesTable.current, true)];
  if (q.severity) conds.push(eq(vulnerabilityMatchesTable.severity, q.severity));
  if (q.kevOnly) conds.push(eq(vulnerabilityMatchesTable.knownExploited, true));
  if (q.deviceId) conds.push(eq(vulnerabilityMatchesTable.deviceId, q.deviceId));
  if (q.matchConfidence) conds.push(eq(vulnerabilityMatchesTable.matchConfidence, q.matchConfidence));
  if (q.search) {
    const s = `%${q.search.replace(/[%_]/g, "")}%`;
    conds.push(or(ilike(vulnerabilityMatchesTable.cveId, s), ilike(vulnerabilityMatchesTable.product, s), ilike(vulnerabilityMatchesTable.vendor, s), ilike(devicesTable.name, s))!);
  }
  const rows = await db
    .select({ v: vulnerabilityMatchesTable, deviceName: devicesTable.name })
    .from(vulnerabilityMatchesTable)
    .innerJoin(devicesTable, eq(devicesTable.id, vulnerabilityMatchesTable.deviceId))
    .where(and(...conds))
    .orderBy(desc(vulnerabilityMatchesTable.knownExploited), desc(vulnerabilityMatchesTable.cvssScore))
    .limit(2000);
  res.json(rows.map(({ v, deviceName }) => ({
    id: v.id, deviceId: v.deviceId, deviceName, cveId: v.cveId, vendor: v.vendor, product: v.product, installedVersion: v.installedVersion, affectedRange: v.affectedRange,
    severity: v.severity, cvssScore: v.cvssScore, cvssVector: v.cvssVector, knownExploited: v.knownExploited, kevDateAdded: v.kevDateAdded, matchConfidence: v.matchConfidence,
    matchReason: v.matchReason, references: v.references, remediation: v.remediation, description: v.description, publishedAt: iso(v.publishedAt), firstSeenAt: v.firstSeenAt.toISOString(), lastSeenAt: v.lastSeenAt.toISOString(),
  })));
}));

router.get("/vulnerabilities/intelligence", asyncHandler(async (_req, res) => {
  res.json(await intelligenceStatus());
}));

router.post("/vulnerabilities/intelligence", requireRole("SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const a = ctx(req);
  const r = await refreshIntelligence(a.organization.id);
  if (!r.allowed) throw tooMany(`Intelligence was refreshed recently; next allowed at ${r.nextAllowedRefreshAt}`);
  await audit({ organizationId: a.organization.id, actorType: "USER", actorId: a.userId, actorLabel: a.email, action: "intelligence.refresh_requested", ipAddress: req.ip });
  res.status(202).json(await intelligenceStatus());
}));

export default router;
