import { Router, type IRouter } from "express";
import { and, desc, eq } from "drizzle-orm";
import { db, deviceEnrollmentRequestsTable, devicesTable } from "@workspace/db";
import { CreateEnrollmentBody } from "@workspace/api-zod";
import { asyncHandler } from "../lib/asyncHandler";
import { requireOrg, requireRole, ctx } from "../middlewares/auth";
import { badRequest, notFound } from "../lib/errors";
import { audit } from "../lib/audit";
import {
  generateEnrollmentCode,
  normalizeEnrollmentCode,
  sha256Hex,
} from "../lib/crypto";
import { iso } from "../services/serializers";
import { agentPublicBaseUrl } from "../lib/publicBaseUrl";

const router: IRouter = Router();
router.use(requireOrg);

export const CONSENT_SUMMARY = [
  "Device identity: hostname, OS name/version/build, CPU architecture, model, RAM size and the last 4 characters of the serial number.",
  "Security posture: firewall, disk encryption, update, screen lock, Secure Boot/SIP/Gatekeeper/UAC state and OS support status.",
  "Antivirus: product name, real-time protection state, definition age and the product's own detection history.",
  "Installed software inventory: application names, vendors and versions (used for CVE matching).",
  "Startup persistence inventory: names and locations of autostart entries, services, scheduled tasks and launch agents.",
  "Safe network summary: firewall profiles and legacy protocol state. No traffic is captured.",
  "NOT collected: files, documents, browsing history, keystrokes, screenshots, credentials, email or chat content, or full serial numbers.",
  "The agent is read-only. It never changes settings, deletes files or executes remote commands. Operators can only request a re-assessment of the fixed collectors above.",
];

function serialize(
  e: typeof deviceEnrollmentRequestsTable.$inferSelect,
  deviceName: string | null,
) {
  const status =
    e.status === "PENDING" && e.expiresAt.getTime() < Date.now()
      ? "EXPIRED"
      : e.status;
  return {
    id: e.id,
    osType: e.osType,
    deviceLabel: e.deviceLabel,
    status,
    createdByEmail: e.createdByEmail,
    createdAt: e.createdAt.toISOString(),
    expiresAt: e.expiresAt.toISOString(),
    consumedAt: iso(e.consumedAt),
    deviceId: e.deviceId,
    deviceName,
    codeHint: e.codeHint,
  };
}

async function nameFor(deviceId: string | null) {
  if (!deviceId) return null;
  const [d] = await db
    .select({ name: devicesTable.name })
    .from(devicesTable)
    .where(eq(devicesTable.id, deviceId));
  return d?.name ?? null;
}

router.get(
  "/enrollments",
  asyncHandler(async (req, res) => {
    const { organization } = ctx(req);
    const rows = await db
      .select()
      .from(deviceEnrollmentRequestsTable)
      .where(eq(deviceEnrollmentRequestsTable.organizationId, organization.id))
      .orderBy(desc(deviceEnrollmentRequestsTable.createdAt))
      .limit(100);
    res.json(
      await Promise.all(
        rows.map(async (e) => serialize(e, await nameFor(e.deviceId))),
      ),
    );
  }),
);

router.post(
  "/enrollments",
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const body = CreateEnrollmentBody.parse(req.body);
    if (!a.organization.allowedOsTypes.includes(body.osType))
      throw badRequest(`${body.osType} is not allowed by organization policy`);
    const code = generateEnrollmentCode();
    const expiresAt = new Date(
      Date.now() + a.organization.enrollmentCodeTtlMinutes * 60_000,
    );
    const [e] = await db
      .insert(deviceEnrollmentRequestsTable)
      .values({
        organizationId: a.organization.id,
        osType: body.osType,
        deviceLabel: body.deviceLabel?.trim() || null,
        codeHash: sha256Hex(normalizeEnrollmentCode(code)),
        codeHint: `${code.slice(0, 5)}-…`,
        createdByUserId: a.userId,
        createdByEmail: a.email,
        expiresAt,
      })
      .returning();
    await audit({
      organizationId: a.organization.id,
      actorType: "USER",
      actorId: a.userId,
      actorLabel: a.email,
      action: "enrollment.created",
      targetType: "enrollment",
      targetId: e!.id,
      details: { osType: body.osType },
      ipAddress: req.ip,
    });
    res.status(201).json({
      ...serialize(e!, null),
      code,
      serverUrl: agentPublicBaseUrl(req),
      consentSummary: CONSENT_SUMMARY,
    });
  }),
);

router.get(
  "/enrollments/:id",
  asyncHandler(async (req, res) => {
    const { organization } = ctx(req);
    const [e] = await db
      .select()
      .from(deviceEnrollmentRequestsTable)
      .where(
        and(
          eq(deviceEnrollmentRequestsTable.id, String(req.params["id"])),
          eq(deviceEnrollmentRequestsTable.organizationId, organization.id),
        ),
      );
    if (!e) throw notFound("Enrollment not found");
    res.json(serialize(e, await nameFor(e.deviceId)));
  }),
);

router.delete(
  "/enrollments/:id",
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const a = ctx(req);
    const [e] = await db
      .select()
      .from(deviceEnrollmentRequestsTable)
      .where(
        and(
          eq(deviceEnrollmentRequestsTable.id, String(req.params["id"])),
          eq(deviceEnrollmentRequestsTable.organizationId, a.organization.id),
        ),
      );
    if (!e) throw notFound("Enrollment not found");
    if (e.status === "PENDING") {
      await db
        .update(deviceEnrollmentRequestsTable)
        .set({ status: "CANCELLED" })
        .where(eq(deviceEnrollmentRequestsTable.id, e.id));
      await audit({
        organizationId: a.organization.id,
        actorType: "USER",
        actorId: a.userId,
        actorLabel: a.email,
        action: "enrollment.cancelled",
        targetType: "enrollment",
        targetId: e.id,
        ipAddress: req.ip,
      });
    }
    res.status(204).end();
  }),
);

export default router;
