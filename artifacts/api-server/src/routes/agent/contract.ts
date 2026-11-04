/**
 * Agent <-> server contract (hand-written; mirrored by the Go agent in /agent).
 * Kept outside the dashboard OpenAPI spec on purpose: the agent authenticates
 * with per-device tokens, not with the operator's session.
 */
import { z } from "zod";
import { COLLECTOR_IDS } from "@workspace/db";

export const collectorIdSchema = z.enum(COLLECTOR_IDS);
export const osTypeSchema = z.enum(["WINDOWS", "MACOS"]);
export const architectureSchema = z.enum(["amd64", "arm64", "unknown"]);
export const checkStatusSchema = z.enum([
  "PASS",
  "FAIL",
  "WARNING",
  "UNKNOWN",
  "UNSUPPORTED",
  "PERMISSION_DENIED",
  "STALE",
]);
export const confidenceSchema = z.enum(["HIGH", "MEDIUM", "LOW"]);
export const checkCategorySchema = z.enum([
  "SECURITY_POSTURE",
  "ANTIVIRUS",
  "ENCRYPTION",
  "FIREWALL",
  "UPDATES",
  "OS_SUPPORT",
  "NETWORK",
  "SYSTEM",
]);

const shortStr = (max: number) => z.string().trim().max(max);
const isoDate = z.string().datetime({ offset: true });

export const checkSchema = z.object({
  checkId: shortStr(64).regex(/^[A-Z0-9_.-]+$/i),
  category: checkCategorySchema,
  title: shortStr(160),
  status: checkStatusSchema,
  evidence: shortStr(2000).default(""),
  dataSource: shortStr(200).default(""),
  confidence: confidenceSchema.default("MEDIUM"),
  requiredPermissions: shortStr(200).default(""),
  unavailableReason: shortStr(500).nullable().optional(),
  details: z.record(z.unknown()).optional(),
});
export type AgentCheck = z.infer<typeof checkSchema>;

export const systemInfoSchema = z.object({
  hostname: shortStr(253),
  osName: shortStr(120),
  osVersion: shortStr(80),
  osBuild: shortStr(80).nullable().optional(),
  architecture: architectureSchema,
  cpuModel: shortStr(160).nullable().optional(),
  totalRamMb: z.number().int().nonnegative().nullable().optional(),
  model: shortStr(160).nullable().optional(),
  /** Last 4 characters only; the agent must never send the full serial. */
  serialRedacted: shortStr(16).nullable().optional(),
});

export const antivirusSchema = z.object({
  product: shortStr(160).nullable(),
  status: z.enum(["ACTIVE", "DISABLED", "PASSIVE", "THIRD_PARTY", "UNKNOWN", "UNSUPPORTED", "PERMISSION_DENIED"]),
  realTimeProtection: checkStatusSchema,
  definitionsAgeDays: z.number().int().nonnegative().nullable(),
  lastDefinitionUpdate: isoDate.nullable(),
  source: shortStr(200).nullable(),
  note: shortStr(500).default(""),
});

export const threatSchema = z.object({
  externalId: shortStr(120).nullable().optional(),
  threatName: shortStr(300),
  severity: shortStr(40).nullable().optional(),
  detectedAt: isoDate.nullable().optional(),
  actionTaken: shortStr(120).nullable().optional(),
  product: shortStr(160),
  source: shortStr(200),
});

export const softwareSchema = z.object({
  name: shortStr(300),
  vendor: shortStr(200).nullable().optional(),
  version: shortStr(120).nullable().optional(),
  installedAt: isoDate.nullable().optional(),
  source: shortStr(120),
});

export const startupItemSchema = z.object({
  name: shortStr(300),
  location: shortStr(1000),
  kind: z.enum([
    "REGISTRY_RUN",
    "STARTUP_FOLDER",
    "SCHEDULED_TASK",
    "SERVICE",
    "LAUNCH_AGENT",
    "LAUNCH_DAEMON",
    "LOGIN_ITEM",
    "OTHER",
  ]),
  enabled: z.boolean().nullable().optional(),
  publisher: shortStr(200).nullable().optional(),
});

export const collectorResultSchema = z.object({
  collectorId: collectorIdSchema,
  collectorVersion: shortStr(40),
  status: z.enum(["OK", "FAILED", "UNSUPPORTED", "PERMISSION_DENIED"]),
  error: shortStr(1000).nullable().optional(),
  collectedAt: isoDate,
  checks: z.array(checkSchema).max(200).default([]),
  system: systemInfoSchema.optional(),
  antivirus: antivirusSchema.optional(),
  threats: z.array(threatSchema).max(500).optional(),
  software: z.array(softwareSchema).max(5000).optional(),
  startupItems: z.array(startupItemSchema).max(2000).optional(),
});
export type CollectorResult = z.infer<typeof collectorResultSchema>;

export const enrollBodySchema = z.object({
  code: z.string().trim().min(10).max(40),
  agentVersion: shortStr(40),
  osType: osTypeSchema,
  system: systemInfoSchema,
});

export const heartbeatBodySchema = z.object({
  requestId: shortStr(80),
  agentVersion: shortStr(40),
  timestamp: isoDate,
  uptimeSeconds: z.number().int().nonnegative().nullable().optional(),
  collectorErrors: z
    .array(z.object({ collectorId: collectorIdSchema, message: shortStr(500), occurredAt: isoDate }))
    .max(50)
    .default([]),
});

export const assessmentBodySchema = z.object({
  idempotencyKey: shortStr(80),
  trigger: z.enum(["ENROLLMENT", "SCHEDULED", "MANUAL"]),
  agentVersion: shortStr(40),
  startedAt: isoDate,
  completedAt: isoDate,
  /** The server-side agent request this assessment fulfils, if any. */
  agentRequestId: z.string().uuid().nullable().optional(),
  collectors: z.array(collectorResultSchema).min(1).max(6),
});
export type AssessmentBody = z.infer<typeof assessmentBodySchema>;

export const ackBodySchema = z.object({
  requestId: z.string().uuid(),
  status: z.enum(["ACKNOWLEDGED", "REJECTED"]),
  reason: shortStr(300).optional(),
});

export const AGENT_API_VERSION = "1";
export const DEVICE_TOKEN_TTL_DAYS = 90;
export const DEVICE_TOKEN_PREFIX = "nxa_";
