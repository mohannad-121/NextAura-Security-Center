import {
  pgTable,
  text,
  uuid,
  timestamp,
  integer,
  boolean,
  index,
  jsonb,
} from "drizzle-orm/pg-core";
import { organizationsTable } from "./organizations";
import {
  osTypeEnum,
  deviceStatusEnum,
  enrollmentStatusEnum,
  agentRequestStatusEnum,
} from "./enums";

export const devicesTable = pgTable(
  "devices",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    label: text("label"),
    osType: osTypeEnum("os_type").notNull(),
    osName: text("os_name").notNull().default(""),
    osVersion: text("os_version").notNull().default(""),
    osBuild: text("os_build"),
    architecture: text("architecture").notNull().default("unknown"),
    cpuModel: text("cpu_model"),
    totalRamMb: integer("total_ram_mb"),
    hardwareModel: text("hardware_model"),
    serialRedacted: text("serial_redacted"),
    agentVersion: text("agent_version").notNull().default(""),
    status: deviceStatusEnum("status").notNull().default("ACTIVE"),
    enrolledAt: timestamp("enrolled_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    lastAssessmentAt: timestamp("last_assessment_at", { withTimezone: true }),
    lastAssessmentId: uuid("last_assessment_id"),
    riskScore: integer("risk_score"),
    coveragePercent: integer("coverage_percent").notNull().default(0),
    consecutiveMissedHeartbeats: integer("consecutive_missed_heartbeats")
      .notNull()
      .default(0),
    lastCollectorErrors: jsonb("last_collector_errors")
      .$type<{ collectorId: string; message: string; occurredAt: string }[]>()
      .notNull()
      .default([]),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    index("devices_org_idx").on(t.organizationId),
    index("devices_org_last_seen_idx").on(t.organizationId, t.lastSeenAt),
  ],
);
export type Device = typeof devicesTable.$inferSelect;

/** Per-device credentials. Only the SHA-256 hash of the token is stored. */
export const deviceCredentialsTable = pgTable(
  "device_credentials",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    tokenPrefix: text("token_prefix").notNull(),
    issuedAt: timestamp("issued_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    rotatedFromId: uuid("rotated_from_id"),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (t) => [index("device_credentials_device_idx").on(t.deviceId)],
);
export type DeviceCredential = typeof deviceCredentialsTable.$inferSelect;

export const deviceEnrollmentRequestsTable = pgTable(
  "device_enrollment_requests",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    osType: osTypeEnum("os_type").notNull(),
    deviceLabel: text("device_label"),
    codeHash: text("code_hash").notNull().unique(),
    codeHint: text("code_hint").notNull(),
    status: enrollmentStatusEnum("status").notNull().default("PENDING"),
    createdByUserId: text("created_by_user_id").notNull(),
    createdByEmail: text("created_by_email").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    deviceId: uuid("device_id").references(() => devicesTable.id, {
      onDelete: "set null",
    }),
    attemptCount: integer("attempt_count").notNull().default(0),
  },
  (t) => [index("enrollment_org_idx").on(t.organizationId, t.createdAt)],
);
export type DeviceEnrollmentRequest =
  typeof deviceEnrollmentRequestsTable.$inferSelect;

export const deviceHeartbeatsTable = pgTable(
  "device_heartbeats",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    agentVersion: text("agent_version").notNull(),
    agentTimestamp: timestamp("agent_timestamp", { withTimezone: true }).notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    uptimeSeconds: integer("uptime_seconds"),
    collectorErrors: jsonb("collector_errors")
      .$type<{ collectorId: string; message: string; occurredAt: string }[]>()
      .notNull()
      .default([]),
    requestId: text("request_id").notNull(),
  },
  (t) => [
    index("heartbeats_device_received_idx").on(t.deviceId, t.receivedAt),
    index("heartbeats_org_received_idx").on(t.organizationId, t.receivedAt),
  ],
);

export const agentRequestsTable = pgTable(
  "agent_requests",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    collectors: text("collectors").array().notNull(),
    status: agentRequestStatusEnum("status").notNull().default("PENDING"),
    requestedByUserId: text("requested_by_user_id").notNull(),
    requestedByEmail: text("requested_by_email").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }),
    acknowledgedAt: timestamp("acknowledged_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    rejectionReason: text("rejection_reason"),
  },
  (t) => [index("agent_requests_device_status_idx").on(t.deviceId, t.status)],
);
export type AgentRequest = typeof agentRequestsTable.$inferSelect;

/** Tracks idempotency keys / request ids already processed per device (replay protection). */
export const agentRequestReplayTable = pgTable(
  "agent_request_replay",
  {
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    requestId: text("request_id").notNull(),
    seenAt: timestamp("seen_at", { withTimezone: true }).notNull().defaultNow(),
    processed: boolean("processed").notNull().default(true),
  },
  (t) => [
    index("replay_device_request_idx").on(t.deviceId, t.requestId),
    index("replay_seen_idx").on(t.seenAt),
  ],
);
