import {
  pgTable,
  uuid,
  text,
  timestamp,
  integer,
  bigint,
  boolean,
  jsonb,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { organizationsTable } from "./organizations";
import { devicesTable, agentRequestsTable } from "./devices";
import {
  agentOperationEnum,
  confidenceEnum,
  evidenceClassificationEnum,
  scanJobStatusEnum,
  scanTypeEnum,
  severityEnum,
} from "./enums";

export const deviceScanScopesTable = pgTable(
  "device_scan_scopes",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    scopeId: text("scope_id").notNull(),
    label: text("label").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    lastReportedAt: timestamp("last_reported_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("device_scan_scopes_device_scope_idx").on(
      t.deviceId,
      t.scopeId,
    ),
    index("device_scan_scopes_org_idx").on(t.organizationId, t.deviceId),
  ],
);

export const scanJobsTable = pgTable(
  "scan_jobs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    scanType: scanTypeEnum("scan_type").notNull(),
    status: scanJobStatusEnum("status").notNull().default("QUEUED"),
    collectors: text("collectors").array().notNull().default([]),
    scopeId: text("scope_id"),
    requestedByUserId: text("requested_by_user_id").notNull(),
    requestedByEmail: text("requested_by_email").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    cancellationRequestedAt: timestamp("cancellation_requested_at", {
      withTimezone: true,
    }),
  },
  (t) => [index("scan_jobs_org_created_idx").on(t.organizationId, t.createdAt)],
);

export const scanJobDevicesTable = pgTable(
  "scan_job_devices",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    scanJobId: uuid("scan_job_id")
      .notNull()
      .references(() => scanJobsTable.id, { onDelete: "cascade" }),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    agentRequestId: uuid("agent_request_id").references(
      () => agentRequestsTable.id,
      { onDelete: "set null" },
    ),
    operation: agentOperationEnum("operation").notNull(),
    scopeId: text("scope_id"),
    status: scanJobStatusEnum("status").notNull().default("WAITING_FOR_AGENT"),
    stage: text("stage").notNull().default("Awaiting agent pickup"),
    filesObserved: integer("files_observed").notNull().default(0),
    evidenceCount: integer("evidence_count").notNull().default(0),
    collectorFailures: jsonb("collector_failures")
      .$type<Array<{ collectorId: string; reason: string }>>()
      .notNull()
      .default([]),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    error: text("error"),
  },
  (t) => [
    uniqueIndex("scan_job_devices_job_device_idx").on(t.scanJobId, t.deviceId),
    index("scan_job_devices_device_status_idx").on(t.deviceId, t.status),
  ],
);

export const scanFileEvidenceTable = pgTable(
  "scan_file_evidence",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    scanJobId: uuid("scan_job_id")
      .notNull()
      .references(() => scanJobsTable.id, { onDelete: "cascade" }),
    agentRequestId: uuid("agent_request_id")
      .notNull()
      .references(() => agentRequestsTable.id, { onDelete: "cascade" }),
    evidenceKey: text("evidence_key").notNull(),
    fileName: text("file_name").notNull(),
    relativePathHash: text("relative_path_hash").notNull(),
    sha256: text("sha256").notNull(),
    sizeBytes: bigint("size_bytes", { mode: "number" }).notNull(),
    detectedType: text("detected_type").notNull(),
    classification: evidenceClassificationEnum("classification").notNull(),
    severity: severityEnum("severity").notNull(),
    confidence: confidenceEnum("confidence").notNull(),
    detectorId: text("detector_id").notNull(),
    detectorVersion: text("detector_version").notNull(),
    evidenceSource: text("evidence_source").notNull(),
    signatureMetadata: text("signature_metadata").notNull().default("UNKNOWN"),
    indicators: jsonb("indicators").notNull().default([]),
    archiveSummary: jsonb("archive_summary"),
    peMetadata: jsonb("pe_metadata"),
    limitations: text("limitations").array().notNull().default([]),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    uniqueIndex("scan_file_evidence_request_key_idx").on(
      t.agentRequestId,
      t.evidenceKey,
    ),
    index("scan_file_evidence_job_idx").on(t.scanJobId, t.observedAt),
    index("scan_file_evidence_device_idx").on(t.deviceId, t.observedAt),
  ],
);
