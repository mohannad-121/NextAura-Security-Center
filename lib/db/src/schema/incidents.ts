import {
  bigint,
  index,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";
import { organizationsTable } from "./organizations";
import { devicesTable } from "./devices";
import { securityFindingsTable } from "./assessments";
import {
  confidenceEnum,
  evidenceClassificationEnum,
  incidentStatusEnum,
  severityEnum,
} from "./enums";

export const incidentsTable = pgTable(
  "incidents",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    severity: severityEnum("severity").notNull(),
    status: incidentStatusEnum("status").notNull().default("OPEN"),
    summary: text("summary").notNull().default(""),
    confidence: confidenceEnum("confidence").notNull().default("MEDIUM"),
    evidenceLimitations: text("evidence_limitations")
      .array()
      .notNull()
      .default([]),
    recommendedActions: text("recommended_actions")
      .array()
      .notNull()
      .default([]),
    createdByUserId: text("created_by_user_id").notNull(),
    createdByEmail: text("created_by_email").notNull(),
    assignedToEmail: text("assigned_to_email"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    closedAt: timestamp("closed_at", { withTimezone: true }),
  },
  (t) => [index("incidents_org_updated_idx").on(t.organizationId, t.updatedAt)],
);

export const incidentDevicesTable = pgTable(
  "incident_devices",
  {
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidentsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
  },
  (t) => [
    primaryKey({ columns: [t.incidentId, t.deviceId] }),
    index("incident_devices_device_idx").on(t.deviceId),
  ],
);

export const incidentFindingsTable = pgTable(
  "incident_findings",
  {
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidentsTable.id, { onDelete: "cascade" }),
    findingId: uuid("finding_id")
      .notNull()
      .references(() => securityFindingsTable.id, { onDelete: "cascade" }),
  },
  (t) => [
    primaryKey({ columns: [t.incidentId, t.findingId] }),
    index("incident_findings_finding_idx").on(t.findingId),
  ],
);

export const incidentFileEvidenceTable = pgTable(
  "incident_file_evidence",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidentsTable.id, { onDelete: "cascade" }),
    fileName: text("file_name").notNull(),
    sha256: text("sha256").notNull(),
    sizeBytes: bigint("size_bytes", { mode: "number" }).notNull(),
    detectedType: text("detected_type").notNull(),
    classification: evidenceClassificationEnum("classification").notNull(),
    signatureMetadata: text("signature_metadata").notNull().default("UNKNOWN"),
    reputation: jsonb("reputation")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    indicators: jsonb("indicators").$type<unknown[]>().notNull().default([]),
    archiveSummary: jsonb("archive_summary").$type<Record<
      string,
      unknown
    > | null>(),
    limitations: text("limitations").array().notNull().default([]),
    source: text("source").notNull(),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [index("incident_files_incident_idx").on(t.incidentId, t.observedAt)],
);

export const incidentTimelineTable = pgTable(
  "incident_timeline",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidentsTable.id, { onDelete: "cascade" }),
    occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull(),
    eventType: text("event_type").notNull(),
    title: text("title").notNull(),
    evidence: text("evidence").notNull(),
    source: text("source").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    index("incident_timeline_incident_idx").on(t.incidentId, t.occurredAt),
  ],
);

export type Incident = typeof incidentsTable.$inferSelect;
