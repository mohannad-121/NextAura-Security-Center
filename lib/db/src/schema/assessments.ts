import {
  pgTable,
  text,
  uuid,
  timestamp,
  integer,
  boolean,
  index,
  uniqueIndex,
  jsonb,
  real,
} from "drizzle-orm/pg-core";
import { organizationsTable } from "./organizations";
import { devicesTable } from "./devices";
import {
  assessmentTriggerEnum,
  assessmentStatusEnum,
  checkStatusEnum,
  confidenceEnum,
  severityEnum,
  findingStatusEnum,
  matchConfidenceEnum,
} from "./enums";

export const assessmentsTable = pgTable(
  "assessments",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    idempotencyKey: text("idempotency_key").notNull(),
    trigger: assessmentTriggerEnum("trigger").notNull(),
    status: assessmentStatusEnum("status").notNull(),
    agentVersion: text("agent_version").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }).notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    collectorsRequested: text("collectors_requested").array().notNull(),
    collectorsSucceeded: text("collectors_succeeded").array().notNull(),
    collectorsFailed: text("collectors_failed").array().notNull(),
    riskScore: integer("risk_score"),
    coveragePercent: integer("coverage_percent").notNull().default(0),
    checkCounts: jsonb("check_counts")
      .$type<Record<string, number>>()
      .notNull()
      .default({}),
    agentRequestId: uuid("agent_request_id"),
  },
  (t) => [
    uniqueIndex("assessments_device_idem_idx").on(t.deviceId, t.idempotencyKey),
    index("assessments_org_received_idx").on(t.organizationId, t.receivedAt),
    index("assessments_device_received_idx").on(t.deviceId, t.receivedAt),
  ],
);
export type Assessment = typeof assessmentsTable.$inferSelect;

export const assessmentChecksTable = pgTable(
  "assessment_checks",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    assessmentId: uuid("assessment_id")
      .notNull()
      .references(() => assessmentsTable.id, { onDelete: "cascade" }),
    collectorId: text("collector_id").notNull(),
    checkId: text("check_id").notNull(),
    category: text("category").notNull(),
    title: text("title").notNull(),
    status: checkStatusEnum("status").notNull(),
    evidence: text("evidence").notNull().default(""),
    collectedAt: timestamp("collected_at", { withTimezone: true }).notNull(),
    dataSource: text("data_source").notNull().default(""),
    confidence: confidenceEnum("confidence").notNull().default("MEDIUM"),
    requiredPermissions: text("required_permissions").notNull().default(""),
    unavailableReason: text("unavailable_reason"),
    collectorVersion: text("collector_version").notNull().default(""),
    /** Structured, non-sensitive details (e.g. definitions age) used by rules. */
    details: jsonb("details").$type<Record<string, unknown>>().notNull().default({}),
  },
  (t) => [
    index("checks_assessment_idx").on(t.assessmentId),
    index("checks_device_check_idx").on(t.deviceId, t.checkId),
  ],
);
export type AssessmentCheck = typeof assessmentChecksTable.$inferSelect;

export const softwareInventoryTable = pgTable(
  "software_inventory",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    assessmentId: uuid("assessment_id").references(() => assessmentsTable.id, {
      onDelete: "set null",
    }),
    name: text("name").notNull(),
    normalizedName: text("normalized_name").notNull(),
    vendor: text("vendor"),
    normalizedVendor: text("normalized_vendor"),
    version: text("version"),
    installedAt: timestamp("installed_at", { withTimezone: true }),
    source: text("source").notNull(),
    collectedAt: timestamp("collected_at", { withTimezone: true }).notNull(),
    current: boolean("current").notNull().default(true),
  },
  (t) => [
    index("software_device_current_idx").on(t.deviceId, t.current),
    index("software_org_norm_idx").on(t.organizationId, t.normalizedName),
  ],
);
export type SoftwareItem = typeof softwareInventoryTable.$inferSelect;

export const startupItemsTable = pgTable(
  "startup_items",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    assessmentId: uuid("assessment_id").references(() => assessmentsTable.id, {
      onDelete: "set null",
    }),
    name: text("name").notNull(),
    location: text("location").notNull(),
    kind: text("kind").notNull(),
    enabled: boolean("enabled"),
    publisher: text("publisher"),
    collectedAt: timestamp("collected_at", { withTimezone: true }).notNull(),
    current: boolean("current").notNull().default(true),
  },
  (t) => [index("startup_device_current_idx").on(t.deviceId, t.current)],
);

export const threatDetectionsTable = pgTable(
  "threat_detections",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    assessmentId: uuid("assessment_id").references(() => assessmentsTable.id, {
      onDelete: "set null",
    }),
    externalId: text("external_id"),
    threatName: text("threat_name").notNull(),
    severity: text("severity"),
    detectedAt: timestamp("detected_at", { withTimezone: true }),
    actionTaken: text("action_taken"),
    product: text("product").notNull(),
    source: text("source").notNull(),
    collectedAt: timestamp("collected_at", { withTimezone: true }).notNull(),
  },
  (t) => [index("threats_device_idx").on(t.deviceId, t.detectedAt)],
);

export const securityFindingsTable = pgTable(
  "security_findings",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    ruleId: text("rule_id").notNull(),
    /** Discriminator for rules that can fire more than once per device (e.g. per CVE). */
    fingerprint: text("fingerprint").notNull(),
    title: text("title").notNull(),
    description: text("description").notNull(),
    severity: severityEnum("severity").notNull(),
    confidence: confidenceEnum("confidence").notNull(),
    evidence: text("evidence").notNull(),
    detectionSource: text("detection_source").notNull(),
    remediation: text("remediation").notNull(),
    status: findingStatusEnum("status").notNull().default("OPEN"),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    // provenance
    assessmentId: uuid("assessment_id"),
    collectorId: text("collector_id"),
    rawStatus: text("raw_status"),
    collectorVersion: text("collector_version"),
    observedAt: timestamp("observed_at", { withTimezone: true }),
    statusChangedByUserId: text("status_changed_by_user_id"),
    statusChangedByEmail: text("status_changed_by_email"),
    statusChangedAt: timestamp("status_changed_at", { withTimezone: true }),
    statusNote: text("status_note"),
  },
  (t) => [
    uniqueIndex("findings_device_fp_idx").on(t.deviceId, t.fingerprint),
    index("findings_org_status_idx").on(t.organizationId, t.status),
  ],
);
export type SecurityFinding = typeof securityFindingsTable.$inferSelect;

export const vulnerabilityMatchesTable = pgTable(
  "vulnerability_matches",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    deviceId: uuid("device_id")
      .notNull()
      .references(() => devicesTable.id, { onDelete: "cascade" }),
    softwareId: uuid("software_id").references(() => softwareInventoryTable.id, {
      onDelete: "set null",
    }),
    cveId: text("cve_id").notNull(),
    vendor: text("vendor").notNull(),
    product: text("product").notNull(),
    installedVersion: text("installed_version").notNull(),
    affectedRange: text("affected_range").notNull(),
    severity: severityEnum("severity").notNull(),
    cvssScore: real("cvss_score"),
    cvssVector: text("cvss_vector"),
    knownExploited: boolean("known_exploited").notNull().default(false),
    kevDateAdded: text("kev_date_added"),
    matchConfidence: matchConfidenceEnum("match_confidence").notNull(),
    matchReason: text("match_reason").notNull(),
    references: text("references").array().notNull().default([]),
    remediation: text("remediation").notNull(),
    description: text("description").notNull().default(""),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    current: boolean("current").notNull().default(true),
  },
  (t) => [
    uniqueIndex("vuln_device_cve_product_idx").on(t.deviceId, t.cveId, t.product, t.installedVersion),
    index("vuln_org_current_idx").on(t.organizationId, t.current),
  ],
);
export type VulnerabilityMatch = typeof vulnerabilityMatchesTable.$inferSelect;
