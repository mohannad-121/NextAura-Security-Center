import {
  pgTable,
  text,
  uuid,
  timestamp,
  integer,
  boolean,
  index,
  jsonb,
  real,
} from "drizzle-orm/pg-core";
import { organizationsTable } from "./organizations";
import { devicesTable } from "./devices";
import { reportTypeEnum, reportStatusEnum, actorTypeEnum, severityEnum } from "./enums";

export const auditLogsTable = pgTable(
  "audit_logs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    actorType: actorTypeEnum("actor_type").notNull(),
    actorId: text("actor_id"),
    actorLabel: text("actor_label").notNull(),
    action: text("action").notNull(),
    targetType: text("target_type"),
    targetId: text("target_id"),
    details: jsonb("details").$type<Record<string, unknown>>().notNull().default({}),
    ipAddress: text("ip_address"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [index("audit_org_created_idx").on(t.organizationId, t.createdAt)],
);
export type AuditLog = typeof auditLogsTable.$inferSelect;

export const reportExportsTable = pgTable(
  "report_exports",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    type: reportTypeEnum("type").notNull(),
    status: reportStatusEnum("status").notNull(),
    deviceId: uuid("device_id").references(() => devicesTable.id, {
      onDelete: "set null",
    }),
    fileName: text("file_name").notNull(),
    mimeType: text("mime_type").notNull(),
    sizeBytes: integer("size_bytes").notNull().default(0),
    content: text("content_base64").notNull(),
    generatedByUserId: text("generated_by_user_id").notNull(),
    generatedByEmail: text("generated_by_email").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    errorMessage: text("error_message"),
  },
  (t) => [index("reports_org_created_idx").on(t.organizationId, t.createdAt)],
);
export type ReportExport = typeof reportExportsTable.$inferSelect;

export const emailDomainAuditsTable = pgTable(
  "email_domain_audits",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    domain: text("domain").notNull(),
    overallStatus: text("overall_status").notNull(),
    checks: jsonb("checks").$type<unknown[]>().notNull().default([]),
    dkimSelectors: text("dkim_selectors").array().notNull().default([]),
    limitations: text("limitations").notNull(),
    runByUserId: text("run_by_user_id").notNull(),
    runByEmail: text("run_by_email").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [index("email_audit_org_idx").on(t.organizationId, t.createdAt)],
);
export type EmailDomainAuditRow = typeof emailDomainAuditsTable.$inferSelect;

/** Global (not org-scoped) cache of NVD CVE records. */
export const cveCacheTable = pgTable(
  "cve_cache",
  {
    cveId: text("cve_id").primaryKey(),
    description: text("description").notNull().default(""),
    severity: severityEnum("severity").notNull(),
    cvssScore: real("cvss_score"),
    cvssVector: text("cvss_vector"),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    lastModifiedAt: timestamp("last_modified_at", { withTimezone: true }),
    references: text("references").array().notNull().default([]),
    /** CPE match criteria + version ranges extracted from NVD configurations. */
    configurations: jsonb("configurations")
      .$type<
        {
          vendor: string;
          product: string;
          versionStartIncluding?: string;
          versionStartExcluding?: string;
          versionEndIncluding?: string;
          versionEndExcluding?: string;
          exactVersion?: string;
        }[]
      >()
      .notNull()
      .default([]),
    fetchedAt: timestamp("fetched_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
);

/** Global cache of the CISA Known Exploited Vulnerabilities catalog. */
export const kevCatalogTable = pgTable("kev_catalog", {
  cveId: text("cve_id").primaryKey(),
  vendorProject: text("vendor_project").notNull(),
  product: text("product").notNull(),
  vulnerabilityName: text("vulnerability_name").notNull(),
  dateAdded: text("date_added").notNull(),
  dueDate: text("due_date"),
  requiredAction: text("required_action").notNull().default(""),
  knownRansomwareUse: boolean("known_ransomware_use").notNull().default(false),
  fetchedAt: timestamp("fetched_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

/** Cache of NVD keyword/CPE queries per normalized product so we respect rate limits. */
export const cveProductQueriesTable = pgTable("cve_product_queries", {
  queryKey: text("query_key").primaryKey(),
  cveIds: text("cve_ids").array().notNull().default([]),
  fetchedAt: timestamp("fetched_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  error: text("error"),
});

/** Single-row state for intelligence feeds. */
export const intelligenceStateTable = pgTable("intelligence_state", {
  id: text("id").primaryKey(),
  nvdLastSyncAt: timestamp("nvd_last_sync_at", { withTimezone: true }),
  nvdLastStatus: text("nvd_last_status").notNull().default("NEVER"),
  nvdLastError: text("nvd_last_error"),
  kevLastSyncAt: timestamp("kev_last_sync_at", { withTimezone: true }),
  kevLastStatus: text("kev_last_status").notNull().default("NEVER"),
  kevLastError: text("kev_last_error"),
  kevCount: integer("kev_count").notNull().default(0),
  lastManualRefreshAt: timestamp("last_manual_refresh_at", { withTimezone: true }),
});
