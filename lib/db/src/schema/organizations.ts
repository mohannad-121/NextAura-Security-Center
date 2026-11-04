import {
  pgTable,
  text,
  uuid,
  timestamp,
  integer,
  boolean,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { osTypeEnum, roleEnum } from "./enums";

export const organizationsTable = pgTable("organizations", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  isDemo: boolean("is_demo").notNull().default(false),
  retentionDays: integer("retention_days").notNull().default(90),
  heartbeatIntervalMinutes: integer("heartbeat_interval_minutes")
    .notNull()
    .default(5),
  postureIntervalHours: integer("posture_interval_hours").notNull().default(6),
  inventoryIntervalHours: integer("inventory_interval_hours")
    .notNull()
    .default(24),
  enrollmentCodeTtlMinutes: integer("enrollment_code_ttl_minutes")
    .notNull()
    .default(15),
  onlineThresholdMinutes: integer("online_threshold_minutes")
    .notNull()
    .default(12),
  allowedOsTypes: osTypeEnum("allowed_os_types")
    .array()
    .notNull()
    .default(["WINDOWS", "MACOS"]),
  minimumAgentVersion: text("minimum_agent_version").notNull().default("0.1.0"),
  requireMfa: boolean("require_mfa").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
});
export type Organization = typeof organizationsTable.$inferSelect;

/** Identity-provider users known to the system (Clerk user id). */
export const userProfilesTable = pgTable("user_profiles", {
  userId: text("user_id").primaryKey(),
  email: text("email").notNull(),
  name: text("name"),
  currentOrganizationId: uuid("current_organization_id").references(
    () => organizationsTable.id,
    { onDelete: "set null" },
  ),
  lastSignInAt: timestamp("last_sign_in_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});
export type UserProfile = typeof userProfilesTable.$inferSelect;

/** Membership by email so owners can authorize people before they first sign in. */
export const organizationMembersTable = pgTable(
  "organization_members",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizationsTable.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    userId: text("user_id"),
    role: roleEnum("role").notNull().default("VIEWER"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    uniqueIndex("org_members_org_email_idx").on(t.organizationId, t.email),
    index("org_members_user_idx").on(t.userId),
  ],
);
export type OrganizationMember = typeof organizationMembersTable.$inferSelect;
