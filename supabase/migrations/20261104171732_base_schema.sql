CREATE TYPE "public"."actor_type" AS ENUM('USER', 'DEVICE', 'SYSTEM');--> statement-breakpoint
CREATE TYPE "public"."agent_request_status" AS ENUM('PENDING', 'DELIVERED', 'ACKNOWLEDGED', 'COMPLETED', 'EXPIRED', 'REJECTED');--> statement-breakpoint
CREATE TYPE "public"."assessment_status" AS ENUM('COMPLETE', 'PARTIAL', 'FAILED');--> statement-breakpoint
CREATE TYPE "public"."assessment_trigger" AS ENUM('ENROLLMENT', 'SCHEDULED', 'MANUAL');--> statement-breakpoint
CREATE TYPE "public"."check_status" AS ENUM('PASS', 'FAIL', 'WARNING', 'UNKNOWN', 'UNSUPPORTED', 'PERMISSION_DENIED', 'STALE');--> statement-breakpoint
CREATE TYPE "public"."confidence" AS ENUM('HIGH', 'MEDIUM', 'LOW');--> statement-breakpoint
CREATE TYPE "public"."device_status" AS ENUM('ACTIVE', 'REVOKED');--> statement-breakpoint
CREATE TYPE "public"."enrollment_status" AS ENUM('PENDING', 'CONSUMED', 'EXPIRED', 'CANCELLED');--> statement-breakpoint
CREATE TYPE "public"."finding_status" AS ENUM('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE');--> statement-breakpoint
CREATE TYPE "public"."match_confidence" AS ENUM('CONFIRMED', 'PROBABLE', 'POSSIBLE', 'UNKNOWN');--> statement-breakpoint
CREATE TYPE "public"."os_type" AS ENUM('WINDOWS', 'MACOS');--> statement-breakpoint
CREATE TYPE "public"."report_status" AS ENUM('COMPLETED', 'FAILED');--> statement-breakpoint
CREATE TYPE "public"."report_type" AS ENUM('DEVICE_PDF', 'ORGANIZATION_PDF', 'FINDINGS_CSV');--> statement-breakpoint
CREATE TYPE "public"."member_role" AS ENUM('OWNER', 'ADMIN', 'SECURITY_ANALYST', 'VIEWER');--> statement-breakpoint
CREATE TYPE "public"."severity" AS ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');--> statement-breakpoint
CREATE TABLE "assessment_checks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"assessment_id" uuid NOT NULL,
	"collector_id" text NOT NULL,
	"check_id" text NOT NULL,
	"category" text NOT NULL,
	"title" text NOT NULL,
	"status" "check_status" NOT NULL,
	"evidence" text DEFAULT '' NOT NULL,
	"collected_at" timestamp with time zone NOT NULL,
	"data_source" text DEFAULT '' NOT NULL,
	"confidence" "confidence" DEFAULT 'MEDIUM' NOT NULL,
	"required_permissions" text DEFAULT '' NOT NULL,
	"unavailable_reason" text,
	"collector_version" text DEFAULT '' NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "assessments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"idempotency_key" text NOT NULL,
	"trigger" "assessment_trigger" NOT NULL,
	"status" "assessment_status" NOT NULL,
	"agent_version" text NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"collectors_requested" text[] NOT NULL,
	"collectors_succeeded" text[] NOT NULL,
	"collectors_failed" text[] NOT NULL,
	"risk_score" integer,
	"coverage_percent" integer DEFAULT 0 NOT NULL,
	"check_counts" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"agent_request_id" uuid
);
--> statement-breakpoint
CREATE TABLE "security_findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"rule_id" text NOT NULL,
	"fingerprint" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"severity" "severity" NOT NULL,
	"confidence" "confidence" NOT NULL,
	"evidence" text NOT NULL,
	"detection_source" text NOT NULL,
	"remediation" text NOT NULL,
	"status" "finding_status" DEFAULT 'OPEN' NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"assessment_id" uuid,
	"collector_id" text,
	"raw_status" text,
	"collector_version" text,
	"observed_at" timestamp with time zone,
	"status_changed_by_user_id" text,
	"status_changed_by_email" text,
	"status_changed_at" timestamp with time zone,
	"status_note" text
);
--> statement-breakpoint
CREATE TABLE "software_inventory" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"assessment_id" uuid,
	"name" text NOT NULL,
	"normalized_name" text NOT NULL,
	"vendor" text,
	"normalized_vendor" text,
	"version" text,
	"installed_at" timestamp with time zone,
	"source" text NOT NULL,
	"collected_at" timestamp with time zone NOT NULL,
	"current" boolean DEFAULT true NOT NULL
);
--> statement-breakpoint
CREATE TABLE "startup_items" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"assessment_id" uuid,
	"name" text NOT NULL,
	"location" text NOT NULL,
	"kind" text NOT NULL,
	"enabled" boolean,
	"publisher" text,
	"collected_at" timestamp with time zone NOT NULL,
	"current" boolean DEFAULT true NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threat_detections" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"assessment_id" uuid,
	"external_id" text,
	"threat_name" text NOT NULL,
	"severity" text,
	"detected_at" timestamp with time zone,
	"action_taken" text,
	"product" text NOT NULL,
	"source" text NOT NULL,
	"collected_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vulnerability_matches" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"software_id" uuid,
	"cve_id" text NOT NULL,
	"vendor" text NOT NULL,
	"product" text NOT NULL,
	"installed_version" text NOT NULL,
	"affected_range" text NOT NULL,
	"severity" "severity" NOT NULL,
	"cvss_score" real,
	"cvss_vector" text,
	"known_exploited" boolean DEFAULT false NOT NULL,
	"kev_date_added" text,
	"match_confidence" "match_confidence" NOT NULL,
	"match_reason" text NOT NULL,
	"references" text[] DEFAULT '{}' NOT NULL,
	"remediation" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"published_at" timestamp with time zone,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"current" boolean DEFAULT true NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_request_replay" (
	"device_id" uuid NOT NULL,
	"request_id" text NOT NULL,
	"seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"processed" boolean DEFAULT true NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"collectors" text[] NOT NULL,
	"status" "agent_request_status" DEFAULT 'PENDING' NOT NULL,
	"requested_by_user_id" text NOT NULL,
	"requested_by_email" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"delivered_at" timestamp with time zone,
	"acknowledged_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"rejection_reason" text
);
--> statement-breakpoint
CREATE TABLE "device_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"token_prefix" text NOT NULL,
	"issued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"rotated_from_id" uuid,
	"last_used_at" timestamp with time zone,
	CONSTRAINT "device_credentials_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "device_enrollment_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"os_type" "os_type" NOT NULL,
	"device_label" text,
	"code_hash" text NOT NULL,
	"code_hint" text NOT NULL,
	"status" "enrollment_status" DEFAULT 'PENDING' NOT NULL,
	"created_by_user_id" text NOT NULL,
	"created_by_email" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"device_id" uuid,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	CONSTRAINT "device_enrollment_requests_code_hash_unique" UNIQUE("code_hash")
);
--> statement-breakpoint
CREATE TABLE "device_heartbeats" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"agent_version" text NOT NULL,
	"agent_timestamp" timestamp with time zone NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"uptime_seconds" integer,
	"collector_errors" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"request_id" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "devices" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"name" text NOT NULL,
	"label" text,
	"os_type" "os_type" NOT NULL,
	"os_name" text DEFAULT '' NOT NULL,
	"os_version" text DEFAULT '' NOT NULL,
	"os_build" text,
	"architecture" text DEFAULT 'unknown' NOT NULL,
	"cpu_model" text,
	"total_ram_mb" integer,
	"hardware_model" text,
	"serial_redacted" text,
	"agent_version" text DEFAULT '' NOT NULL,
	"status" "device_status" DEFAULT 'ACTIVE' NOT NULL,
	"enrolled_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked_at" timestamp with time zone,
	"last_seen_at" timestamp with time zone,
	"last_assessment_at" timestamp with time zone,
	"last_assessment_id" uuid,
	"risk_score" integer,
	"coverage_percent" integer DEFAULT 0 NOT NULL,
	"consecutive_missed_heartbeats" integer DEFAULT 0 NOT NULL,
	"last_collector_errors" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organization_members" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"email" text NOT NULL,
	"user_id" text,
	"role" "member_role" DEFAULT 'VIEWER' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"is_demo" boolean DEFAULT false NOT NULL,
	"retention_days" integer DEFAULT 90 NOT NULL,
	"heartbeat_interval_minutes" integer DEFAULT 5 NOT NULL,
	"posture_interval_hours" integer DEFAULT 6 NOT NULL,
	"inventory_interval_hours" integer DEFAULT 24 NOT NULL,
	"enrollment_code_ttl_minutes" integer DEFAULT 15 NOT NULL,
	"online_threshold_minutes" integer DEFAULT 12 NOT NULL,
	"allowed_os_types" "os_type"[] DEFAULT '{"WINDOWS","MACOS"}' NOT NULL,
	"minimum_agent_version" text DEFAULT '0.1.0' NOT NULL,
	"require_mfa" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organizations_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "user_profiles" (
	"user_id" text PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"name" text,
	"current_organization_id" uuid,
	"last_sign_in_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"actor_type" "actor_type" NOT NULL,
	"actor_id" text,
	"actor_label" text NOT NULL,
	"action" text NOT NULL,
	"target_type" text,
	"target_id" text,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ip_address" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cve_cache" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"severity" "severity" NOT NULL,
	"cvss_score" real,
	"cvss_vector" text,
	"published_at" timestamp with time zone,
	"last_modified_at" timestamp with time zone,
	"references" text[] DEFAULT '{}' NOT NULL,
	"configurations" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cve_product_queries" (
	"query_key" text PRIMARY KEY NOT NULL,
	"cve_ids" text[] DEFAULT '{}' NOT NULL,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL,
	"error" text
);
--> statement-breakpoint
CREATE TABLE "email_domain_audits" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"domain" text NOT NULL,
	"overall_status" text NOT NULL,
	"checks" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"dkim_selectors" text[] DEFAULT '{}' NOT NULL,
	"limitations" text NOT NULL,
	"run_by_user_id" text NOT NULL,
	"run_by_email" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "intelligence_state" (
	"id" text PRIMARY KEY NOT NULL,
	"nvd_last_sync_at" timestamp with time zone,
	"nvd_last_status" text DEFAULT 'NEVER' NOT NULL,
	"nvd_last_error" text,
	"kev_last_sync_at" timestamp with time zone,
	"kev_last_status" text DEFAULT 'NEVER' NOT NULL,
	"kev_last_error" text,
	"kev_count" integer DEFAULT 0 NOT NULL,
	"last_manual_refresh_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "kev_catalog" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"vendor_project" text NOT NULL,
	"product" text NOT NULL,
	"vulnerability_name" text NOT NULL,
	"date_added" text NOT NULL,
	"due_date" text,
	"required_action" text DEFAULT '' NOT NULL,
	"known_ransomware_use" boolean DEFAULT false NOT NULL,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report_exports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"type" "report_type" NOT NULL,
	"status" "report_status" NOT NULL,
	"device_id" uuid,
	"file_name" text NOT NULL,
	"mime_type" text NOT NULL,
	"size_bytes" integer DEFAULT 0 NOT NULL,
	"content_base64" text NOT NULL,
	"generated_by_user_id" text NOT NULL,
	"generated_by_email" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"error_message" text
);
--> statement-breakpoint
ALTER TABLE "assessment_checks" ADD CONSTRAINT "assessment_checks_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_checks" ADD CONSTRAINT "assessment_checks_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_checks" ADD CONSTRAINT "assessment_checks_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessments" ADD CONSTRAINT "assessments_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessments" ADD CONSTRAINT "assessments_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_findings" ADD CONSTRAINT "security_findings_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_findings" ADD CONSTRAINT "security_findings_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "software_inventory" ADD CONSTRAINT "software_inventory_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "software_inventory" ADD CONSTRAINT "software_inventory_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "software_inventory" ADD CONSTRAINT "software_inventory_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "startup_items" ADD CONSTRAINT "startup_items_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "startup_items" ADD CONSTRAINT "startup_items_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "startup_items" ADD CONSTRAINT "startup_items_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_detections" ADD CONSTRAINT "threat_detections_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_detections" ADD CONSTRAINT "threat_detections_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_detections" ADD CONSTRAINT "threat_detections_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_matches" ADD CONSTRAINT "vulnerability_matches_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_matches" ADD CONSTRAINT "vulnerability_matches_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_matches" ADD CONSTRAINT "vulnerability_matches_software_id_software_inventory_id_fk" FOREIGN KEY ("software_id") REFERENCES "public"."software_inventory"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_request_replay" ADD CONSTRAINT "agent_request_replay_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_requests" ADD CONSTRAINT "agent_requests_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_requests" ADD CONSTRAINT "agent_requests_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_credentials" ADD CONSTRAINT "device_credentials_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_credentials" ADD CONSTRAINT "device_credentials_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_enrollment_requests" ADD CONSTRAINT "device_enrollment_requests_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_enrollment_requests" ADD CONSTRAINT "device_enrollment_requests_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_heartbeats" ADD CONSTRAINT "device_heartbeats_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_heartbeats" ADD CONSTRAINT "device_heartbeats_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "devices" ADD CONSTRAINT "devices_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_members" ADD CONSTRAINT "organization_members_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_profiles" ADD CONSTRAINT "user_profiles_current_organization_id_organizations_id_fk" FOREIGN KEY ("current_organization_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_domain_audits" ADD CONSTRAINT "email_domain_audits_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_exports" ADD CONSTRAINT "report_exports_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_exports" ADD CONSTRAINT "report_exports_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "checks_assessment_idx" ON "assessment_checks" USING btree ("assessment_id");--> statement-breakpoint
CREATE INDEX "checks_device_check_idx" ON "assessment_checks" USING btree ("device_id","check_id");--> statement-breakpoint
CREATE UNIQUE INDEX "assessments_device_idem_idx" ON "assessments" USING btree ("device_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "assessments_org_received_idx" ON "assessments" USING btree ("organization_id","received_at");--> statement-breakpoint
CREATE INDEX "assessments_device_received_idx" ON "assessments" USING btree ("device_id","received_at");--> statement-breakpoint
CREATE UNIQUE INDEX "findings_device_fp_idx" ON "security_findings" USING btree ("device_id","fingerprint");--> statement-breakpoint
CREATE INDEX "findings_org_status_idx" ON "security_findings" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "software_device_current_idx" ON "software_inventory" USING btree ("device_id","current");--> statement-breakpoint
CREATE INDEX "software_org_norm_idx" ON "software_inventory" USING btree ("organization_id","normalized_name");--> statement-breakpoint
CREATE INDEX "startup_device_current_idx" ON "startup_items" USING btree ("device_id","current");--> statement-breakpoint
CREATE INDEX "threats_device_idx" ON "threat_detections" USING btree ("device_id","detected_at");--> statement-breakpoint
CREATE UNIQUE INDEX "vuln_device_cve_product_idx" ON "vulnerability_matches" USING btree ("device_id","cve_id","product","installed_version");--> statement-breakpoint
CREATE INDEX "vuln_org_current_idx" ON "vulnerability_matches" USING btree ("organization_id","current");--> statement-breakpoint
CREATE UNIQUE INDEX "replay_device_request_idx" ON "agent_request_replay" USING btree ("device_id","request_id");--> statement-breakpoint
CREATE INDEX "replay_seen_idx" ON "agent_request_replay" USING btree ("seen_at");--> statement-breakpoint
CREATE INDEX "agent_requests_device_status_idx" ON "agent_requests" USING btree ("device_id","status");--> statement-breakpoint
CREATE INDEX "device_credentials_device_idx" ON "device_credentials" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "enrollment_org_idx" ON "device_enrollment_requests" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "heartbeats_device_received_idx" ON "device_heartbeats" USING btree ("device_id","received_at");--> statement-breakpoint
CREATE INDEX "heartbeats_org_received_idx" ON "device_heartbeats" USING btree ("organization_id","received_at");--> statement-breakpoint
CREATE INDEX "devices_org_idx" ON "devices" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "devices_org_last_seen_idx" ON "devices" USING btree ("organization_id","last_seen_at");--> statement-breakpoint
CREATE UNIQUE INDEX "org_members_org_email_idx" ON "organization_members" USING btree ("organization_id","email");--> statement-breakpoint
CREATE INDEX "org_members_user_idx" ON "organization_members" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "audit_org_created_idx" ON "audit_logs" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "email_audit_org_idx" ON "email_domain_audits" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "reports_org_created_idx" ON "report_exports" USING btree ("organization_id","created_at");