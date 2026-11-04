-- NextAura uses a server-side PostgreSQL connection, not the Supabase Data API.
-- Keep the application tables unreachable through PostgREST even if a future
-- table is added without a policy. The database owner retains normal access.
revoke all on schema public from public, anon, authenticated, service_role;
revoke all privileges on all tables in schema public from public, anon, authenticated, service_role;
revoke all privileges on all sequences in schema public from public, anon, authenticated, service_role;
revoke all privileges on all functions in schema public from public, anon, authenticated, service_role;

alter default privileges for role postgres in schema public
  revoke all privileges on tables from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke all privileges on sequences from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke all privileges on functions from public, anon, authenticated, service_role;

-- RLS is defense in depth. With no policies, Data API roles cannot read or
-- mutate rows even if a grant is accidentally restored later.
alter table public.assessment_checks enable row level security;
alter table public.assessments enable row level security;
alter table public.security_findings enable row level security;
alter table public.software_inventory enable row level security;
alter table public.startup_items enable row level security;
alter table public.threat_detections enable row level security;
alter table public.vulnerability_matches enable row level security;
alter table public.agent_request_replay enable row level security;
alter table public.agent_requests enable row level security;
alter table public.device_credentials enable row level security;
alter table public.device_enrollment_requests enable row level security;
alter table public.device_heartbeats enable row level security;
alter table public.devices enable row level security;
alter table public.organization_members enable row level security;
alter table public.organizations enable row level security;
alter table public.user_profiles enable row level security;
alter table public.audit_logs enable row level security;
alter table public.cve_cache enable row level security;
alter table public.cve_product_queries enable row level security;
alter table public.email_domain_audits enable row level security;
alter table public.intelligence_state enable row level security;
alter table public.kev_catalog enable row level security;
alter table public.report_exports enable row level security;
