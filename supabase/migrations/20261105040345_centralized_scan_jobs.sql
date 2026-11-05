create type public.scan_job_status as enum ('QUEUED', 'WAITING_FOR_AGENT', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'EXPIRED');
create type public.scan_type as enum ('SECURITY_ASSESSMENT', 'APPROVED_SCOPE_FILES');
create type public.agent_operation as enum ('ASSESSMENT', 'FILE_SCOPE_SCAN');

alter table public.agent_requests
  add column operation public.agent_operation not null default 'ASSESSMENT',
  add column scope_id text,
  add column scan_job_id uuid;

create table public.device_scan_scopes (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  scope_id text not null check (scope_id ~ '^scope_[0-9a-f]{32}$'),
  label text not null check (char_length(label) between 1 and 120),
  enabled boolean not null default true,
  last_reported_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (device_id, scope_id)
);

create table public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  scan_type public.scan_type not null,
  status public.scan_job_status not null default 'QUEUED',
  collectors text[] not null default '{}',
  scope_id text,
  requested_by_user_id text not null,
  requested_by_email text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  completed_at timestamptz,
  cancellation_requested_at timestamptz,
  check ((scan_type = 'SECURITY_ASSESSMENT' and cardinality(collectors) > 0)
      or (scan_type = 'APPROVED_SCOPE_FILES' and cardinality(collectors) = 0))
);

create table public.scan_job_devices (
  id uuid primary key default gen_random_uuid(),
  scan_job_id uuid not null references public.scan_jobs(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  agent_request_id uuid references public.agent_requests(id) on delete set null,
  operation public.agent_operation not null,
  scope_id text,
  status public.scan_job_status not null default 'WAITING_FOR_AGENT',
  stage text not null default 'Awaiting agent pickup',
  files_observed integer not null default 0 check (files_observed >= 0),
  evidence_count integer not null default 0 check (evidence_count >= 0),
  collector_failures jsonb not null default '[]',
  delivered_at timestamptz,
  started_at timestamptz,
  completed_at timestamptz,
  error text,
  unique (scan_job_id, device_id)
  ,check ((operation = 'ASSESSMENT' and scope_id is null) or (operation = 'FILE_SCOPE_SCAN' and scope_id is not null))
);

alter table public.agent_requests
  add constraint agent_requests_scan_job_fk foreign key (scan_job_id) references public.scan_jobs(id) on delete cascade,
  add constraint agent_requests_operation_scope_ck check ((operation = 'ASSESSMENT' and scope_id is null) or (operation = 'FILE_SCOPE_SCAN' and scope_id is not null));

create table public.scan_file_evidence (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  scan_job_id uuid not null references public.scan_jobs(id) on delete cascade,
  agent_request_id uuid not null references public.agent_requests(id) on delete cascade,
  evidence_key text not null,
  file_name text not null,
  relative_path_hash text not null check (relative_path_hash ~ '^[0-9a-f]{64}$'),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes bigint not null check (size_bytes >= 0 and size_bytes <= 536870912),
  detected_type text not null,
  classification public.evidence_classification not null,
  severity public.severity not null,
  confidence public.confidence not null,
  detector_id text not null,
  detector_version text not null,
  evidence_source text not null,
  signature_metadata text not null default 'UNKNOWN',
  indicators jsonb not null default '[]',
  archive_summary jsonb,
  pe_metadata jsonb,
  limitations text[] not null default '{}',
  observed_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index device_scan_scopes_org_idx on public.device_scan_scopes (organization_id, device_id);
create index scan_jobs_org_created_idx on public.scan_jobs (organization_id, created_at desc);
create index scan_job_devices_device_status_idx on public.scan_job_devices (device_id, status);
create index scan_file_evidence_job_idx on public.scan_file_evidence (scan_job_id, observed_at desc);
create index scan_file_evidence_device_idx on public.scan_file_evidence (device_id, observed_at desc);
create unique index scan_file_evidence_request_key_idx on public.scan_file_evidence (agent_request_id, evidence_key);

alter table public.device_scan_scopes enable row level security;
alter table public.scan_jobs enable row level security;
alter table public.scan_job_devices enable row level security;
alter table public.scan_file_evidence enable row level security;

revoke all privileges on public.device_scan_scopes, public.scan_jobs, public.scan_job_devices, public.scan_file_evidence from public, anon, authenticated, service_role;
