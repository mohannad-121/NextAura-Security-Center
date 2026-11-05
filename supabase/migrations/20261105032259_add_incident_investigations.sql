create type public.incident_status as enum ('OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED');
create type public.evidence_classification as enum ('CONFIRMED_DETECTION', 'SUSPICIOUS_INDICATOR', 'INCONCLUSIVE', 'NO_FINDINGS_OBSERVED', 'UNSUPPORTED');
create table public.incidents (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  title text not null,
  severity public.severity not null,
  status public.incident_status not null default 'OPEN',
  summary text not null default '',
  confidence public.confidence not null default 'MEDIUM',
  evidence_limitations text[] not null default '{}',
  recommended_actions text[] not null default '{}',
  created_by_user_id text not null,
  created_by_email text not null,
  assigned_to_email text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz
);

create table public.incident_devices (
  incident_id uuid not null references public.incidents(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  primary key (incident_id, device_id)
);

create table public.incident_findings (
  incident_id uuid not null references public.incidents(id) on delete cascade,
  finding_id uuid not null references public.security_findings(id) on delete cascade,
  primary key (incident_id, finding_id)
);

create table public.incident_file_evidence (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  file_name text not null,
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes bigint not null check (size_bytes >= 0),
  detected_type text not null,
  classification public.evidence_classification not null,
  signature_metadata text not null default 'UNKNOWN',
  reputation jsonb not null default '{}',
  indicators jsonb not null default '[]',
  archive_summary jsonb,
  limitations text[] not null default '{}',
  source text not null,
  observed_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table public.incident_timeline (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  occurred_at timestamptz not null,
  event_type text not null,
  title text not null,
  evidence text not null,
  source text not null,
  created_at timestamptz not null default now()
);

create index incidents_org_updated_idx on public.incidents (organization_id, updated_at desc);
create index incident_devices_device_idx on public.incident_devices (device_id);
create index incident_findings_finding_idx on public.incident_findings (finding_id);
create index incident_files_incident_idx on public.incident_file_evidence (incident_id, observed_at desc);
create index incident_timeline_incident_idx on public.incident_timeline (incident_id, occurred_at);

alter table public.incidents enable row level security;
alter table public.incident_devices enable row level security;
alter table public.incident_findings enable row level security;
alter table public.incident_file_evidence enable row level security;
alter table public.incident_timeline enable row level security;

revoke all privileges on public.incidents, public.incident_devices, public.incident_findings, public.incident_file_evidence, public.incident_timeline from public, anon, authenticated, service_role;
