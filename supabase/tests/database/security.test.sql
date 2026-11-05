begin;

select plan(7);

select is(
  (
    select count(*)::bigint
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public'
      and c.relkind = 'r'
      and c.relrowsecurity
  ),
  32::bigint,
  'RLS is enabled on every NextAura public table'
);

select is(
  (
    select count(*)::bigint
    from information_schema.role_table_grants
    where table_schema = 'public'
      and grantee in ('anon', 'authenticated', 'service_role')
  ),
  0::bigint,
  'Data API roles have no direct public-table privileges'
);

select ok(
  not has_schema_privilege('anon', 'public', 'USAGE')
    and not has_schema_privilege('authenticated', 'public', 'USAGE')
    and not has_schema_privilege('service_role', 'public', 'USAGE'),
  'Data API roles have no public-schema usage'
);

select ok(
  exists (
    select 1
    from pg_index i
    join pg_class idx on idx.oid = i.indexrelid
    join pg_class tbl on tbl.oid = i.indrelid
    join pg_namespace n on n.oid = tbl.relnamespace
    where n.nspname = 'public'
      and tbl.relname = 'scan_file_evidence'
      and idx.relname = 'scan_file_evidence_request_key_idx'
      and i.indisunique
  ),
  'agent file evidence is idempotent per request and evidence key'
);

select ok(
  exists (
    select 1
    from pg_index i
    join pg_class idx on idx.oid = i.indexrelid
    join pg_class tbl on tbl.oid = i.indrelid
    join pg_namespace n on n.oid = tbl.relnamespace
    where n.nspname = 'public'
      and tbl.relname = 'agent_request_replay'
      and idx.relname = 'replay_device_request_idx'
      and i.indisunique
  ),
  'agent replay keys are protected by a unique index'
);

select ok(
  has_table_privilege(current_user, 'public.devices', 'SELECT'),
  'database owner connection retains server-side table access'
);

select is(
  (
    select count(*)::bigint
    from pg_policies
    where schemaname = 'public'
  ),
  0::bigint,
  'no accidental permissive public policies exist'
);

select * from finish();
rollback;
