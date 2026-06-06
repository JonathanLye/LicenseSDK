-- License SDK — initial schema
-- Run this in Supabase SQL editor or via CLI

create table if not exists products (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  description text,
  created_at  timestamptz default now()
);

create table if not exists licenses (
  id              uuid primary key default gen_random_uuid(),
  product_id      uuid references products(id) on delete restrict,
  license_key     text unique not null,
  type            text not null check (type in ('single', 'volume', 'subscription')),
  max_activations int not null default 1 check (max_activations >= 1),
  expires_at      timestamptz,         -- null = never expires
  status          text not null default 'active' check (status in ('active', 'revoked', 'expired')),
  metadata        jsonb not null default '{}',
  created_at      timestamptz default now()
);

create table if not exists activations (
  id                      uuid primary key default gen_random_uuid(),
  license_id              uuid not null references licenses(id) on delete cascade,
  machine_fingerprint_hash text not null,
  fingerprint_detail      jsonb not null,
  activated_at            timestamptz default now(),
  last_heartbeat          timestamptz,
  status                  text not null default 'active' check (status in ('active', 'deactivated'))
);

create table if not exists audit_logs (
  id                      uuid primary key default gen_random_uuid(),
  license_id              uuid references licenses(id) on delete set null,
  activation_id           uuid references activations(id) on delete set null,
  event_type              text not null,
  machine_fingerprint_hash text,
  ip_address              text,
  success                 boolean not null,
  detail                  jsonb not null default '{}',
  created_at              timestamptz default now()
);

-- Indexes
create index if not exists idx_licenses_license_key       on licenses(license_key);
create index if not exists idx_activations_license_status on activations(license_id, status);
create index if not exists idx_activations_fp_hash        on activations(machine_fingerprint_hash);
create index if not exists idx_audit_logs_license_time    on audit_logs(license_id, created_at desc);
create index if not exists idx_audit_logs_event_type      on audit_logs(event_type, created_at desc);

-- RLS: All tables are locked down; server uses service_role key which bypasses RLS.
-- No direct client access needed.
alter table products       enable row level security;
alter table licenses       enable row level security;
alter table activations    enable row level security;
alter table audit_logs     enable row level security;

-- Deny all by default (service_role bypasses these policies automatically)
create policy "no_public_access_products"    on products    for all using (false);
create policy "no_public_access_licenses"    on licenses    for all using (false);
create policy "no_public_access_activations" on activations for all using (false);
create policy "no_public_access_audit_logs"  on audit_logs  for all using (false);
