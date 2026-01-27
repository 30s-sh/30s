create table users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  unkey_key_id text unique,
  created_at timestamptz not null default now(),
  verified_at timestamptz
);

create index idx_users_email ON users(email);
