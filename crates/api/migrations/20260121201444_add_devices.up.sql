create table devices (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    public_key text not null,
    created_at timestamptz not null default now()
);

create index idx_devices_user_id on devices(user_id);
