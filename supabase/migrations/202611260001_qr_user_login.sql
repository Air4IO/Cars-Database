begin;

create table if not exists public.app_user_qr_access (
    user_id uuid primary key references public.app_users(id) on delete cascade,
    token_hash text not null unique,
    created_at timestamptz not null default now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);

alter table public.app_user_qr_access enable row level security;
revoke all on table public.app_user_qr_access from anon, authenticated;
grant select, insert, update, delete on table public.app_user_qr_access to service_role;

commit;

