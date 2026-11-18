-- =========================================================
-- 1. TABELAS
-- =========================================================
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 120),
  email text not null unique,
  role text not null default 'user' check (role in ('user','admin')),
  status text not null default 'active' check (status in ('active','inactive')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  description text not null check (char_length(description) between 1 and 200),
  amount numeric(14,2) not null check (amount > 0),
  type text not null check (type in ('income','expense')),
  category text not null check (char_length(category) between 1 and 60),
  transaction_date date not null,
  payment_method text not null check (payment_method in ('pix','cash','debit','credit','transfer','boleto','other')),
  notes text check (notes is null or char_length(notes) <= 1000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete set null,
  action text not null,
  entity text not null,
  entity_id uuid,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- =========================================================
-- 2. ÍNDICES
-- =========================================================
create index if not exists idx_tx_user_date on public.transactions (user_id, transaction_date desc);
create index if not exists idx_tx_user_type on public.transactions (user_id, type);
create index if not exists idx_tx_user_cat on public.transactions (user_id, category);
create index if not exists idx_profiles_status on public.profiles (status);
create index if not exists idx_audit_created on public.audit_logs (created_at desc);

-- =========================================================
-- 3. TRIGGER updated_at
-- =========================================================
create or replace function public.set_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists trg_profiles_updated on public.profiles;
create trigger trg_profiles_updated before update on public.profiles
  for each row execute function public.set_updated_at();

drop trigger if exists trg_tx_updated on public.transactions;
create trigger trg_tx_updated before update on public.transactions
  for each row execute function public.set_updated_at();

-- =========================================================
-- 4. PERFIL AUTOMÁTICO NO CADASTRO (SEMPRE role = 'user')
-- =========================================================
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, name, email, role, status)
  values (
    new.id,
    left(coalesce(nullif(trim(new.raw_user_meta_data->>'name'), ''), split_part(new.email, '@', 1)), 120),
    lower(new.email),
    'user',
    'active'
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- =========================================================
-- 5. FUNÇÃO AUXILIAR: usuário ativo?
-- =========================================================
create or replace function public.is_active_user()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and status = 'active'
  );
$$;

-- =========================================================
-- 6. PRIVILÉGIOS: usuário comum só altera o próprio NOME
-- =========================================================
revoke insert, update, delete on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (name) on public.profiles to authenticated;

revoke all on public.audit_logs from anon, authenticated;
revoke all on public.transactions from anon;

-- =========================================================
-- 7. ROW LEVEL SECURITY
-- =========================================================
alter table public.profiles enable row level security;
alter table public.transactions enable row level security;
alter table public.audit_logs enable row level security; -- sem políticas = só service role

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
  for select to authenticated using (id = (select auth.uid()));

drop policy if exists "profiles_update_own_name" on public.profiles;
create policy "profiles_update_own_name" on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

drop policy if exists "tx_select_own" on public.transactions;
create policy "tx_select_own" on public.transactions
  for select to authenticated
  using (user_id = (select auth.uid()) and public.is_active_user());

drop policy if exists "tx_insert_own" on public.transactions;
create policy "tx_insert_own" on public.transactions
  for insert to authenticated
  with check (user_id = (select auth.uid()) and public.is_active_user());

drop policy if exists "tx_update_own" on public.transactions;
create policy "tx_update_own" on public.transactions
  for update to authenticated
  using (user_id = (select auth.uid()) and public.is_active_user())
  with check (user_id = (select auth.uid()));

drop policy if exists "tx_delete_own" on public.transactions;
create policy "tx_delete_own" on public.transactions
  for delete to authenticated
  using (user_id = (select auth.uid()) and public.is_active_user());

-- =========================================================
-- 8. RESUMO DA DASHBOARD (soma feita no Postgres, respeita RLS)
-- =========================================================
create or replace function public.dashboard_summary()
returns table (total_income numeric, total_expenses numeric, balance numeric, transaction_count bigint)
language sql stable security invoker set search_path = '' as $$
  select
    coalesce(sum(amount) filter (where type = 'income'), 0),
    coalesce(sum(amount) filter (where type = 'expense'), 0),
    coalesce(sum(case when type = 'income' then amount else -amount end), 0),
    count(*)
  from public.transactions
  where user_id = auth.uid();
$$;

revoke execute on function public.dashboard_summary() from public, anon;
grant execute on function public.dashboard_summary() to authenticated;
