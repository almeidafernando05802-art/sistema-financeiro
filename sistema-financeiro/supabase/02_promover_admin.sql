update public.profiles
set role = 'admin', status = 'active'
where email = lower('fernando01889495@gmail.com');

select id, email, role, status from public.profiles where role = 'admin';