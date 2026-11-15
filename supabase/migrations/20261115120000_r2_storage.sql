create function public.is_admin()
returns boolean
language sql
stable
security invoker set search_path = ''
as $$
    select private.is_admin();
$$;

revoke execute on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

create function public.unused_files(files jsonb)
returns table (bucket text, name text)
language sql
stable
security definer set search_path = ''
as $$
    select file.bucket, file.name
    from jsonb_to_recordset(files) as file (bucket text, name text, uploaded_at timestamptz)
    where (select private.is_admin())
        and file.bucket in ('sheet_music', 'audio')
        and private.file_is_unused(file.bucket, file.name, file.uploaded_at)
    order by file.bucket, file.name;
$$;

revoke execute on function public.unused_files(jsonb) from public, anon;
grant execute on function public.unused_files(jsonb) to authenticated;
