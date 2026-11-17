drop policy "Admins fuegen Einzaehler zu wartenden Stuecken hinzu" on public.count_in;
create policy "Admins fuegen Einzaehler zu wartenden Stuecken hinzu" on public.count_in
    for insert to authenticated
    with check (
        (select private.is_admin())
        and private.song_is_pending(song_id)
        and replaces_id is null
        and release_at is null
    );

drop policy "Admins fuegen Playbacks zu wartenden Stuecken hinzu" on public.playback;
create policy "Admins fuegen Playbacks zu wartenden Stuecken hinzu" on public.playback
    for insert to authenticated
    with check (
        (select private.is_admin())
        and private.song_is_pending(song_id)
        and replaces_id is null
        and release_at is null
    );

drop policy "Admins fuegen Noten zu wartenden Stuecken hinzu" on public.sheet_music;
create policy "Admins fuegen Noten zu wartenden Stuecken hinzu" on public.sheet_music
    for insert to authenticated
    with check (
        (select private.is_admin())
        and private.song_is_pending(song_id)
        and replaces_id is null
        and release_at is null
    );

create function private.count_in_matches_playback(target_playback_id bigint, target_count_in_id bigint)
returns boolean
language sql
stable
security definer set search_path = ''
as $$
    select exists (
        select 1 from public.playback
        join public.count_in on count_in.song_id = playback.song_id
        where playback.id = target_playback_id and count_in.id = target_count_in_id
    );
$$;

revoke execute on function private.count_in_matches_playback(bigint, bigint) from public, anon;
grant execute on function private.count_in_matches_playback(bigint, bigint) to authenticated;

drop policy "Admins fuegen Buchstaben zu wartenden Stuecken hinzu" on public.letter;
create policy "Admins fuegen Buchstaben zu wartenden Stuecken hinzu" on public.letter
    for insert to authenticated
    with check (
        (select private.is_admin())
        and private.playback_is_pending(playback_id)
        and private.count_in_matches_playback(playback_id, count_in_id)
    );

create or replace function private.apply_song_changes(target_song_id bigint)
returns void
language plpgsql
security definer set search_path = ''
as $$
declare
    pending_count_in public.count_in;
    pending_playback public.playback;
    pending_sheet public.sheet_music;
begin
    perform 1 from public.song where id = target_song_id for update;

    for pending_count_in in
        select * from public.count_in
        where song_id = target_song_id and release_at <= now()
        order by id
    loop
        if pending_count_in.replaces_id is null then
            update public.count_in set release_at = null where id = pending_count_in.id;
        else
            update public.letter set count_in_id = pending_count_in.replaces_id where count_in_id = pending_count_in.id;
            delete from public.count_in where id = pending_count_in.id;
            update public.count_in
            set name = pending_count_in.name,
                path = pending_count_in.path,
                duration_ms = pending_count_in.duration_ms,
                sha256 = pending_count_in.sha256
            where id = pending_count_in.replaces_id
                and song_id = target_song_id
                and release_at is null;
            if not found then
                raise exception 'replaces_other_song'
                    using detail = format('count_in %s ersetzt keine sichtbare Zeile von Song %s', pending_count_in.id, target_song_id);
            end if;
        end if;
    end loop;

    for pending_playback in
        select * from public.playback
        where song_id = target_song_id and release_at <= now()
        order by id
    loop
        if pending_playback.replaces_id is null then
            update public.playback set release_at = null where id = pending_playback.id;
        else
            perform 1 from public.playback
            where id = pending_playback.replaces_id
                and song_id = target_song_id
                and release_at is null;
            if not found then
                raise exception 'replaces_other_song'
                    using detail = format('playback %s ersetzt keine sichtbare Zeile von Song %s', pending_playback.id, target_song_id);
            end if;
            delete from public.letter where playback_id = pending_playback.replaces_id;
            delete from public.display_playback where playback_id = pending_playback.replaces_id;
            update public.letter set playback_id = pending_playback.replaces_id where playback_id = pending_playback.id;
            update public.display_playback set playback_id = pending_playback.replaces_id where playback_id = pending_playback.id;
            delete from public.playback where id = pending_playback.id;
            update public.playback
            set type = pending_playback.type,
                path = coalesce(pending_playback.path, path),
                duration_ms = pending_playback.duration_ms,
                sha256 = pending_playback.sha256,
                instrument_mode = pending_playback.instrument_mode
            where id = pending_playback.replaces_id;
        end if;
    end loop;

    for pending_sheet in
        select * from public.sheet_music
        where song_id = target_song_id and release_at <= now()
        order by id
    loop
        if pending_sheet.replaces_id is null then
            update public.sheet_music set release_at = null where id = pending_sheet.id;
        else
            delete from public.sheet_music where id = pending_sheet.id;
            update public.sheet_music
            set path = pending_sheet.path,
                sha256 = pending_sheet.sha256
            where id = pending_sheet.replaces_id
                and song_id = target_song_id
                and release_at is null;
            if not found then
                raise exception 'replaces_other_song'
                    using detail = format('sheet_music %s ersetzt keine sichtbare Zeile von Song %s', pending_sheet.id, target_song_id);
            end if;
        end if;
    end loop;

    update public.song set updated_at = now() where id = target_song_id;
end;
$$;

revoke execute on function private.apply_song_changes(bigint) from public, anon, authenticated;
