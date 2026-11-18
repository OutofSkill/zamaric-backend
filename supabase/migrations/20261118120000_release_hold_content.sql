drop policy "Admins fuegen wartende Stuecke hinzu" on public.song;
drop policy "Admins fuegen Einzaehler zu wartenden Stuecken hinzu" on public.count_in;
drop policy "Admins fuegen Playbacks zu wartenden Stuecken hinzu" on public.playback;
drop policy "Admins fuegen Buchstaben zu wartenden Stuecken hinzu" on public.letter;
drop policy "Admins fuegen Noten zu wartenden Stuecken hinzu" on public.sheet_music;
drop policy "Admins fuegen Playback-Instrumente zu wartenden Stuecken hinzu" on public.display_playback;

drop function private.count_in_matches_playback(bigint, bigint);

create function public.file_is_referenced(bucket_name text, file_name text)
returns boolean
language plpgsql
stable
security definer set search_path = ''
as $$
begin
    if not private.is_admin() then
        raise exception 'forbidden';
    end if;
    return case bucket_name
        when 'audio' then
            exists (select 1 from public.playback where path = file_name)
            or exists (select 1 from public.count_in where path = file_name)
        when 'sheet_music' then
            exists (select 1 from public.sheet_music where path = file_name)
        else false
    end;
end;
$$;

revoke execute on function public.file_is_referenced(text, text) from public, anon;
grant execute on function public.file_is_referenced(text, text) to authenticated;

create or replace function public.import_song(payload jsonb)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
    new_song_id bigint;
    count_in_entry jsonb;
    playback_entry jsonb;
    letter_entry jsonb;
    sheet_entry jsonb;
    new_playback_id bigint;
    playback_duration integer;
    playback_mode text;
    playback_instrument_ids bigint[];
    letter_position integer;
    previous_position integer;
    letter_count_in_id bigint;
    violated_constraint text;
    error_text text;
begin
    if not private.is_admin() then
        raise exception 'forbidden';
    end if;
    if jsonb_typeof(payload) is distinct from 'object'
        or jsonb_typeof(payload -> 'count_ins') is distinct from 'array'
        or jsonb_typeof(payload -> 'playbacks') is distinct from 'array'
        or jsonb_typeof(payload -> 'sheet_music') is distinct from 'array' then
        raise exception 'invalid_manifest' using detail = 'payload hat nicht die erwartete Form';
    end if;
    if jsonb_array_length(payload -> 'playbacks') = 0 and jsonb_array_length(payload -> 'sheet_music') = 0 then
        raise exception 'invalid_manifest' using detail = 'keine Playbacks und keine Noten';
    end if;

    insert into public.song (name, category_id, release_at, publisher_name, publisher_url)
    values (
        payload ->> 'song_name',
        (payload ->> 'category_id')::bigint,
        (payload ->> 'release_at')::timestamptz,
        payload ->> 'publisher_name',
        payload ->> 'publisher_url'
    )
    returning id into new_song_id;

    for count_in_entry in select value from jsonb_array_elements(payload -> 'count_ins') loop
        insert into public.count_in (song_id, name, path, duration_ms, sha256)
        values (
            new_song_id,
            count_in_entry ->> 'name',
            count_in_entry ->> 'path',
            (count_in_entry ->> 'duration_ms')::integer,
            count_in_entry ->> 'sha256'
        );
    end loop;

    for playback_entry in select value from jsonb_array_elements(payload -> 'playbacks') loop
        playback_mode := playback_entry ->> 'instrument_mode';
        select coalesce(array_agg(value::bigint), '{}')
        into playback_instrument_ids
        from jsonb_array_elements_text(coalesce(playback_entry -> 'instrument_ids', '[]'));

        if (playback_mode = 'all') <> (cardinality(playback_instrument_ids) = 0)
            or cardinality(playback_instrument_ids) <> (select count(distinct id) from unnest(playback_instrument_ids) as id) then
            raise exception 'invalid_manifest'
                using detail = format('instrument_ids passen nicht zu instrument_mode bei „%s“', playback_entry ->> 'type');
        end if;

        insert into public.playback (song_id, duration_ms, path, type, instrument_mode, sha256)
        values (
            new_song_id,
            (playback_entry ->> 'duration_ms')::integer,
            playback_entry ->> 'path',
            playback_entry ->> 'type',
            playback_mode,
            playback_entry ->> 'sha256'
        )
        returning id, duration_ms into new_playback_id, playback_duration;

        insert into public.display_playback (instrument_id, playback_id)
        select instrument_id, new_playback_id from unnest(playback_instrument_ids) as instrument_id;

        previous_position := null;
        for letter_entry in select value from jsonb_array_elements(coalesce(playback_entry -> 'letters', '[]')) loop
            letter_position := (letter_entry ->> 'position_ms')::integer;
            if letter_position <= previous_position or letter_position > playback_duration then
                raise exception 'invalid_manifest'
                    using detail = format('Buchstabe „%s“ bei „%s“ nicht aufsteigend oder hinter dem Ende', letter_entry ->> 'name', playback_entry ->> 'type');
            end if;

            letter_count_in_id := null;
            select id into letter_count_in_id
            from public.count_in
            where song_id = new_song_id and lower(name) = lower(letter_entry ->> 'count_in');
            if letter_count_in_id is null then
                raise exception 'invalid_manifest'
                    using detail = format('Einzähler „%s“ fehlt bei „%s“', letter_entry ->> 'count_in', playback_entry ->> 'type');
            end if;

            insert into public.letter (playback_id, name, position_ms, count_in_id)
            values (new_playback_id, letter_entry ->> 'name', letter_position, letter_count_in_id);
            previous_position := letter_position;
        end loop;
    end loop;

    for sheet_entry in select value from jsonb_array_elements(payload -> 'sheet_music') loop
        insert into public.sheet_music (song_id, part_id, level_id, path, sha256)
        values (
            new_song_id,
            (sheet_entry ->> 'part_id')::bigint,
            (sheet_entry ->> 'level_id')::bigint,
            sheet_entry ->> 'path',
            sheet_entry ->> 'sha256'
        );
    end loop;

    return new_song_id;
exception
    when unique_violation then
        get stacked diagnostics violated_constraint = constraint_name, error_text = message_text;
        if violated_constraint = 'song_category_id_lower_name_key' then
            raise exception 'song_exists';
        end if;
        raise exception 'invalid_manifest' using detail = error_text;
    when integrity_constraint_violation or data_exception then
        get stacked diagnostics error_text = message_text;
        raise exception 'invalid_manifest' using detail = error_text;
    when insufficient_privilege then
        raise exception 'forbidden';
end;
$$;

revoke execute on function public.import_song(jsonb) from public, anon;
grant execute on function public.import_song(jsonb) to authenticated;

create or replace function public.update_song(payload jsonb)
returns timestamptz
language plpgsql
security definer set search_path = ''
as $$
declare
    target_song public.song;
    category_name text;
    song_waiting boolean;
    change_release timestamptz;
    count_in_entry jsonb;
    playback_entry jsonb;
    letter_entry jsonb;
    sheet_entry jsonb;
    live_id bigint;
    live_playback public.playback;
    new_playback_id bigint;
    playback_duration integer;
    playback_mode text;
    playback_instrument_ids bigint[];
    letter_position integer;
    previous_position integer;
    letter_count_in_id bigint;
    change_count integer;
    error_text text;
begin
    if not private.is_admin() then
        raise exception 'forbidden';
    end if;
    if jsonb_typeof(payload) is distinct from 'object'
        or jsonb_typeof(payload -> 'count_ins') is distinct from 'array'
        or jsonb_typeof(payload -> 'playbacks') is distinct from 'array'
        or jsonb_typeof(payload -> 'sheet_music') is distinct from 'array' then
        raise exception 'invalid_manifest' using detail = 'payload hat nicht die erwartete Form';
    end if;

    select * into target_song from public.song where id = (payload ->> 'song_id')::bigint for update;
    if not found then
        raise exception 'invalid_manifest' using detail = 'Song gibt es nicht';
    end if;
    song_waiting := target_song.release_at > now();
    change_release := case
        when song_waiting then now()
        else private.release_time(now(), (payload ->> 'release_at')::timestamptz)
    end;

    -- Verlag und Link gelten sofort
    update public.song
    set publisher_name = payload ->> 'publisher_name',
        publisher_url = payload ->> 'publisher_url'
    where id = target_song.id;

    -- Eine schon wartende Änderung wird durch diese ersetzt
    delete from public.playback where song_id = target_song.id and release_at is not null;
    delete from public.sheet_music where song_id = target_song.id and release_at is not null;
    delete from public.count_in where song_id = target_song.id and release_at is not null;

    for count_in_entry in select value from jsonb_array_elements(payload -> 'count_ins') loop
        select id into live_id
        from public.count_in
        where song_id = target_song.id and release_at is null and lower(name) = lower(count_in_entry ->> 'name');
        insert into public.count_in (song_id, name, path, duration_ms, sha256, replaces_id, release_at)
        values (
            target_song.id,
            count_in_entry ->> 'name',
            count_in_entry ->> 'path',
            (count_in_entry ->> 'duration_ms')::integer,
            count_in_entry ->> 'sha256',
            live_id,
            change_release
        );
        live_id := null;
    end loop;

    for playback_entry in select value from jsonb_array_elements(payload -> 'playbacks') loop
        playback_mode := playback_entry ->> 'instrument_mode';
        select coalesce(array_agg(value::bigint), '{}')
        into playback_instrument_ids
        from jsonb_array_elements_text(coalesce(playback_entry -> 'instrument_ids', '[]'));
        if (playback_mode = 'all') <> (cardinality(playback_instrument_ids) = 0)
            or cardinality(playback_instrument_ids) <> (select count(distinct id) from unnest(playback_instrument_ids) as id) then
            raise exception 'invalid_manifest'
                using detail = format('instrument_ids passen nicht zu instrument_mode bei „%s“', playback_entry ->> 'type');
        end if;

        live_playback := null;
        select * into live_playback
        from public.playback
        where song_id = target_song.id and release_at is null and lower(type) = lower(playback_entry ->> 'type');
        if playback_entry ->> 'path' is null and live_playback.id is null then
            raise exception 'invalid_manifest'
                using detail = format('Playback „%s“ ohne MP3, aber es gibt keins zum Ersetzen', playback_entry ->> 'type');
        end if;

        insert into public.playback (song_id, duration_ms, path, type, instrument_mode, sha256, replaces_id, release_at)
        values (
            target_song.id,
            case when playback_entry ->> 'path' is null then live_playback.duration_ms else (playback_entry ->> 'duration_ms')::integer end,
            playback_entry ->> 'path',
            playback_entry ->> 'type',
            playback_mode,
            case when playback_entry ->> 'path' is null then live_playback.sha256 else playback_entry ->> 'sha256' end,
            live_playback.id,
            change_release
        )
        returning id, duration_ms into new_playback_id, playback_duration;

        insert into public.display_playback (instrument_id, playback_id)
        select instrument_id, new_playback_id from unnest(playback_instrument_ids) as instrument_id;

        previous_position := null;
        for letter_entry in select value from jsonb_array_elements(coalesce(playback_entry -> 'letters', '[]')) loop
            letter_position := (letter_entry ->> 'position_ms')::integer;
            if letter_position <= previous_position or letter_position > playback_duration then
                raise exception 'invalid_manifest'
                    using detail = format('Buchstabe „%s“ bei „%s“ nicht aufsteigend oder hinter dem Ende', letter_entry ->> 'name', playback_entry ->> 'type');
            end if;

            -- Erst ein Einzähler aus dieser Änderung, sonst ein sichtbarer
            letter_count_in_id := null;
            select id into letter_count_in_id
            from public.count_in
            where song_id = target_song.id and lower(name) = lower(letter_entry ->> 'count_in')
            order by release_at is null
            limit 1;
            if letter_count_in_id is null then
                raise exception 'invalid_manifest'
                    using detail = format('Einzähler „%s“ fehlt bei „%s“', letter_entry ->> 'count_in', playback_entry ->> 'type');
            end if;

            insert into public.letter (playback_id, name, position_ms, count_in_id)
            values (new_playback_id, letter_entry ->> 'name', letter_position, letter_count_in_id);
            previous_position := letter_position;
        end loop;
    end loop;

    for sheet_entry in select value from jsonb_array_elements(payload -> 'sheet_music') loop
        select id into live_id
        from public.sheet_music
        where song_id = target_song.id
            and release_at is null
            and part_id = (sheet_entry ->> 'part_id')::bigint
            and level_id = (sheet_entry ->> 'level_id')::bigint;
        insert into public.sheet_music (song_id, part_id, level_id, path, sha256, replaces_id, release_at)
        values (
            target_song.id,
            (sheet_entry ->> 'part_id')::bigint,
            (sheet_entry ->> 'level_id')::bigint,
            sheet_entry ->> 'path',
            sheet_entry ->> 'sha256',
            live_id,
            change_release
        );
        live_id := null;
    end loop;

    change_count := jsonb_array_length(payload -> 'count_ins')
        + jsonb_array_length(payload -> 'playbacks')
        + jsonb_array_length(payload -> 'sheet_music');
    if change_count = 0 then
        return now();
    end if;

    -- Wartet der Song noch auf seine erste Freigabe, gilt die Änderung sofort,
    -- die Freigabe rückt aber auf frühestens 24 Stunden nach dieser Änderung
    if song_waiting then
        perform private.apply_song_changes(target_song.id);
        update public.song
        set release_at = greatest(target_song.release_at, private.release_time(now(), null))
        where id = target_song.id
        returning release_at into target_song.release_at;
    end if;

    select name into category_name from public.category where id = target_song.category_id;
    perform private.send_ntfy(
        case when song_waiting then 'Wartender Song geändert' else 'Song geändert, wartet auf Freigabe' end,
        format(
            E'%s (%s)\n%s Noten, %s Playbacks, %s Einzähler neu oder geändert\nFreigabe: %s',
            target_song.name,
            category_name,
            jsonb_array_length(payload -> 'sheet_music'),
            jsonb_array_length(payload -> 'playbacks'),
            jsonb_array_length(payload -> 'count_ins'),
            to_char(
                (case when song_waiting then target_song.release_at else change_release end) at time zone 'Europe/Berlin',
                'DD.MM.YYYY HH24:MI'
            )
        )
    );
    return case when song_waiting then target_song.release_at else change_release end;
exception
    when unique_violation or integrity_constraint_violation or data_exception then
        get stacked diagnostics error_text = message_text;
        raise exception 'invalid_manifest' using detail = error_text;
end;
$$;

revoke execute on function public.update_song(jsonb) from public, anon;
grant execute on function public.update_song(jsonb) to authenticated;
