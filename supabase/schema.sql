-- =====================================================================
-- momo 모모 · "고객이 들려주는 이야기" 게시판 DB 설정
-- Supabase 대시보드 > SQL Editor 에 전체를 붙여넣고 Run 하세요.
-- 여러 번 실행해도 안전합니다.
--
-- 보안 구조
--  - 홈페이지(방문자)는 stories 테이블에 직접 접근할 수 없습니다.
--  - 아래 4개 함수(list/create/update/delete)로만 읽고 쓸 수 있습니다.
--  - 비밀번호는 bcrypt 로 암호화되어 저장되며, 화면에 절대 내려가지 않습니다.
--  - 비밀번호 5회 틀리면 해당 글은 15분간 수정·삭제가 잠깁니다.
--  - 1분에 10건 넘게 등록되면 잠시 등록을 막습니다(도배 방지).
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.stories (
  id              bigint generated always as identity primary key,
  nickname        text        not null check (char_length(nickname) between 2 and 12),
  title           text        not null check (char_length(title)    between 2 and 40),
  content         text        not null check (char_length(content)  between 10 and 1000),
  password_hash   text        not null,
  is_hidden       boolean     not null default false,   -- 관리자가 true 로 바꾸면 화면에서 숨김
  failed_attempts int         not null default 0,
  locked_until    timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz
);

create index if not exists stories_created_at_idx on public.stories (created_at desc);

-- 방문자(anon)는 테이블에 직접 접근 불가
alter table public.stories enable row level security;
revoke all on table public.stories from anon, authenticated;

-- ---------------------------------------------------------------------
-- 목록 조회 (숨김 글 제외, 비밀번호 제외)
-- ---------------------------------------------------------------------
create or replace function public.list_stories(p_limit int default 6, p_offset int default 0)
returns table (
  id bigint, nickname text, title text, content text,
  created_at timestamptz, updated_at timestamptz, total bigint
)
language sql
security definer
set search_path = public
as $$
  select s.id, s.nickname, s.title, s.content, s.created_at, s.updated_at,
         count(*) over () as total
  from public.stories s
  where not s.is_hidden
  order by s.created_at desc
  limit least(greatest(p_limit, 1), 30)
  offset greatest(p_offset, 0);
$$;

-- ---------------------------------------------------------------------
-- 등록
-- ---------------------------------------------------------------------
create or replace function public.create_story(
  p_nickname text, p_title text, p_content text, p_password text
)
returns bigint
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  new_id bigint;
begin
  if char_length(coalesce(p_password, '')) not between 4 and 20 then
    raise exception 'invalid_password';
  end if;

  if (select count(*) from public.stories where created_at > now() - interval '1 minute') >= 10 then
    raise exception 'too_many_requests';
  end if;

  insert into public.stories (nickname, title, content, password_hash)
  values (trim(p_nickname), trim(p_title), trim(p_content), crypt(p_password, gen_salt('bf')))
  returning id into new_id;

  return new_id;
end;
$$;

-- ---------------------------------------------------------------------
-- 비밀번호 확인 공통 처리 (내부용)
--  반환: 'ok' | 'wrong_password' | 'locked' | 'not_found'
-- ---------------------------------------------------------------------
create or replace function public._check_story_password(p_id bigint, p_password text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  s public.stories%rowtype;
begin
  select * into s from public.stories where id = p_id and not is_hidden for update;
  if not found then
    return 'not_found';
  end if;

  if s.locked_until is not null then
    if s.locked_until > now() then
      return 'locked';
    end if;
    update public.stories set failed_attempts = 0, locked_until = null where id = p_id;
    s.failed_attempts := 0;
  end if;

  if s.password_hash <> crypt(coalesce(p_password, ''), s.password_hash) then
    update public.stories
       set failed_attempts = s.failed_attempts + 1,
           locked_until = case when s.failed_attempts + 1 >= 5
                               then now() + interval '15 minutes' end
     where id = p_id;
    return 'wrong_password';
  end if;

  return 'ok';
end;
$$;

-- ---------------------------------------------------------------------
-- 수정 (제목·내용)
-- ---------------------------------------------------------------------
create or replace function public.update_story(
  p_id bigint, p_password text, p_title text, p_content text
)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  result text;
begin
  result := public._check_story_password(p_id, p_password);
  if result <> 'ok' then
    return result;
  end if;

  update public.stories
     set title = trim(p_title),
         content = trim(p_content),
         updated_at = now(),
         failed_attempts = 0,
         locked_until = null
   where id = p_id;

  return 'ok';
end;
$$;

-- ---------------------------------------------------------------------
-- 삭제
-- ---------------------------------------------------------------------
create or replace function public.delete_story(p_id bigint, p_password text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  result text;
begin
  result := public._check_story_password(p_id, p_password);
  if result <> 'ok' then
    return result;
  end if;

  delete from public.stories where id = p_id;
  return 'ok';
end;
$$;

-- ---------------------------------------------------------------------
-- 권한: 방문자는 아래 4개 함수만 실행 가능
-- ---------------------------------------------------------------------
revoke all on function public._check_story_password(bigint, text) from public, anon, authenticated;
revoke all on function public.list_stories(int, int)                 from public;
revoke all on function public.create_story(text, text, text, text)   from public;
revoke all on function public.update_story(bigint, text, text, text) from public;
revoke all on function public.delete_story(bigint, text)             from public;

grant execute on function public.list_stories(int, int)                 to anon, authenticated;
grant execute on function public.create_story(text, text, text, text)   to anon, authenticated;
grant execute on function public.update_story(bigint, text, text, text) to anon, authenticated;
grant execute on function public.delete_story(bigint, text)             to anon, authenticated;
