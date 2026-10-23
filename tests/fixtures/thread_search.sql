-- Synthetic rows for `orchestration.searchThreads` (no real data). Loaded into a gate-shaped
-- fixture DB by the unit tests and into the live engine's DB by `thread_search_shadow_matches_node`.
INSERT INTO projection_projects (project_id, title, workspace_root, scripts_json, created_at, updated_at, deleted_at, auto_pull) VALUES
  ('ts-proj-live', 'Search fixture', '/tmp/ts-live', '[]', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', NULL, 0),
  ('ts-proj-gone', 'Deleted project', '/tmp/ts-gone', '[]', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', 0);

INSERT INTO orchestration_v2_projection_threads (thread_id, project_id, title, default_provider, runtime_mode, interaction_mode, created_at, updated_at, archived_at, deleted_at, payload_json) VALUES
  ('ts-a', 'ts-proj-live', 'Alpha', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-05T00:00:00.000Z', NULL, NULL, '{}'),
  ('ts-c', 'ts-proj-live', 'Gamma', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-06T00:00:00.000Z', NULL, NULL, '{}'),
  ('ts-b', 'ts-proj-live', 'Beta', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-06T00:00:00.000Z', NULL, NULL, '{}'),
  ('ts-arch', 'ts-proj-live', 'Archived', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-07T00:00:00.000Z', '2026-01-07T00:00:00.000Z', NULL, '{}'),
  ('ts-del', 'ts-proj-live', 'Deleted', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-07T00:00:00.000Z', NULL, '2026-01-07T00:00:00.000Z', '{}'),
  ('ts-gone', 'ts-proj-gone', 'Gone', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-07T00:00:00.000Z', NULL, NULL, '{}'),
  (' ts-pad', 'ts-proj-live', 'Padded id', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-03T00:00:00.000Z', NULL, NULL, '{}'),
  ('ts-num', 'ts-proj-live', 'Numeric text', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-03T00:00:00.000Z', NULL, NULL, '{}'),
  ('ts-long', 'ts-proj-live', 'Long texts', 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', '2026-01-04T00:00:00.000Z', NULL, NULL, '{}');

INSERT INTO orchestration_v2_projection_messages (message_id, thread_id, role, streaming, created_at, updated_at, payload_json) VALUES
  ('m-a1', 'ts-a', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'Hello World foo')),
  ('m-a2', 'ts-a', 'user', 0, '2025-12-31T00:00:00.000Z', '2025-12-31T00:00:00.000Z', json_object('text', 'older user hello')),
  ('m-a3', 'ts-a', 'assistant', 0, '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z', json_object('text', 'hello there FOO bar')),
  ('m-a4', 'ts-a', 'assistant', 1, '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z', json_object('text', 'streamingonly')),
  ('m-a5', 'ts-a', 'system', 0, '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z', json_object('text', 'systemonly')),
  ('m-a6', 'ts-a', 'user', 0, '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z', json_object('other', 'hiddenkey')),
  ('m-b1', 'ts-b', 'assistant', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'foo from the assistant only')),
  ('m-b2', 'ts-b', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'Ärger über Öl 🎉')),
  ('m-c1', 'ts-c', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', '100% done_with! it')),
  ('m-c2', 'ts-c', 'user', 0, '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z', json_object('text', '100 percent doneXwith it')),
  ('m-c4', 'ts-c', 'assistant', 0, '2026-01-03T00:00:00.000Z', '2026-01-03T00:00:00.000Z', json_object('text', 'tie break foo second')),
  ('m-c3', 'ts-c', 'assistant', 0, '2026-01-03T00:00:00.000Z', '2026-01-03T00:00:00.000Z', json_object('text', 'tie break foo first')),
  ('m-arch', 'ts-arch', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'foo archivedonly')),
  ('m-del', 'ts-del', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'foo deletedonly')),
  ('m-gone', 'ts-gone', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'foo goneproject')),
  ('m-pad', ' ts-pad', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'paddedid marker')),
  ('m-num', 'ts-num', 'user', 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', '{"text":12345}'),
  ('m-l1', 'ts-long', 'user', 0, '2026-01-01T00:00:01.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('%.*c', 300, 'a') || ' midneedle ' || printf('%.*c', 300, 'b'))),
  ('m-l2', 'ts-long', 'user', 0, '2026-01-01T00:00:02.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'startneedle ' || printf('%.*c', 400, 'c'))),
  ('m-l3', 'ts-long', 'user', 0, '2026-01-01T00:00:03.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('%.*c', 400, 'd') || ' endneedle')),
  ('m-l4', 'ts-long', 'user', 0, '2026-01-01T00:00:04.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'exactfit ' || printf('%.*c', 231, 'e'))),
  ('m-l5', 'ts-long', 'user', 0, '2026-01-01T00:00:05.000Z', '2026-01-01T00:00:00.000Z', json_object('text', 'overfit ' || printf('%.*c', 233, 'f'))),
  ('m-l6', 'ts-long', 'user', 0, '2026-01-01T00:00:06.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('%.*c', 99, 'x') || '🎉' || printf('%.*c', 71, 'y') || 'emojicut' || printf('%.*c', 200, 'z'))),
  ('m-l7', 'ts-long', 'user', 0, '2026-01-01T00:00:07.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('%.*c', 100, 'x') || 'emojiend' || printf('%.*c', 155, 'y') || '🎉' || printf('%.*c', 100, 'z'))),
  ('m-l8', 'ts-long', 'user', 0, '2026-01-01T00:00:08.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('%.*c', 100, 'x') || 'emojiin🎉' || printf('%.*c', 200, 'z'))),
  ('m-l9', 'ts-long', 'user', 0, '2026-01-01T00:00:09.000Z', '2026-01-01T00:00:00.000Z', json_object('text', char(10) || ' wsmark' || char(160, 160) || 'line' || char(8232) || char(9) || 'sep ' || char(65279))),
  ('m-l10', 'ts-long', 'user', 0, '2026-01-01T00:00:10.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('%.*c', 300, 'g') || ' Double  SPACE ' || printf('%.*c', 300, 'h'))),
  ('m-l11', 'ts-long', 'user', 0, '2026-01-01T00:00:11.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('%.*c', 150, 'i') || char(10, 10, 160) || 'spacedcut' || char(8232, 8232) || printf('%.*c', 300, 'j')));

-- 55 threads, more than the default limit of 50; updated_at repeats so thread_id breaks ties.
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 55)
INSERT INTO orchestration_v2_projection_threads (thread_id, project_id, title, default_provider, runtime_mode, interaction_mode, created_at, updated_at, archived_at, deleted_at, payload_json)
SELECT printf('ts-bulk-%02d', i), 'ts-proj-live', printf('Bulk %d', i), 'codex', 'full-access', 'default', '2026-01-01T00:00:00.000Z', printf('2026-02-%02dT00:00:00.000Z', i % 20 + 1), NULL, NULL, '{}' FROM n;

WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 55)
INSERT INTO orchestration_v2_projection_messages (message_id, thread_id, role, streaming, created_at, updated_at, payload_json)
SELECT printf('m-bulk-%02d', i), printf('ts-bulk-%02d', i), CASE i % 3 WHEN 0 THEN 'assistant' ELSE 'user' END, 0, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', json_object('text', printf('bulk item %02d', i)) FROM n;
