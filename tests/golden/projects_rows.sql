-- Rows behind tests/golden/projects.json: a VALUES list for projection_projects
-- (project_id, title, workspace_root, default_model_selection_json, default_thread_env_mode,
-- auto_pull, favicon_path, project_icon_json, scripts_json, created_at, updated_at, deleted_at).
('p-b', 'Zürich 🚀 プロジェクト', '/w/b', NULL, NULL, 0, NULL, NULL, '[]',
         '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z', NULL),
        ('p-a', 'Alpha "quoted" \ back', '/w/a',
         '{"model":"gpt-5","instanceId":"codex","options":[{"value":true,"id":"fast"},{"id":"effort","value":"high"}]}',
         'worktree', 1, '/w/a/favicon.svg', '{"color":"orange","name":"video","kind":"lucide"}',
         '[{"runOnWorktreeCreate":false,"icon":"test","command":"npm test","name":"Test","id":"t","autoOpenPreview":true,"previewUrl":"http://localhost:3000","async":false,"runOnSettle":true},{"id":"b","name":"Build","command":"make","icon":"build","runOnWorktreeCreate":true}]',
         '2026-01-02T00:00:00.000Z', '2026-01-03T00:00:00.000Z', NULL),
        ('p-c', 'Emoji', '/w/c', '{"instanceId":"claudeAgent","model":"opus"}', 'local', 0, NULL,
         '{"kind":"emoji","emoji":"🦀"}', '[]', '2026-01-01T00:00:00.000Z', 'not a date', NULL),
        ('p-d', 'Mono', '/w/d', NULL, NULL, 0, NULL, '{"kind":"monogram","text":"VK","color":"blue"}',
         '[]', '2026-01-04T00:00:00.000Z', '2026-01-04T00:00:00.000Z', NULL),
        ('p-gone', 'Deleted', '/w/gone', NULL, NULL, 0, NULL, NULL, '[]',
         '2026-01-01T00:00:00.000Z', '2026-01-05T00:00:00.000Z', '2026-01-05T00:00:00.000Z')
