DROP TABLE IF EXISTS notes;

DROP INDEX IF EXISTS idx_notes_user_id;

DROP INDEX IF EXISTS idx_notes_created_at;

DROP TABLE IF EXISTS users CASCADE;

DROP INDEX IF EXISTS idx_users_email;

DROP INDEX IF EXISTS idx_users_username;
