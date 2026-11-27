-- =====================================================================
-- BookHub migration: Bug #2 (one account = buyer + seller)
--                    Bug #3 (no duplicate names)
-- Run once on Neon (SQL Editor) BEFORE deploying the new run.py.
-- Safe to run more than once.
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------------
-- Bug #2: role table
-- One row per (user, role). A user who is both buyer and seller has
-- two rows. This replaces the single users.role column.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       VARCHAR(10) NOT NULL CHECK (role IN ('BUYER', 'SELLER')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role)
);

-- Copy every existing user's current role into the new table.
INSERT INTO user_roles (user_id, role)
SELECT id, role
FROM users
WHERE role IN ('BUYER', 'SELLER')
ON CONFLICT (user_id, role) DO NOTHING;

-- users.role is kept only for backward compatibility. The app no longer
-- reads it, so stop requiring it.
ALTER TABLE users ALTER COLUMN role DROP NOT NULL;

-- ---------------------------------------------------------------------
-- Bug #3: unique names (case-insensitive: "Amy" and "amy" count as the same)
-- ---------------------------------------------------------------------

-- Existing duplicates would block the UNIQUE index. Keep the oldest account's
-- name as is and add the user id to the others, e.g. "Amy" -> "Amy_12".
-- To see the duplicates first, run:
--   SELECT LOWER(name), COUNT(*) FROM users GROUP BY LOWER(name) HAVING COUNT(*) > 1;
UPDATE users u
SET name = u.name || '_' || u.id
WHERE EXISTS (
    SELECT 1 FROM users older
    WHERE LOWER(older.name) = LOWER(u.name)
      AND older.id < u.id
);

CREATE UNIQUE INDEX IF NOT EXISTS users_name_unique_idx
    ON users (LOWER(name));

COMMIT;
