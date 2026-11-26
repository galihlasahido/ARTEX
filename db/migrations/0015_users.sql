-- Additional login accounts with roles (admin/user). The bootstrap "ARTEX"
-- admin stays in settings (auth.password_hash) and is NOT moved here, so a
-- deleted row can never resurrect it. The idempotent schema supplies the same
-- DDL; this migration records the feature version for existing installs.
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    active        BOOLEAN NOT NULL DEFAULT true,
    pwd_version   BIGINT NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_role_check CHECK (role IN ('admin','user'))
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_key ON users (lower(username));
