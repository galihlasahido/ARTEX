-- Task access control: a per-task owner and task groups.
--
-- owner is the username that created the task. A 'user' role may access only
-- the tasks it owns or that belong to a task group it is a member of; an
-- 'admin' (and the ARTEX bootstrap admin) sees every task. Existing tasks are
-- given to ARTEX so they stay admin-visible; an empty owner is treated as
-- admin-only by the access check.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';
UPDATE tasks SET owner = 'ARTEX' WHERE owner = '';

-- A task group is a shared space: admins assign users to it, and every member
-- can access the tasks placed in the group, regardless of who created them.
CREATE TABLE IF NOT EXISTS task_groups (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS task_groups_name_key ON task_groups (lower(name));

CREATE TABLE IF NOT EXISTS task_group_members (
    group_id BIGINT NOT NULL REFERENCES task_groups(id) ON DELETE CASCADE,
    username TEXT   NOT NULL,
    PRIMARY KEY (group_id, username)
);

ALTER TABLE tasks ADD COLUMN IF NOT EXISTS group_id BIGINT REFERENCES task_groups(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS tasks_owner_idx ON tasks (owner);
CREATE INDEX IF NOT EXISTS tasks_group_idx ON tasks (group_id);
