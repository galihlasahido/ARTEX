package db

import (
	"database/sql"
	"errors"
	"time"
)

// Task access control: per-task owner (on the tasks row) plus task groups. A
// 'user' role may access a task it owns or that is in a task group it belongs
// to; an 'admin' sees every task. Admins manage groups and their members.

// TaskGroup is a shared space whose members can access the tasks placed in it.
type TaskGroup struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Members   []string  `json:"members,omitempty"`
}

var ErrTaskGroupExists = errors.New("a task group with that name already exists")

// CreateTaskGroup inserts a group; ErrTaskGroupExists on a duplicate name.
func (d *DB) CreateTaskGroup(name string) (*TaskGroup, error) {
	var g TaskGroup
	err := d.QueryRow(`INSERT INTO task_groups(name) VALUES ($1) RETURNING id, name, created_at`, name).
		Scan(&g.ID, &g.Name, &g.CreatedAt)
	if isUniqueViolation(err) {
		return nil, ErrTaskGroupExists
	}
	return &g, err
}

// ListTaskGroups returns all groups with their members.
func (d *DB) ListTaskGroups() ([]TaskGroup, error) {
	rows, err := d.Query(`SELECT id, name, created_at FROM task_groups ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskGroup
	for rows.Next() {
		var g TaskGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		m, err := d.ListTaskGroupMembers(out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Members = m
	}
	return out, nil
}

// DeleteTaskGroup removes a group; its tasks keep running with group_id cleared
// (ON DELETE SET NULL), so they revert to owner-only access.
func (d *DB) DeleteTaskGroup(id int64) error {
	_, err := d.Exec(`DELETE FROM task_groups WHERE id=$1`, id)
	return err
}

// SetTaskGroupMembers replaces a group's member list.
func (d *DB) SetTaskGroupMembers(groupID int64, members []string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`DELETE FROM task_group_members WHERE group_id=$1`, groupID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, u := range members {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		if _, err := tx.Exec(`INSERT INTO task_group_members(group_id, username) VALUES ($1,$2)
			ON CONFLICT DO NOTHING`, groupID, u); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListTaskGroupMembers returns the usernames in a group.
func (d *DB) ListTaskGroupMembers(groupID int64) ([]string, error) {
	rows, err := d.Query(`SELECT username FROM task_group_members WHERE group_id=$1 ORDER BY lower(username)`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// IsTaskGroupMember reports whether username belongs to the group (case-insensitive).
func (d *DB) IsTaskGroupMember(groupID int64, username string) (bool, error) {
	if username == "" {
		return false, nil
	}
	var one int
	err := d.QueryRow(`SELECT 1 FROM task_group_members WHERE group_id=$1 AND lower(username)=lower($2)`,
		groupID, username).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SetTaskGroup assigns (groupID != nil) or clears (nil) a task's group.
func (d *DB) SetTaskGroup(taskID int64, groupID *int64) error {
	_, err := d.Exec(`UPDATE tasks SET group_id=$2, updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, taskID, groupID)
	return err
}
