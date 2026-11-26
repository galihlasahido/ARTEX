package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Users are the additional login accounts layered on top of the bootstrap
// "ARTEX" admin (which stays in settings, see server/auth.go). Each row carries
// a role ('admin' or 'user'), an active flag, and a pwd_version counter. The
// server validates a session token's pwd claim against pwd_version, so bumping
// it — on a password change, an admin reset, a role change or a deactivation —
// invalidates every live session for that user. The password itself is a bcrypt
// hash computed by the server; this layer only stores the string.

// ErrUserExists is returned by CreateUser when the username is already taken
// (case-insensitive). ErrUserNotFound is returned when an id/username has no row.
var (
	ErrUserExists   = errors.New("username already exists")
	ErrUserNotFound = errors.New("user not found")
)

// User is one login account in the users table. Hash is never serialized to
// clients (no JSON tag that would expose it; handlers build their own DTO).
type User struct {
	ID         int64
	Username   string
	Hash       string
	Role       string
	Active     bool
	PwdVersion int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UserStore groups the user-account queries. Obtain it with d.Users().
type UserStore struct{ db *DB }

// Users returns the user-account store.
func (d *DB) Users() *UserStore { return &UserStore{db: d} }

const userCols = `id, username, password_hash, role, active, pwd_version, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Hash, &u.Role, &u.Active, &u.PwdVersion, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// List returns every user ordered by username (case-insensitive).
func (s *UserStore) List() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY lower(username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetByName returns the user whose username matches name case-insensitively, or
// ErrUserNotFound when there is none.
func (s *UserStore) GetByName(name string) (User, error) {
	row := s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, name)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	}
	return u, err
}

// GetByID returns the user with that id, or ErrUserNotFound.
func (s *UserStore) GetByID(id int64) (User, error) {
	row := s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=$1`, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	}
	return u, err
}

// Create inserts a new account. role must be 'admin' or 'user'; hash is a bcrypt
// hash. A duplicate username (case-insensitive) returns ErrUserExists.
func (s *UserStore) Create(username, hash, role string) (User, error) {
	row := s.db.QueryRow(`
INSERT INTO users(username, password_hash, role, active, pwd_version)
VALUES ($1, $2, $3, true, 1)
RETURNING `+userCols, strings.TrimSpace(username), hash, role)
	u, err := scanUser(row)
	if err != nil && isUniqueViolation(err) {
		return User{}, ErrUserExists
	}
	return u, err
}

// SetPassword replaces the hash and bumps pwd_version, killing live sessions.
// It returns the new version. ErrUserNotFound when the id is unknown.
func (s *UserStore) SetPassword(id int64, hash string) (int64, error) {
	var v int64
	err := s.db.QueryRow(`
UPDATE users SET password_hash=$2, pwd_version=pwd_version+1, updated_at=now()
WHERE id=$1 RETURNING pwd_version`, id, hash).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, ErrUserNotFound
	}
	return v, err
}

// SetRole changes the role and bumps pwd_version so an open session re-derives
// its privileges on the next login. ErrUserNotFound when the id is unknown.
func (s *UserStore) SetRole(id int64, role string) error {
	res, err := s.db.Exec(`
UPDATE users SET role=$2, pwd_version=pwd_version+1, updated_at=now() WHERE id=$1`, id, role)
	return affected(res, err)
}

// SetActive toggles the active flag and bumps pwd_version, so deactivating a
// user ends their live sessions at once. ErrUserNotFound when the id is unknown.
func (s *UserStore) SetActive(id int64, active bool) error {
	res, err := s.db.Exec(`
UPDATE users SET active=$2, pwd_version=pwd_version+1, updated_at=now() WHERE id=$1`, id, active)
	return affected(res, err)
}

// Delete removes the account. ErrUserNotFound when the id is unknown.
func (s *UserStore) Delete(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id=$1`, id)
	return affected(res, err)
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint error.
// The driver wraps a SQLSTATE 23505; matching on the message keeps this free of
// a direct pgx dependency here.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") ||
		strings.Contains(msg, "duplicate key value") ||
		strings.Contains(msg, "unique constraint")
}
