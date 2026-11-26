package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Users store contract: case-insensitive uniqueness, and the pwd_version bump on
// every password/role/active change that the server relies on to end sessions.
func TestUserStore(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	us := d.Users()
	name := fmt.Sprintf("store%d", time.Now().UnixNano())

	u, err := us.Create(name, "hash1", "user")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = us.Delete(u.ID) })
	if u.Role != "user" || !u.Active || u.PwdVersion != 1 {
		t.Fatalf("new user = %+v, want role user / active / version 1", u)
	}

	// Case-insensitive duplicate is rejected (upper-cased spelling collides).
	if _, err := us.Create(strings.ToUpper(name), "h2", "admin"); err != ErrUserExists {
		t.Fatalf("duplicate create err = %v, want ErrUserExists", err)
	}

	// Lookups are case-insensitive.
	got, err := us.GetByName(name)
	if err != nil || got.ID != u.ID {
		t.Fatalf("GetByName = %+v, %v", got, err)
	}

	// Each mutation bumps the version.
	v, err := us.SetPassword(u.ID, "hash2")
	if err != nil || v != 2 {
		t.Fatalf("SetPassword version = %d, %v, want 2", v, err)
	}
	if err := us.SetRole(u.ID, "admin"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if err := us.SetActive(u.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	after, err := us.GetByID(u.ID)
	if err != nil || after.Role != "admin" || after.Active || after.PwdVersion != 4 {
		t.Fatalf("after mutations = %+v, %v; want admin/inactive/version 4", after, err)
	}

	if err := us.Delete(u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := us.GetByID(u.ID); err != ErrUserNotFound {
		t.Fatalf("GetByID after delete = %v, want ErrUserNotFound", err)
	}
	if err := us.SetRole(u.ID, "user"); err != ErrUserNotFound {
		t.Fatalf("SetRole on deleted = %v, want ErrUserNotFound", err)
	}
}
