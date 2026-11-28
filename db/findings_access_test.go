package db

import (
	"strings"
	"testing"
)

// The per-user restriction turns into an owner (and optional group) condition in
// the findings WHERE clause, so every findings query is narrowed the same way.
func TestFindingFilterRestrictOwner(t *testing.T) {
	// Owner only: no groups.
	where, args := FindingFilter{RestrictOwner: "alice"}.where()
	if !strings.Contains(where, "lower(t.owner) = lower($1)") {
		t.Fatalf("owner-only where = %q", where)
	}
	if len(args) != 1 || args[0] != "alice" {
		t.Fatalf("owner-only args = %v", args)
	}

	// Owner or one of the groups (group ids inlined, owner parameterized).
	where, args = FindingFilter{RestrictOwner: "bob", RestrictGroupIDs: []int64{3, 5}}.where()
	if !strings.Contains(where, "(lower(t.owner) = lower($1) OR t.group_id IN (3,5))") {
		t.Fatalf("owner+group where = %q", where)
	}
	if len(args) != 1 || args[0] != "bob" {
		t.Fatalf("owner+group args = %v", args)
	}

	// No restriction for an admin (empty owner): no owner condition.
	where, _ = FindingFilter{}.where()
	if strings.Contains(where, "t.owner") {
		t.Fatalf("unrestricted where should not mention owner: %q", where)
	}
}
