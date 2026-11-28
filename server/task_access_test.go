package server

import (
	"fmt"
	"testing"
)

func TestTaskIDFromPath(t *testing.T) {
	cases := map[string]string{
		"/api/tasks/8":                "8",
		"/api/tasks/8/control":        "8",
		"/api/tasks/123/findings":     "123",
		"/api/tasks":                  "",
		"/api/tasks/":                 "",
		"/api/tasks/control/batch":    "",
		"/api/tasks/category/batch":   "",
		"/api/tasks/archive/batch":    "",
		"/api/settings":               "",
		"/api/tasks/8x/control":       "", // non-numeric segment is not an id
		"/api/intercept/task/scope-1": "",
	}
	for path, want := range cases {
		if got := taskIDFromPath(path); got != want {
			t.Errorf("taskIDFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestFindingIDFromPath(t *testing.T) {
	cases := map[string]int64{
		"/api/exploration/findings/42":             42,
		"/api/exploration/findings/42/lineage":     42,
		"/api/exploration/findings":                0,
		"/api/exploration/findings/groups":         0,
		"/api/exploration/findings/stats":          0,
		"/api/exploration/findings/asset-tree":     0,
		"/api/exploration/findings/export":         0,
		"/api/exploration/findings/bulk-status":    0,
		"/api/exploration/findings/retests/active": 0,
		"/api/tasks/8":                             0,
	}
	for path, want := range cases {
		if got := findingIDFromPath(path); got != want {
			t.Errorf("findingIDFromPath(%q) = %d, want %d", path, got, want)
		}
	}
}

func TestCanAccessTaskOwner(t *testing.T) {
	s := &Server{} // group branch is not exercised (GroupID nil), so no Manager needed
	task := &Task{Owner: "alice", GroupID: nil}

	admin := principal{username: "ARTEX", role: roleAdmin}
	alice := principal{username: "alice", role: roleUser}
	bob := principal{username: "bob", role: roleUser}

	if !s.canAccessTask(admin, task) {
		t.Fatal("admin denied access")
	}
	if !s.canAccessTask(alice, task) {
		t.Fatal("owner denied access")
	}
	if s.canAccessTask(bob, task) {
		t.Fatal("non-owner granted access to an ungrouped task")
	}
	if s.canAccessTask(alice, &Task{Owner: "", GroupID: nil}) {
		t.Fatal("empty-owner task granted to a non-admin")
	}
}

// TestTaskOwnershipAccess: over the real mux, a 'user' sees and reaches only the
// tasks it created; another user is refused; an admin sees all.
func TestTaskOwnershipAccess(t *testing.T) {
	g := newGateServer(t)
	_, aName := createTestUser(t, g, roleUser)
	_, bName := createTestUser(t, g, roleUser)
	aTok := userToken(t, g, aName, roleUser, 1)
	bTok := userToken(t, g, bName, roleUser, 1)

	// A creates a task.
	code, body := g.doAs(t, aTok, "POST", "/api/tasks", `{"description":"A task","goal":"`+gateTestGoal+`"}`)
	if code != 201 {
		t.Fatalf("A create task = %d %v", code, body)
	}
	tid, _ := body["id"].(string)
	if tid == "" {
		t.Fatalf("no task id: %v", body)
	}
	t.Cleanup(func() { g.cleanupTask(t, tid) })

	// A reaches its own task and sees it in the list.
	if code, _ := g.doAs(t, aTok, "GET", "/api/tasks/"+tid, ""); code != 200 {
		t.Fatalf("A GET own task = %d, want 200", code)
	}
	if !listHasTask(t, g, aTok, tid) {
		t.Fatal("A's own task missing from A's task list")
	}

	// B cannot reach it and does not see it.
	if code, _ := g.doAs(t, bTok, "GET", "/api/tasks/"+tid, ""); code != 403 {
		t.Fatalf("B GET A's task = %d, want 403", code)
	}
	if listHasTask(t, g, bTok, tid) {
		t.Fatal("A's task leaked into B's task list")
	}

	// Admin sees everything.
	if code, _ := g.do(t, "GET", "/api/tasks/"+tid, ""); code != 200 {
		t.Fatalf("admin GET task = %d, want 200", code)
	}
}

func listHasTask(t *testing.T, g *gateServer, token, id string) bool {
	t.Helper()
	code, body := g.doAs(t, token, "GET", "/api/tasks", "")
	if code != 200 {
		t.Fatalf("GET /api/tasks = %d %v", code, body)
	}
	tasks, _ := body["tasks"].([]any)
	for _, it := range tasks {
		m, _ := it.(map[string]any)
		if fmt.Sprint(m["id"]) == id {
			return true
		}
	}
	return false
}
