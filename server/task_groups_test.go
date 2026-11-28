package server

import (
	"fmt"
	"testing"
	"time"
)

// TestTaskGroupAccess: a task placed in a group is reachable by every member of
// that group, and by no one else; deleting the group reverts it to owner-only.
func TestTaskGroupAccess(t *testing.T) {
	g := newGateServer(t)
	_, aName := createTestUser(t, g, roleUser)
	_, bName := createTestUser(t, g, roleUser)
	_, cName := createTestUser(t, g, roleUser)
	aTok := userToken(t, g, aName, roleUser, 1)
	bTok := userToken(t, g, bName, roleUser, 1)
	cTok := userToken(t, g, cName, roleUser, 1)

	// Admin creates a group and assigns A and B to it.
	code, body := g.do(t, "POST", "/api/task-groups", fmt.Sprintf(`{"name":"shared-%d"}`, time.Now().UnixNano()))
	if code != 201 {
		t.Fatalf("create group = %d %v", code, body)
	}
	gid := int64(body["id"].(float64))
	t.Cleanup(func() { g.do(t, "DELETE", fmt.Sprintf("/api/task-groups/%d", gid), "") })
	if code, _ := g.do(t, "PUT", fmt.Sprintf("/api/task-groups/%d/members", gid),
		fmt.Sprintf(`{"members":[%q,%q]}`, aName, bName)); code != 200 {
		t.Fatalf("set members failed")
	}

	// A creates a task and places it in the group.
	code, body = g.doAs(t, aTok, "POST", "/api/tasks", `{"description":"grp","goal":"`+gateTestGoal+`"}`)
	if code != 201 {
		t.Fatalf("A create task = %d %v", code, body)
	}
	tid := body["id"].(string)
	t.Cleanup(func() { g.cleanupTask(t, tid) })
	if code, b := g.doAs(t, aTok, "PUT", "/api/tasks/"+tid+"/group", fmt.Sprintf(`{"group_id":%d}`, gid)); code != 200 {
		t.Fatalf("A set task group = %d %v", code, b)
	}

	// B (a member) can reach it; C (not a member) cannot.
	if code, _ := g.doAs(t, bTok, "GET", "/api/tasks/"+tid, ""); code != 200 {
		t.Fatalf("B GET grouped task = %d, want 200", code)
	}
	if !listHasTask(t, g, bTok, tid) {
		t.Fatal("grouped task missing from member B's list")
	}
	if code, _ := g.doAs(t, cTok, "GET", "/api/tasks/"+tid, ""); code != 403 {
		t.Fatalf("C GET grouped task = %d, want 403", code)
	}

	// A non-member cannot place the task into the group (403), and a user sees
	// only the groups it belongs to.
	if code, _ := g.doAs(t, cTok, "PUT", "/api/tasks/"+tid+"/group", fmt.Sprintf(`{"group_id":%d}`, gid)); code == 200 {
		t.Fatal("C (no task access) set group succeeded")
	}
	if n := userGroupCount(t, g, cTok); n != 0 {
		t.Fatalf("C sees %d groups, want 0 (not a member)", n)
	}
	if n := userGroupCount(t, g, bTok); n < 1 {
		t.Fatalf("B sees %d groups, want >= 1", n)
	}

	// Deleting the group reverts the task to owner-only: B loses access.
	if code, _ := g.do(t, "DELETE", fmt.Sprintf("/api/task-groups/%d", gid), ""); code != 200 {
		t.Fatalf("delete group failed")
	}
	if code, _ := g.doAs(t, bTok, "GET", "/api/tasks/"+tid, ""); code != 403 {
		t.Fatalf("B GET after group delete = %d, want 403", code)
	}
}

func userGroupCount(t *testing.T, g *gateServer, token string) int {
	t.Helper()
	code, body := g.doAs(t, token, "GET", "/api/task-groups", "")
	if code != 200 {
		t.Fatalf("GET /api/task-groups = %d %v", code, body)
	}
	groups, _ := body["groups"].([]any)
	return len(groups)
}
