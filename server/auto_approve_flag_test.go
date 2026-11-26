package server

import (
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Automatic-scan opt-in over the real mux: the create flag, the DTO, the stored
// column, the live scope, the metadata patch, and the global default.

// setAutoApproveDefault sets the global auto_approve_default and restores it to
// false when the test ends; settings are global and persist across runs.
func setAutoApproveDefault(t *testing.T, g *gateServer, v bool) {
	t.Helper()
	body := `{"auto_approve_default":false}`
	if v {
		body = `{"auto_approve_default":true}`
	}
	if code, _ := g.do(t, "PUT", "/api/settings", body); code != 200 {
		t.Fatalf("set auto_approve_default=%v: %d", v, code)
	}
	t.Cleanup(func() { g.do(t, "PUT", "/api/settings", `{"auto_approve_default":false}`) })
}

// The flag is accepted on create; omitted means off (inheriting the default,
// which is off). The DTO, the stored column and the task scope all agree.
func TestCreateTaskAcceptsAutoApprove(t *testing.T) {
	g := newGateServer(t)
	// Settings are global and persist across runs, so pin the default to off for
	// the "omitted" case rather than depend on whatever another test left behind.
	setAutoApproveDefault(t, g, false)
	for _, tc := range []struct {
		field string
		want  bool
	}{
		{`,"auto_approve":true`, true},
		{`,"auto_approve":false`, false},
		{``, false},
	} {
		code, body := g.do(t, "POST", "/api/tasks", `{"description":"auto create","goal":"`+gateTestGoal+`"`+tc.field+`}`)
		id, _ := body["id"].(string)
		if code != 201 || id == "" {
			t.Fatalf("create %q: %d %v", tc.field, code, body)
		}
		g.cleanupTask(t, id)
		task, ok := g.m.Task(id)
		if !ok || body["auto_approve"] != tc.want {
			t.Fatalf("create %q: auto_approve=%v, want %v", tc.field, body["auto_approve"], tc.want)
		}
		if got := task.targetScope(0).AutoApprove; got == nil || got() != tc.want {
			t.Fatalf("create %q: scope AutoApprove != %v", tc.field, tc.want)
		}
		n, _ := strconv.ParseInt(id, 10, 64)
		stored, err := g.m.pg.GetTask(n)
		if err != nil || stored == nil || stored.AutoApprove != tc.want {
			t.Fatalf("create %q: stored %+v, %v; want %v", tc.field, stored, err, tc.want)
		}
	}
}

// The flag is read on every tool call: a switch through the API is seen by a
// scope handed out before it. A task created via the API with no flag inherits
// the global default.
func TestAutoApproveLiveSwitchAndDefault(t *testing.T) {
	g := newGateServer(t)
	task := g.newTask(t, db.TaskCreateOptions{})
	scope := task.targetScope(0)
	if scope.AutoApprove == nil || scope.AutoApprove() {
		t.Fatal("a new task must have automatic scan off")
	}
	if code, body := g.do(t, "GET", "/api/tasks/"+task.ID, ""); code != 200 || body["auto_approve"] != false {
		t.Fatalf("task detail: %d %v, want auto_approve false", code, body)
	}

	if code, body := g.do(t, "PATCH", "/api/tasks/"+task.ID, `{"auto_approve":true}`); code != 200 || body["auto_approve"] != true {
		t.Fatalf("switch on: %d %v", code, body)
	}
	if !scope.AutoApprove() {
		t.Fatal("the scope handed out before the switch still reports automatic scan off")
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if stored, err := g.m.pg.GetTask(id); err != nil || stored == nil || !stored.AutoApprove {
		t.Fatalf("stored task = %+v, %v; want automatic scan on", stored, err)
	}
	// A rename leaves the flag alone.
	if code, body := g.do(t, "PATCH", "/api/tasks/"+task.ID, `{"name":"renamed"}`); code != 200 || body["auto_approve"] != true {
		t.Fatalf("rename: %d %v, want automatic scan still on", code, body)
	}

	// With the global default on, a task created via the API without the flag
	// starts with automatic scan on. Restore it afterwards: settings are global.
	setAutoApproveDefault(t, g, true)
	code, body := g.do(t, "POST", "/api/tasks", `{"description":"inherits default","goal":"`+gateTestGoal+`"}`)
	childID, _ := body["id"].(string)
	if code != 201 || body["auto_approve"] != true {
		t.Fatalf("create inheriting default: %d %v, want auto_approve true", code, body)
	}
	g.cleanupTask(t, childID)
	// An explicit flag still wins over the default.
	code, body = g.do(t, "POST", "/api/tasks", `{"description":"explicit off","goal":"`+gateTestGoal+`","auto_approve":false}`)
	offID, _ := body["id"].(string)
	if code != 201 || body["auto_approve"] != false {
		t.Fatalf("explicit off over default: %d %v, want auto_approve false", code, body)
	}
	g.cleanupTask(t, offID)
}
