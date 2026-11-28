package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/chatbridge"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// fakeConsole is a chatConsole for the command-table tests: no PG, no engine.
type fakeConsole struct {
	tasks       []consoleTask
	taskByID    map[string]consoleTask
	pending     []consolePending
	pendingByID map[int64]consolePending
	listErr     error
	controlStat string
	controlErr  error
	decideErr   error

	lastControlID, lastControlAction string
	lastDecideID                     int64
	lastDecideAllow                  bool
	lastDecideApprover               string
}

func (f *fakeConsole) consoleListTasks() []consoleTask { return f.tasks }
func (f *fakeConsole) consoleGetTask(id string) (consoleTask, bool) {
	t, ok := f.taskByID[id]
	return t, ok
}
func (f *fakeConsole) consoleControlTask(id, action string) (string, error) {
	f.lastControlID, f.lastControlAction = id, action
	return f.controlStat, f.controlErr
}
func (f *fakeConsole) consoleListPending() ([]consolePending, error) { return f.pending, f.listErr }
func (f *fakeConsole) consoleGetPending(id int64) (consolePending, bool, error) {
	it, ok := f.pendingByID[id]
	return it, ok, nil
}
func (f *fakeConsole) consoleDecide(id int64, allow bool, approver string) error {
	f.lastDecideID, f.lastDecideAllow, f.lastDecideApprover = id, allow, approver
	return f.decideErr
}

func runCmd(t *testing.T, cmds []chatbridge.Command, name string, req chatbridge.Request) string {
	t.Helper()
	for _, c := range cmds {
		if c.Name == name {
			return c.Run(context.Background(), req)
		}
	}
	t.Fatalf("command /%s not found in table", name)
	return ""
}

func TestChatConsoleCommands(t *testing.T) {
	f := &fakeConsole{
		tasks: []consoleTask{
			{ID: "7", Name: "Bank Aceh", Status: "running", Active: true, Findings: [4]int{1, 2, 3, 4}},
			{ID: "8", Goal: "scan the DMZ\nmore", Status: "done"},
		},
		taskByID: map[string]consoleTask{
			"7": {ID: "7", Name: "Bank Aceh", Goal: "pwn it", Status: "running", Paused: true, Findings: [4]int{1, 2, 3, 4}},
		},
		pending: []consolePending{
			{ID: 42, Task: "7", Agent: "worker", Tool: "Bash", Input: `{"command":"nmap"}`, Reason: "out of scope", Risk: "high (80)"},
		},
		pendingByID: map[int64]consolePending{
			42: {ID: 42, Task: "7", Agent: "worker", Tool: "Bash", Input: `{"command":"nmap x"}`, Reason: "out of scope", Risk: "high (80)"},
		},
	}
	cmds := chatConsoleCommands(f)

	// The table must not redefine whoami/help (those are built in elsewhere).
	for _, c := range cmds {
		if c.Name == "whoami" || c.Name == "help" {
			t.Fatalf("console table must not include /%s", c.Name)
		}
	}

	if got := runCmd(t, cmds, "tasks", chatbridge.Request{}); !strings.Contains(got, "#7") ||
		!strings.Contains(got, "▶") || !strings.Contains(got, "Bank Aceh") || !strings.Contains(got, "scan the DMZ") {
		t.Fatalf("/tasks = %q", got)
	}
	if got := runCmd(t, cmds, "tasks", chatbridge.Request{}); strings.Contains(got, "\nmore") {
		t.Fatalf("/tasks must use only the first line of a goal: %q", got)
	}
	if got := runCmd(t, cmds, "task", chatbridge.Request{Args: "7"}); !strings.Contains(got, "Task #7") ||
		!strings.Contains(got, "(paused)") || !strings.Contains(got, "1 critical, 2 high, 3 medium, 4 low") {
		t.Fatalf("/task 7 = %q", got)
	}
	if got := runCmd(t, cmds, "task", chatbridge.Request{Args: "999"}); !strings.Contains(got, "No task") {
		t.Fatalf("/task 999 = %q", got)
	}
	if got := runCmd(t, cmds, "task", chatbridge.Request{}); !strings.Contains(got, "Usage:") {
		t.Fatalf("/task (no arg) = %q", got)
	}

	// Control: success records the call; error surfaces.
	f.controlStat = "paused"
	if got := runCmd(t, cmds, "pause", chatbridge.Request{Args: "7"}); !strings.Contains(got, "Task 7 paused") ||
		!strings.Contains(got, "Status: paused") {
		t.Fatalf("/pause 7 = %q", got)
	}
	if f.lastControlID != "7" || f.lastControlAction != "pause" {
		t.Fatalf("control recorded id=%q action=%q", f.lastControlID, f.lastControlAction)
	}
	f.controlErr = errString("task is being deleted")
	if got := runCmd(t, cmds, "resume", chatbridge.Request{Args: "7"}); !strings.Contains(got, "Could not resume task 7") ||
		!strings.Contains(got, "being deleted") {
		t.Fatalf("/resume 7 (err) = %q", got)
	}
	f.controlErr = nil

	// Approvals list + detail.
	if got := runCmd(t, cmds, "approvals", chatbridge.Request{}); !strings.Contains(got, "#42") ||
		!strings.Contains(got, "Bash") || !strings.Contains(got, "risk:high (80)") {
		t.Fatalf("/approvals = %q", got)
	}
	if got := runCmd(t, cmds, "approval", chatbridge.Request{Args: "42"}); !strings.Contains(got, "Approval #42") ||
		!strings.Contains(got, "nmap x") || !strings.Contains(got, "out of scope") {
		t.Fatalf("/approval 42 = %q", got)
	}

	// Decide: approver is built from the chat user id, username as a label.
	if got := runCmd(t, cmds, "approve", chatbridge.Request{Args: "42", UserID: "123", UserName: "op"}); !strings.Contains(got, "Approval 42 approved") {
		t.Fatalf("/approve 42 = %q", got)
	}
	if f.lastDecideID != 42 || !f.lastDecideAllow || f.lastDecideApprover != "telegram:123 (@op)" {
		t.Fatalf("decide recorded id=%d allow=%v approver=%q", f.lastDecideID, f.lastDecideAllow, f.lastDecideApprover)
	}
	if got := runCmd(t, cmds, "deny", chatbridge.Request{Args: "42", UserID: "123"}); !strings.Contains(got, "Approval 42 denied") {
		t.Fatalf("/deny 42 = %q", got)
	}
	if f.lastDecideAllow {
		t.Fatalf("/deny recorded allow=true")
	}
	if got := runCmd(t, cmds, "approve", chatbridge.Request{Args: "notanumber"}); !strings.Contains(got, "Usage:") {
		t.Fatalf("/approve (bad id) = %q", got)
	}

	// Decide error surfaces to the chat.
	f.decideErr = errString("approval already decided or does not exist; please refresh the list")
	if got := runCmd(t, cmds, "approve", chatbridge.Request{Args: "42", UserID: "1"}); !strings.Contains(got, "Could not approve approval 42") ||
		!strings.Contains(got, "already decided") {
		t.Fatalf("/approve (decide err) = %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestChatConsoleEmptyLists(t *testing.T) {
	cmds := chatConsoleCommands(&fakeConsole{})
	if got := runCmd(t, cmds, "tasks", chatbridge.Request{}); got != "No tasks yet." {
		t.Fatalf("/tasks empty = %q", got)
	}
	if got := runCmd(t, cmds, "approvals", chatbridge.Request{}); got != "No pending approvals." {
		t.Fatalf("/approvals empty = %q", got)
	}
}

// TestConsoleDecideAdapter exercises the security-relevant adapter against a
// real database: a Telegram /approve must resolve the pending row and record
// the chat identity as the approver, and a second decision must be refused.
func TestConsoleDecideAdapter(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	scope := "chat-console-decide"
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, scope) })

	s := &Server{m: &Manager{pg: d, interceptor: intercept.New(d)}}

	// An audit record must exist for the approver patch to be stored.
	id, err := d.CreateInterceptPending(0, 0, scope, "worker", "Bash",
		[]byte(`{"command":"nmap"}`), "out of scope", &db.InterceptAudit{Correlation: "exact"})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.consoleDecide(id, true, "telegram:123 (@op)"); err != nil {
		t.Fatalf("consoleDecide: %v", err)
	}

	var status, decidedBy, approver string
	if err := d.QueryRow(
		`SELECT status, decided_by, COALESCE(audit->>'approver','') FROM intercept_pending WHERE id=$1`, id,
	).Scan(&status, &decidedBy, &approver); err != nil {
		t.Fatal(err)
	}
	if status != "allowed" || decidedBy != "human" || approver != "telegram:123 (@op)" {
		t.Fatalf("stored status=%q decided_by=%q approver=%q", status, decidedBy, approver)
	}

	// A second decision on the same row is refused.
	if err := s.consoleDecide(id, false, "telegram:123 (@op)"); err != intercept.ErrAlreadyDecided {
		t.Fatalf("second decide err = %v, want ErrAlreadyDecided", err)
	}
}
