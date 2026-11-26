package guard

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/intercept"
)

// Automatic scan (TargetScope.AutoApprove) turns a tool call the rules would ask
// about into an allow, so a scan runs without stopping; it never overrides a deny,
// and the target gate still asks for an out-of-scope destination.
func TestAutoApproveTurnsAskIntoAllow(t *testing.T) {
	g := newGateDB(t)
	ask := marker(t)
	askRule := g.rule("ask", ask)
	guard := NewWithInterceptor(g.ic)
	input := `{"command":"echo ` + ask + `"}`
	base := intercept.WithTaskContext(context.Background(), g.task, "worker", nil)

	// Without auto-approve the ask rule opens a classic pending row and waits.
	ch := call(guard, base, "Bash", input)
	row := g.onePending(ch)
	if row.ruleID != askRule.ID || row.targetKey != "" {
		t.Fatalf("ask row = %+v, want a classic ask of the rule", row)
	}
	g.decide(row.id, true)
	if r := g.result(ch); r.block {
		t.Fatalf("approved ask blocked: %s", r.msg)
	}

	// With auto-approve on, the same ask passes without a pending row, logged allowed.
	autoCtx := intercept.WithTargetScope(base, intercept.TargetScope{
		TaskID: g.task, AutoApprove: func() bool { return true }, WaitBound: time.Minute, Interceptor: g.ic,
	})
	before := len(g.rows())
	if block, msg := pre(guard, autoCtx, "Bash", input); block {
		t.Fatalf("auto-approve: the ask was blocked: %s", msg)
	}
	rows := g.rows()[before:]
	if len(rows) != 1 || rows[0].status != "allowed" || rows[0].targetKey != "" {
		t.Fatalf("auto-approve rows = %+v, want one allowed non-target row", rows)
	}
}

// Auto-approve never overrides a deny rule.
func TestAutoApproveDoesNotOverrideDeny(t *testing.T) {
	g := newGateDB(t)
	deny := marker(t)
	g.rule("deny", deny)
	guard := NewWithInterceptor(g.ic)
	autoCtx := intercept.WithTargetScope(
		intercept.WithTaskContext(context.Background(), g.task, "worker", nil),
		intercept.TargetScope{TaskID: g.task, AutoApprove: func() bool { return true }, WaitBound: time.Minute, Interceptor: g.ic},
	)
	if block, _ := pre(guard, autoCtx, "Bash", `{"command":"echo `+deny+`"}`); !block {
		t.Fatal("auto-approve must not turn a deny into an allow")
	}
}

// With the target gate and auto-approve both on, an out-of-scope destination still
// raises a target approval request: auto-approve covers tool-call asks, not the
// scope boundary.
func TestAutoApproveStillGatesOutOfScope(t *testing.T) {
	g := newGateDB(t)
	guard := NewWithInterceptor(g.ic)
	ctx := intercept.WithTargetScope(
		intercept.WithTaskContext(context.Background(), g.task, "worker", nil),
		intercept.TargetScope{TaskID: g.task, Enabled: func() bool { return true },
			AutoApprove: func() bool { return true }, WaitBound: time.Minute, Interceptor: g.ic},
	)
	// The task declares no scope, so every host is out of scope.
	ch := call(guard, ctx, "WebFetch", `{"url":"https://app.example.com/"}`)
	row := g.onePending(ch)
	if row.targetKey == "" {
		t.Fatalf("auto-approve bypassed the target gate: row = %+v, want a target request", row)
	}
	g.decide(row.id, false) // operator denies the out-of-scope host
	if r := g.result(ch); !r.block {
		t.Fatalf("denied out-of-scope target was not blocked: %+v", r)
	}
}
