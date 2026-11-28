package server

import (
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/chatbridge"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// TestBridgeDecide drives the chat-bridge approval decision against a real
// database: /approve resolves the pending row and records the chat identity as
// the approver, and a second decision is refused.
func TestBridgeDecide(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	scope := "bridge-approve"
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, scope) })
	s := &Server{m: &Manager{pg: d, interceptor: intercept.New(d)}}

	id, err := d.CreateInterceptPending(0, 0, scope, "worker", "Bash",
		[]byte(`{"command":"nmap"}`), "out of scope", &db.InterceptAudit{Correlation: "exact"})
	if err != nil {
		t.Fatal(err)
	}

	req := chatbridge.Request{Kind: "telegram", ChatID: "100", UserID: "123", UserName: "op",
		Args: "#" + strconv.FormatInt(id, 10)}
	if got := s.bridgeDecide(req, true); !strings.Contains(got, "approved") {
		t.Fatalf("approve reply = %q", got)
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

	// Second decision is refused (already decided).
	if got := s.bridgeDecide(req, false); !strings.Contains(got, "Could not deny") {
		t.Fatalf("second decide reply = %q", got)
	}

	// Bad argument → usage.
	if got := s.bridgeDecide(chatbridge.Request{Args: "x"}, true); !strings.Contains(got, "Usage:") {
		t.Fatalf("bad id reply = %q", got)
	}
}
