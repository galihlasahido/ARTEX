package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/chatbridge"
	"github.com/Autumn-27/artex/intercept"
)

// Approval commands of the chat bridge: an allowlisted operator lists pending
// gate approvals and decides them from the chat app. A decision goes through
// the same Interceptor.Decide as the web approval page and records the chat
// identity as the approver, so the audit trail is identical. These sit beside
// the task commands in chatBridgeHandlers.

func (s *Server) bridgeApprovals(_ context.Context, req chatbridge.Request) string {
	pg := s.m.PG()
	if pg == nil {
		return "Database unavailable."
	}
	pending, err := pg.ListPendingIntercepts()
	if err != nil {
		return "Could not read approvals. Try again."
	}
	if len(pending) == 0 {
		return "No pending approvals."
	}
	n := min(len(pending), chatBridgeListLimit)
	var b strings.Builder
	fmt.Fprintf(&b, "Pending approvals (%d", n)
	if len(pending) > chatBridgeListLimit {
		fmt.Fprintf(&b, " of %d", len(pending))
	}
	b.WriteString("):")
	for _, p := range pending[:n] {
		risk := intercept.ScoreRisk(p.ToolName, p.ToolInput)
		task := "—"
		if p.TaskID != nil && *p.TaskID != "" {
			task = *p.TaskID
		}
		fmt.Fprintf(&b, "\n#%d [%s] %s · risk %s(%d)", p.ID, task, bridgeCut(p.ToolName, 40), risk.Level, risk.Score)
		if r := oneLine(p.Reason); r != "" {
			fmt.Fprintf(&b, "\n   %s", bridgeCut(r, 100))
		}
	}
	b.WriteString("\n\nSend /approve <id> or /deny <id>.")
	return b.String()
}

func (s *Server) bridgeApprove(_ context.Context, req chatbridge.Request) string {
	return s.bridgeDecide(req, true)
}

func (s *Server) bridgeDeny(_ context.Context, req chatbridge.Request) string {
	return s.bridgeDecide(req, false)
}

// bridgeDecide resolves one pending approval. The chat user id is the stable
// approver key; the username, when set, is a readable label.
func (s *Server) bridgeDecide(req chatbridge.Request, allow bool) string {
	verb, past := "deny", "denied"
	if allow {
		verb, past = "approve", "approved"
	}
	id := strings.TrimPrefix(strings.TrimSpace(req.Args), "#")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return "Usage: /" + verb + " <id> — send /approvals for the ids."
	}
	approver := "telegram:" + req.UserID
	if req.UserName != "" {
		approver += " (@" + req.UserName + ")"
	}
	if err := s.m.interceptor.Decide(n, allow, approver, "telegram"); err != nil {
		return fmt.Sprintf("Could not %s approval %d: %s", verb, n, err.Error())
	}
	return fmt.Sprintf("Approval %d %s.", n, past)
}
