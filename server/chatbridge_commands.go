package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/chatbridge"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// Task and approval commands for the inbound chat bridge: an allowlisted
// operator drives ARTEX from a chat app. The command table is built from a
// small chatConsole interface so it can be unit-tested with a fake, while the
// *Server implementation (below) is a thin adapter over the same Manager and
// Interceptor calls the HTTP handlers use. defaultChatBridgeCommands (whoami,
// /help) is left untouched and these are appended to it in server.New.
//
// All replies are plain text. chatbridge/telegram.go sends with no parse_mode
// and truncates at the transport limit, so agent- and target-influenced text
// (a tool's argv, a finding's reason) can never inject markup or a link; the
// list commands still cap their own length so a long queue is paged, not cut.

// Row caps keep a list reply well under the transport's ~4096-char limit so a
// long queue is paged ("…and N more"), not silently cut mid-row. Approval rows
// are two lines, so their cap is lower.
const (
	chatConsoleTaskCap    = 25
	chatConsolePendingCap = 12
)

// consoleTask is one task as the chat console shows it.
type consoleTask struct {
	ID       string
	Name     string
	Goal     string
	Status   string
	Active   bool
	Paused   bool
	Findings [4]int // critical, high, medium, low
}

// consolePending is one pending approval request as the chat console shows it.
type consolePending struct {
	ID      int64
	Task    string
	Agent   string
	Tool    string
	Input   string
	Reason  string
	Risk    string
	Targets string // target-gate addresses + resolved IPs; shown in detail only
}

// chatConsole is everything the command table needs from the server. The real
// implementation is *Server; tests substitute a fake.
type chatConsole interface {
	consoleListTasks() []consoleTask
	consoleGetTask(id string) (consoleTask, bool)
	consoleControlTask(id, action string) (status string, err error)
	consoleListPending() ([]consolePending, error)
	consoleGetPending(id int64) (item consolePending, found bool, err error)
	consoleDecide(id int64, allow bool, approver string) error
}

// chatConsoleCommands builds the task and approval command table over c. It
// does not include whoami or help: those are built in elsewhere.
func chatConsoleCommands(c chatConsole) []chatbridge.Command {
	return []chatbridge.Command{
		{
			Name:    "tasks",
			Summary: "list pentest tasks and their status",
			Run: func(_ context.Context, _ chatbridge.Request) string {
				return formatTaskList(c.consoleListTasks())
			},
		},
		{
			Name:    "task",
			Usage:   "<id>",
			Summary: "show one task's detail",
			Run: func(_ context.Context, req chatbridge.Request) string {
				id := trimID(req.Args)
				if id == "" {
					return "Usage: /task <id> — see /tasks for ids."
				}
				t, ok := c.consoleGetTask(id)
				if !ok {
					return "No task with id " + id + "."
				}
				return formatTaskDetail(t)
			},
		},
		{
			Name:    "pause",
			Usage:   "<id>",
			Summary: "pause a running task",
			Run:     taskControlCmd(c, "pause"),
		},
		{
			Name:    "resume",
			Usage:   "<id>",
			Summary: "resume a paused task",
			Run:     taskControlCmd(c, "resume"),
		},
		{
			Name:    "approvals",
			Summary: "list pending approval requests",
			Run: func(_ context.Context, _ chatbridge.Request) string {
				items, err := c.consoleListPending()
				if err != nil {
					return "Could not read approvals: " + err.Error()
				}
				return formatPendingList(items)
			},
		},
		{
			Name:    "approval",
			Usage:   "<id>",
			Summary: "show one approval request's detail",
			Run: func(_ context.Context, req chatbridge.Request) string {
				id, ok := parseConsoleID(req.Args)
				if !ok {
					return "Usage: /approval <id> — see /approvals for ids."
				}
				it, found, err := c.consoleGetPending(id)
				if err != nil {
					return "Could not read approval: " + err.Error()
				}
				if !found {
					return fmt.Sprintf("No pending approval with id %d.", id)
				}
				return formatPendingDetail(it)
			},
		},
		{
			Name:    "approve",
			Usage:   "<id>",
			Summary: "allow a pending request",
			Run:     decideCmd(c, true),
		},
		{
			Name:    "deny",
			Usage:   "<id>",
			Summary: "deny a pending request",
			Run:     decideCmd(c, false),
		},
	}
}

func taskControlCmd(c chatConsole, action string) chatbridge.CommandFunc {
	return func(_ context.Context, req chatbridge.Request) string {
		id := trimID(req.Args)
		if id == "" {
			return "Usage: /" + action + " <id> — see /tasks for ids."
		}
		status, err := c.consoleControlTask(id, action)
		if err != nil {
			return fmt.Sprintf("Could not %s task %s: %s", action, id, err.Error())
		}
		// "pause"+"d" = "paused", "resume"+"d" = "resumed".
		return fmt.Sprintf("Task %s %sd. Status: %s", id, action, status)
	}
}

func decideCmd(c chatConsole, allow bool) chatbridge.CommandFunc {
	verb, past := "deny", "denied"
	if allow {
		verb, past = "approve", "approved"
	}
	return func(_ context.Context, req chatbridge.Request) string {
		id, ok := parseConsoleID(req.Args)
		if !ok {
			return "Usage: /" + verb + " <id> — see /approvals for ids."
		}
		if err := c.consoleDecide(id, allow, consoleApprover(req)); err != nil {
			return fmt.Sprintf("Could not %s approval %d: %s", verb, id, err.Error())
		}
		return fmt.Sprintf("Approval %d %s.", id, past)
	}
}

// consoleApprover builds the audit identity for a decision. The chat user id is
// the stable key (usernames are optional and can change); the username, when
// set, is only a human-readable label.
func consoleApprover(req chatbridge.Request) string {
	who := "telegram:" + req.UserID
	if req.UserName != "" {
		who += " (@" + req.UserName + ")"
	}
	return who
}

// trimID normalizes an id argument: the lists print "#7" and "#42", so a user
// who copies one back ("/pause #7") must still work.
func trimID(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "#")
}

func parseConsoleID(s string) (int64, bool) {
	id, err := strconv.ParseInt(trimID(s), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func formatTaskList(tasks []consoleTask) string {
	if len(tasks) == 0 {
		return "No tasks yet."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Tasks (%d):\n", len(tasks))
	shown, more := tasks, 0
	if len(shown) > chatConsoleTaskCap {
		more = len(shown) - chatConsoleTaskCap
		shown = shown[:chatConsoleTaskCap]
	}
	for _, t := range shown {
		marker := "·"
		if t.Active {
			marker = "▶"
		}
		label := clip(t.Name, 60)
		if label == "" {
			label = firstLine(t.Goal, 60)
		}
		if label == "" {
			label = "(unnamed)"
		}
		status := t.Status
		if t.Paused {
			status += "/paused"
		}
		fmt.Fprintf(&b, "%s #%s  %s  %s\n", marker, t.ID, status, label)
	}
	if more > 0 {
		fmt.Fprintf(&b, "…and %d more. Use /task <id> for detail.", more)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatTaskDetail(t consoleTask) string {
	name := t.Name
	if name == "" {
		name = "(unnamed)"
	}
	status := t.Status
	if t.Paused {
		status += " (paused)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Task #%s — %s\n", t.ID, name)
	fmt.Fprintf(&b, "Status: %s\n", status)
	if t.Goal != "" {
		fmt.Fprintf(&b, "Goal: %s\n", clip(t.Goal, 300))
	}
	fmt.Fprintf(&b, "Findings: %d critical, %d high, %d medium, %d low",
		t.Findings[0], t.Findings[1], t.Findings[2], t.Findings[3])
	return b.String()
}

func formatPendingList(items []consolePending) string {
	if len(items) == 0 {
		return "No pending approvals."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Pending approvals (%d):\n", len(items))
	shown, more := items, 0
	if len(shown) > chatConsolePendingCap {
		more = len(shown) - chatConsolePendingCap
		shown = shown[:chatConsolePendingCap]
	}
	for _, it := range shown {
		fmt.Fprintf(&b, "#%d  [%s]  %s  risk:%s\n", it.ID, it.Task, clip(it.Tool, 40), it.Risk)
		if it.Reason != "" {
			fmt.Fprintf(&b, "   %s\n", clip(it.Reason, 100))
		}
	}
	if more > 0 {
		fmt.Fprintf(&b, "…and %d more.\n", more)
	}
	b.WriteString("Use /approval <id> for detail, then /approve <id> or /deny <id>.")
	return b.String()
}

func formatPendingDetail(it consolePending) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Approval #%d\n", it.ID)
	fmt.Fprintf(&b, "Task: %s\n", it.Task)
	if it.Agent != "" {
		fmt.Fprintf(&b, "Agent: %s\n", it.Agent)
	}
	fmt.Fprintf(&b, "Tool: %s\n", it.Tool)
	fmt.Fprintf(&b, "Risk: %s\n", it.Risk)
	if it.Reason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", clip(it.Reason, 300))
	}
	if it.Targets != "" {
		fmt.Fprintf(&b, "Targets (pinned on approve): %s\n", it.Targets)
	}
	if strings.TrimSpace(it.Input) != "" {
		fmt.Fprintf(&b, "Input: %s\n", clip(it.Input, 1000))
	}
	fmt.Fprintf(&b, "\nReply /approve %d or /deny %d.", it.ID, it.ID)
	return b.String()
}

// formatTargets summarizes a target-gate request's addresses. Allowing one pins
// the resolved IPs, so the operator sees "host:port → resolved ips" per target.
func formatTargets(targets []db.InterceptTarget) string {
	if len(targets) == 0 {
		return ""
	}
	parts := make([]string, 0, len(targets))
	for _, t := range targets {
		host := t.Host
		if t.Port > 0 {
			host = fmt.Sprintf("%s:%d", t.Host, t.Port)
		}
		if len(t.ResolvedIPs) > 0 {
			host += " → " + strings.Join(t.ResolvedIPs, ", ")
		}
		parts = append(parts, host)
	}
	return clip(strings.Join(parts, "; "), 400)
}

// clip shortens s to at most n runes, appending an ellipsis when it cut.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + "…"
}

// --- *Server adapter: the real chatConsole, over the same Manager and
// Interceptor calls the HTTP handlers use. ---

func (s *Server) consoleTaskFrom(t *Task, active string, m db.TaskListMetrics) consoleTask {
	return consoleTask{
		ID:       t.ID,
		Name:     t.Name,
		Goal:     t.Goal,
		Status:   s.resolvedTaskStatus(t),
		Active:   t.ID == active,
		Paused:   t.lifecycleSnapshot().Paused,
		Findings: [4]int{m.Findings.Critical, m.Findings.High, m.Findings.Medium, m.Findings.Low},
	}
}

func (s *Server) consoleActiveTaskID() string {
	if a := s.m.ActiveTask(); a != nil {
		return a.ID
	}
	return ""
}

func (s *Server) consoleListTasks() []consoleTask {
	list := s.m.List()
	active := s.consoleActiveTaskID()
	metrics, _ := s.m.PG().TaskListMetricsAll()
	out := make([]consoleTask, 0, len(list))
	for _, t := range list {
		out = append(out, s.consoleTaskFrom(t, active, metrics[t.ExpID]))
	}
	return out
}

func (s *Server) consoleGetTask(id string) (consoleTask, bool) {
	t, ok := s.m.Task(id)
	if !ok {
		return consoleTask{}, false
	}
	metrics, _ := s.m.PG().TaskListMetricsAll()
	return s.consoleTaskFrom(t, s.consoleActiveTaskID(), metrics[t.ExpID]), true
}

func (s *Server) consoleControlTask(id, action string) (string, error) {
	t, ok := s.m.Task(id)
	if !ok {
		return "", fmt.Errorf("task not found")
	}
	res, err := s.applyTaskControl(t, action)
	if err != nil {
		return "", err
	}
	return res.Status, nil
}

func consolePendingFrom(p db.InterceptPending) consolePending {
	risk := intercept.ScoreRisk(p.ToolName, p.ToolInput)
	task := "—"
	if p.TaskID != nil && *p.TaskID != "" {
		task = *p.TaskID
	}
	return consolePending{
		ID:     p.ID,
		Task:   task,
		Agent:  p.AgentName,
		Tool:   p.ToolName,
		Input:  string(p.ToolInput),
		Reason: p.Reason,
		Risk:   fmt.Sprintf("%s (%d)", risk.Level, risk.Score),
	}
}

func (s *Server) consoleListPending() ([]consolePending, error) {
	pg := s.m.PG()
	if pg == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	pending, err := pg.ListPendingIntercepts()
	if err != nil {
		return nil, err
	}
	out := make([]consolePending, 0, len(pending))
	for _, p := range pending {
		out = append(out, consolePendingFrom(p))
	}
	return out, nil
}

func (s *Server) consoleGetPending(id int64) (consolePending, bool, error) {
	pg := s.m.PG()
	if pg == nil {
		return consolePending{}, false, fmt.Errorf("database unavailable")
	}
	p, err := pg.GetInterceptPending(id)
	if err != nil {
		return consolePending{}, false, err
	}
	if p == nil {
		return consolePending{}, false, nil
	}
	item := consolePendingFrom(*p)
	// A target-gate request carries the resolved addresses in audit.targets;
	// surface them so an approve is not blind. Best-effort: a read error leaves
	// the rest of the detail intact.
	if p.DecisionSource == "target" {
		var raw json.RawMessage
		if qErr := pg.QueryRow(`SELECT COALESCE(audit->'targets','[]') FROM intercept_pending WHERE id=$1`, id).Scan(&raw); qErr == nil {
			var targets []db.InterceptTarget
			if json.Unmarshal(raw, &targets) == nil {
				item.Targets = formatTargets(targets)
			}
		}
	}
	return item, true, nil
}

func (s *Server) consoleDecide(id int64, allow bool, approver string) error {
	return s.m.interceptor.Decide(id, allow, approver, "telegram")
}
