package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Per-user task access. A task records its owner (the username that created it).
// An 'admin' (and the ARTEX bootstrap admin) accesses every task; a 'user' may
// access only the tasks it owns or that belong to a task group it is a member
// of. taskGate enforces this on every /api/tasks/{id} route centrally, and
// listTasks filters the list the same way.

// requestOwner returns the authenticated caller's username, for recording task
// ownership. It falls back to the bootstrap admin when identity is absent.
func requestOwner(r *http.Request) string {
	if id, ok := identityFrom(r.Context()); ok && id.username != "" {
		return id.username
	}
	return bootstrapAdmin
}

// canAccessTask reports whether principal p may access task t.
func (s *Server) canAccessTask(p principal, t *Task) bool {
	if p.admin() {
		return true
	}
	if t == nil {
		return false
	}
	if t.Owner != "" && strings.EqualFold(t.Owner, p.username) { // Owner is set once at creation
		return true
	}
	if gid := t.groupID(); gid != nil {
		member, _ := s.m.PG().IsTaskGroupMember(*gid, p.username)
		return member
	}
	return false
}

// groupID returns the task's group under the lifecycle lock (it changes via
// setTaskGroup).
func (t *Task) groupID() *int64 {
	t.lifecycleMu.RLock()
	defer t.lifecycleMu.RUnlock()
	return t.GroupID
}

// setGroupID updates the in-memory group after a persisted change.
func (t *Task) setGroupID(gid *int64) {
	t.lifecycleMu.Lock()
	t.GroupID = gid
	t.lifecycleMu.Unlock()
}

// taskGate refuses a non-admin caller access to a task it may not see, on every
// /api/tasks/{numeric id}... route. Collection routes (/api/tasks,
// /api/tasks/category/..., /api/tasks/control/..., /api/tasks/archive/...) pass
// through: the list is filtered in listTasks and the batch handlers filter their
// ids. requireAuth has already put the identity in the context.
func (s *Server) taskGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := taskIDFromPath(r.URL.Path)
		if id == "" {
			next.ServeHTTP(w, r)
			return
		}
		p, ok := identityFrom(r.Context())
		if !ok || p.admin() {
			next.ServeHTTP(w, r)
			return
		}
		t, found := s.m.Task(id)
		if !found {
			next.ServeHTTP(w, r) // let the handler answer 404
			return
		}
		if !s.canAccessTask(p, t) {
			writeErr(w, 403, "you do not have access to this task")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// findingGate refuses a non-admin caller access to a single finding whose task
// it may not see, on every /api/exploration/findings/{id}... route. The
// collection routes (groups, stats, asset-tree, export, bulk-*) pass through:
// they are already narrowed by restrictFindingFilter.
func (s *Server) findingGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := findingIDFromPath(r.URL.Path)
		if id == 0 {
			next.ServeHTTP(w, r)
			return
		}
		p, ok := identityFrom(r.Context())
		if !ok || p.admin() {
			next.ServeHTTP(w, r)
			return
		}
		taskID, found, err := s.m.PG().FindingTaskID(id)
		if err != nil || !found {
			next.ServeHTTP(w, r) // let the handler answer (404/500)
			return
		}
		if !s.canAccessFindingTask(r, taskID) {
			writeErr(w, 403, "you do not have access to this finding")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// findingIDFromPath returns the numeric finding id in
// /api/exploration/findings/{id}... or 0 for a collection route.
func findingIDFromPath(path string) int64 {
	const pfx = "/api/exploration/findings/"
	if !strings.HasPrefix(path, pfx) {
		return 0
	}
	seg := path[len(pfx):]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	n, err := strconv.ParseInt(seg, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// taskIDFromPath returns the numeric task id in /api/tasks/{id}... or "" when
// the path is not a per-task route (a collection verb like "category" or
// "control" is not an id).
func taskIDFromPath(path string) string {
	const pfx = "/api/tasks/"
	if !strings.HasPrefix(path, pfx) {
		return ""
	}
	seg := path[len(pfx):]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	if seg == "" {
		return ""
	}
	for _, c := range seg {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return seg
}

// deniesTask reports whether the caller may NOT access task t — used by the
// batch handlers, whose collection path taskGate does not cover, to skip tasks
// the caller does not own.
func (s *Server) deniesTask(r *http.Request, t *Task) bool {
	p, ok := identityFrom(r.Context())
	return ok && !s.canAccessTask(p, t)
}

// restrictFindingFilter narrows a findings query to the caller's own / group
// tasks when the caller is not an admin. Findings live under /api/exploration,
// outside taskGate, so each findings handler must call this.
func (s *Server) restrictFindingFilter(r *http.Request, f *db.FindingFilter) {
	p, ok := identityFrom(r.Context())
	if !ok || p.admin() {
		return
	}
	f.RestrictOwner = p.username
	if gids, err := s.m.PG().GroupsForUser(p.username); err == nil {
		f.RestrictGroupIDs = gids
	}
}

// canAccessFindingTask reports whether the caller may see a finding that belongs
// to task taskID (nil = no task → admin-only). Admin sees all.
func (s *Server) canAccessFindingTask(r *http.Request, taskID *int64) bool {
	p, ok := identityFrom(r.Context())
	if !ok || p.admin() {
		return true
	}
	if taskID == nil {
		return false // a finding with no task is not owned by any user
	}
	t, found := s.m.Task(strconv.FormatInt(*taskID, 10))
	if !found {
		return false
	}
	return s.canAccessTask(p, t)
}

// accessibleFindingIDs narrows a list of finding ids (from a bulk request body)
// to those the caller may act on. Admin keeps all.
func (s *Server) accessibleFindingIDs(r *http.Request, ids []int64) []int64 {
	p, ok := identityFrom(r.Context())
	if !ok || p.admin() {
		return ids
	}
	gids, _ := s.m.PG().GroupsForUser(p.username)
	out, err := s.m.PG().FilterAccessibleFindingIDs(ids, p.username, gids)
	if err != nil {
		return nil // fail closed
	}
	return out
}

// accessibleTasks filters a task list to those the principal may access.
func (s *Server) accessibleTasks(p principal, tasks []*Task) []*Task {
	if p.admin() {
		return tasks
	}
	out := make([]*Task, 0, len(tasks))
	for _, t := range tasks {
		if s.canAccessTask(p, t) {
			out = append(out, t)
		}
	}
	return out
}
