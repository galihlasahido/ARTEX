package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Task group management. Groups and their membership are admin-only; a task's
// owner (or an admin) assigns the task to a group so every member can access it.

// listTaskGroups: an admin sees all groups; a user sees only the groups it is a
// member of (so it can place its tasks into one).
func (s *Server) listTaskGroups(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	groups, err := pg.ListTaskGroups()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p, ok := identityFrom(r.Context()); ok && !p.admin() {
		kept := groups[:0]
		for _, g := range groups {
			for _, m := range g.Members {
				if strings.EqualFold(m, p.username) {
					kept = append(kept, g)
					break
				}
			}
		}
		groups = kept
	}
	if groups == nil {
		groups = []db.TaskGroup{}
	}
	writeJSON(w, 200, map[string]any{"groups": groups})
}

// createTaskGroup (admin) creates an empty group.
func (s *Server) createTaskGroup(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 64 {
		writeErr(w, 400, "group name must be 1-64 characters")
		return
	}
	g, err := pg.CreateTaskGroup(name)
	if err != nil {
		if errors.Is(err, db.ErrTaskGroupExists) {
			writeErr(w, 409, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, g)
}

// updateTaskGroupMembers (admin) replaces a group's member list.
func (s *Server) updateTaskGroupMembers(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad group id")
		return
	}
	var req struct {
		Members []string `json:"members"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	members := make([]string, 0, len(req.Members))
	for _, m := range req.Members {
		if m = strings.TrimSpace(m); m != "" {
			members = append(members, m)
		}
	}
	if len(members) > 500 {
		writeErr(w, 400, "too many members")
		return
	}
	if err := pg.SetTaskGroupMembers(id, members); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// deleteTaskGroup (admin) removes a group; its tasks keep running with the
// group cleared (owner-only access again).
func (s *Server) deleteTaskGroup(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad group id")
		return
	}
	if err := pg.DeleteTaskGroup(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// Clear the group on any live task that pointed at it.
	for _, t := range s.m.List() {
		if g := t.groupID(); g != nil && *g == id {
			t.setGroupID(nil)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// setTaskGroup assigns or clears a task's group. taskGate has already confirmed
// the caller may access the task (its owner, or an admin). A non-admin may set
// the group only to one it is a member of, so it cannot leak a task into a group
// it does not belong to.
func (s *Server) setTaskGroup(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		GroupID *int64 `json:"group_id"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.GroupID != nil {
		if p, ok := identityFrom(r.Context()); ok && !p.admin() {
			member, err := pg.IsTaskGroupMember(*req.GroupID, p.username)
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			if !member {
				writeErr(w, 403, "you are not a member of that group")
				return
			}
		}
	}
	idNum, _ := strconv.ParseInt(t.ID, 10, 64)
	if err := pg.SetTaskGroup(idNum, req.GroupID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.setGroupID(req.GroupID)
	writeJSON(w, 200, map[string]any{"ok": true, "group_id": req.GroupID})
}
