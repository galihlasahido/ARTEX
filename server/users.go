package server

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/Autumn-27/artex/db"
)

// validateComplexPassword extends validatePassword (length bounds) with a
// complexity rule for user accounts, applied when a password is set on create,
// on an admin reset, or when a user changes their own: at least one lowercase
// letter, one uppercase letter, one digit, and one symbol. Returns "" when ok,
// otherwise a reason to show.
func validateComplexPassword(pw string) string {
	if msg := validatePassword(pw); msg != "" {
		return msg
	}
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	if !lower || !upper || !digit || !symbol {
		return "Password must include an uppercase letter, a lowercase letter, a digit, and a symbol"
	}
	return ""
}

// Roles and the bootstrap admin. "ARTEX" is the permanent super-admin whose
// password lives in settings (see auth.go); every other account is a row in the
// users table and carries role 'admin' or 'user'. 'user' reaches the operator
// pages (tasks, chat, findings, traffic, approvals…); 'admin' additionally
// reaches the System configuration pages and user management.
const (
	roleAdmin      = "admin"
	roleUser       = "user"
	bootstrapAdmin = "ARTEX"
)

// principal is who a validated request is acting as. role is taken from the
// server-side record (the users table, or admin for the bootstrap), never from
// the token, so a tampered role claim cannot escalate privilege.
type principal struct {
	username string
	role     string
}

func (i principal) admin() bool { return i.role == roleAdmin }

type ctxKeyID struct{}

func withIdentity(ctx context.Context, id principal) context.Context {
	return context.WithValue(ctx, ctxKeyID{}, id)
}

// identityFrom returns the principal requireAuth put on the request context.
func identityFrom(ctx context.Context) (principal, bool) {
	id, ok := ctx.Value(ctxKeyID{}).(principal)
	return id, ok
}

// userRec is the cached shape of one users-table row for per-request session
// validation without a database hit.
type userRec struct {
	id         int64
	role       string
	active     bool
	pwdVersion int64
}

// reloadUsers refreshes the in-memory mirror of the users table. Called at
// startup and after every user mutation.
func (s *Server) reloadUsers() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	list, err := s.m.pg.Users().List()
	if err != nil {
		log.Printf("[auth] reload users: %v", err)
		return
	}
	m := make(map[string]userRec, len(list))
	for _, u := range list {
		m[strings.ToLower(u.Username)] = userRec{id: u.ID, role: u.Role, active: u.Active, pwdVersion: u.PwdVersion}
	}
	s.userMu.Lock()
	s.userCache = m
	s.userMu.Unlock()
}

func (s *Server) lookupUser(name string) (userRec, bool) {
	s.userMu.RLock()
	defer s.userMu.RUnlock()
	r, ok := s.userCache[strings.ToLower(name)]
	return r, ok
}

// adminGate wraps the API mux. It asks the mux itself which pattern matches the
// request (one parser, after routing), and for a pattern in adminPatterns it
// requires the caller to be an admin. requireAuth runs first and puts the
// principal on the context; a non-admin gets 403 (never 401, which would log the
// operator out). Patterns not in the set fall through to the operator role.
func (s *Server) adminGate(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); adminPatterns[pattern] {
			id, ok := identityFrom(r.Context())
			if !ok || !id.admin() {
				writeErr(w, 403, "administrator access required")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// adminPatterns are the exact mux patterns that only an admin may call: user
// management, the server logs, and every state-changing route behind a System
// configuration page. Config *reads* (GET) stay open because operator pages
// (task-create dialog, chat) read LLM profiles, agents and settings, and those
// responses carry no secrets. Approval decisions and per-task intercept rules
// stay open: those are operator work. Keep this list in sync with the routes in
// server.go — a pattern string must match a mux.HandleFunc registration exactly.
var adminPatterns = map[string]bool{
	// User management (admin-only page).
	"GET /api/users":         true,
	"POST /api/users":        true,
	"PATCH /api/users/{id}":  true,
	"DELETE /api/users/{id}": true,
	// Server logs (System > Logs).
	"GET /api/logs":         true,
	"GET /api/logs/history": true,
	"GET /api/logs/stream":  true,
	// System Settings writes.
	"PUT /api/settings":                  true,
	"POST /api/settings/python/detect":   true,
	"POST /api/settings/web-search/test": true,
	// Chat bot (System > Chat bot): saving the bot token/allowlist and testing
	// the connection. GET /api/chat-bridges is a config read and stays open.
	"PUT /api/chat-bridges/{kind}":       true,
	"POST /api/chat-bridges/{kind}/test": true,
	// Mobile node: status read and node-token generation are admin-only. The
	// node's own WebSocket dial-in (GET /api/mobile-node/connect) authenticates
	// with the node token and is intentionally absent here.
	"GET /api/mobile-node":        true,
	"POST /api/mobile-node/token": true,
	// Task groups: creating groups and setting membership is admin-only. The
	// list read (GET /api/task-groups) and placing a task in a group
	// (PUT /api/tasks/{id}/group) are operator work and intentionally absent.
	"POST /api/task-groups":             true,
	"PUT /api/task-groups/{id}/members": true,
	"DELETE /api/task-groups/{id}":      true,
	// LLM provider configuration (System > LLM). /api/llm/records* is the operator
	// "LLM Recording" page and is intentionally absent.
	"POST /api/llm":                 true,
	"POST /api/llm/models":          true,
	"POST /api/llm/pool/reset":      true,
	"POST /api/llm/profiles":        true,
	"DELETE /api/llm/profiles/{id}": true,
	"POST /api/llm/profiles/active": true,
	"POST /api/llm/retry-policy":    true,
	"POST /api/llm/test":            true,
	// Agents (System > Agent) and their triggers.
	"POST /api/agents":                                 true,
	"DELETE /api/agents/{key}":                         true,
	"PATCH /api/agents/{key}":                          true,
	"PUT /api/agents/{key}/config":                     true,
	"PUT /api/agents/{key}/prompt":                     true,
	"POST /api/agents/{key}/prompt/preview":            true,
	"POST /api/agents/{key}/prompt/reset":              true,
	"POST /api/agents/{key}/triggers":                  true,
	"PATCH /api/triggers/{id}":                         true,
	"DELETE /api/triggers/{id}":                        true,
	"PUT /api/agents/{key}/visibility":                 true,
	"PUT /api/agents/{key}/wrapup":                     true,
	"PUT /api/agents/{key}/wrapup/task-timeout":        true,
	"POST /api/agents/{key}/wrapup/reset":              true,
	"POST /api/agents/{key}/wrapup/task-timeout/reset": true,
	"POST /api/visibility/toggle":                      true,
	"POST /api/visibility/skill/toggle":                true,
	// MCP (System > MCP).
	"POST /api/mcp":              true,
	"DELETE /api/mcp/{id}":       true,
	"POST /api/mcp/{id}/refresh": true,
	// Skills (System > Skill).
	"POST /api/skills":                          true,
	"DELETE /api/skills/{name}":                 true,
	"DELETE /api/skills/{name}/files/{file...}": true,
	"POST /api/skills/{name}/dirs":              true,
	"POST /api/skills/upload":                   true,
	"PUT /api/skills/{name}/files/{file...}":    true,
	"PUT /api/skills/{name}/meta":               true,
	// Tools (System > Tools).
	"POST /api/tools/{key}/reset":    true,
	"POST /api/tools/custom":         true,
	"POST /api/tools/custom/test":    true,
	"DELETE /api/tools/custom/{key}": true,
	"PUT /api/tools/{key}":           true,
	"PUT /api/tools/custom/{key}":    true,
	// Notifications (System > Notifications).
	"POST /api/notify/channels":              true,
	"PATCH /api/notify/channels/{id}":        true,
	"DELETE /api/notify/channels/{id}":       true,
	"POST /api/notify/channels/{id}/test":    true,
	"POST /api/notify/deliveries/{id}/retry": true,
	// Global interception rules & judge (System > Interception Rules). The
	// approval queue (/api/intercept/pending*) is operator work and stays open.
	"POST /api/intercept/rules":             true,
	"DELETE /api/intercept/rules/{id}":      true,
	"POST /api/intercept/rules/{id}/toggle": true,
	"PUT /api/intercept/rules/{id}":         true,
	"PUT /api/intercept/judge":              true,
	"PUT /api/intercept/tool-config":        true,
	"PUT /api/target-gate/exemptions":       true,
	// Asset interception (System > Asset Interception).
	"POST /api/asset-intercept/rules":             true,
	"PUT /api/asset-intercept/rules/{id}":         true,
	"DELETE /api/asset-intercept/rules/{id}":      true,
	"POST /api/asset-intercept/rules/{id}/toggle": true,
}

// userDTO is the client-facing shape of an account; the password hash is never
// included.
type userDTO struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Active    bool   `json:"active"`
	CreatedAt int64  `json:"created_at"`
}

func toUserDTO(u db.User) userDTO {
	return userDTO{ID: u.ID, Username: u.Username, Role: u.Role, Active: u.Active, CreatedAt: u.CreatedAt.Unix()}
}

// GET /api/me — the current session's own principal (any authenticated caller).
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFrom(r.Context())
	if !ok {
		writeErr(w, 401, "Unauthorized")
		return
	}
	writeJSON(w, 200, map[string]any{"username": id.username, "role": id.role})
}

// GET /api/users — list additional accounts (admin). The bootstrap ARTEX admin
// is not a row here; it is shown by the frontend as a fixed entry.
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	list, err := pg.Users().List()
	if err != nil {
		writeErr(w, 500, "list users: "+err.Error())
		return
	}
	out := make([]userDTO, 0, len(list))
	for _, u := range list {
		out = append(out, toUserDTO(u))
	}
	writeJSON(w, 200, out)
}

// POST /api/users — create an account (admin).
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if msg := validateUsername(req.Username); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = roleUser
	}
	if role != roleAdmin && role != roleUser {
		writeErr(w, 400, "Role must be 'admin' or 'user'")
		return
	}
	if msg := validateComplexPassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	u, err := pg.Users().Create(strings.TrimSpace(req.Username), string(hash), role)
	if err == db.ErrUserExists {
		writeErr(w, 409, "That username already exists")
		return
	}
	if err != nil {
		writeErr(w, 500, "create user: "+err.Error())
		return
	}
	s.reloadUsers()
	writeJSON(w, 201, toUserDTO(u))
}

// PATCH /api/users/{id} — change role, activate/deactivate, or reset the
// password of an account (admin). Any combination of the three fields.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "Invalid user id")
		return
	}
	var req struct {
		Role     *string `json:"role"`
		Active   *bool   `json:"active"`
		Password *string `json:"password"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if req.Role == nil && req.Active == nil && req.Password == nil {
		writeErr(w, 400, "Nothing to update")
		return
	}
	us := pg.Users()
	if req.Role != nil {
		role := strings.TrimSpace(*req.Role)
		if role != roleAdmin && role != roleUser {
			writeErr(w, 400, "Role must be 'admin' or 'user'")
			return
		}
		if err := us.SetRole(id, role); err != nil {
			s.userMutationError(w, err)
			return
		}
	}
	if req.Password != nil {
		if msg := validateComplexPassword(*req.Password); msg != "" {
			writeErr(w, 400, msg)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeErr(w, 500, "Password encryption failed")
			return
		}
		if _, err := us.SetPassword(id, string(hash)); err != nil {
			s.userMutationError(w, err)
			return
		}
	}
	if req.Active != nil {
		if err := us.SetActive(id, *req.Active); err != nil {
			s.userMutationError(w, err)
			return
		}
	}
	s.reloadUsers()
	u, err := us.GetByID(id)
	if err != nil {
		writeErr(w, 500, "reload user: "+err.Error())
		return
	}
	writeJSON(w, 200, toUserDTO(u))
}

// DELETE /api/users/{id} — remove an account (admin). The bootstrap ARTEX admin
// has no row here and so cannot be removed, and there is always at least one
// admin (ARTEX), so no last-admin guard is needed.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "Invalid user id")
		return
	}
	if err := pg.Users().Delete(id); err != nil {
		s.userMutationError(w, err)
		return
	}
	s.reloadUsers()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) userMutationError(w http.ResponseWriter, err error) {
	if err == db.ErrUserNotFound {
		writeErr(w, 404, "User not found")
		return
	}
	writeErr(w, 500, err.Error())
}

// validateUsername returns "" when ok, otherwise a reason to show. The
// bootstrap name is reserved.
func validateUsername(u string) string {
	u = strings.TrimSpace(u)
	if len(u) < 3 || len(u) > 32 {
		return "Username must be 3–32 characters"
	}
	if strings.EqualFold(u, bootstrapAdmin) {
		return "That username is reserved"
	}
	for _, r := range u {
		ok := r == '_' || r == '-' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return "Username may contain only letters, digits, and _-."
		}
	}
	return ""
}
