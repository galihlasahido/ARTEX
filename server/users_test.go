package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Role-based access over the real mux: the admin gate (adminGate/adminPatterns),
// per-user session invalidation, and the user-management CRUD. The harness token
// (signJWT) is the bootstrap ARTEX admin; table accounts are minted with
// signJWTUser at the version Create assigns (1).

// doAs sends a request with an explicit bearer token (empty = none).
func (g *gateServer) doAs(t *testing.T, token, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	g.s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func userToken(t *testing.T, g *gateServer, username, role string, version int64) string {
	t.Helper()
	tok, err := signJWTUser(g.s.jwtKey, username, role, version)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// createTestUser makes a fresh account through the admin API and removes it when
// the test ends. Usernames are unique per run because the test database is
// shared and rows persist across runs.
func createTestUser(t *testing.T, g *gateServer, role string) (id int64, username string) {
	t.Helper()
	username = fmt.Sprintf("u%d", time.Now().UnixNano())
	code, body := g.do(t, "POST", "/api/users",
		fmt.Sprintf(`{"username":%q,"password":"Correct-horse-1","role":%q}`, username, role))
	if code != 201 {
		t.Fatalf("create %s: %d %v", username, code, body)
	}
	fid, _ := body["id"].(float64)
	id = int64(fid)
	if id == 0 {
		t.Fatalf("create %s returned no id: %v", username, body)
	}
	t.Cleanup(func() {
		_ = g.m.pg.Users().Delete(id)
		g.s.reloadUsers()
	})
	return id, username
}

func TestUserManagementRequiresAdmin(t *testing.T) {
	g := newGateServer(t)
	id, uname := createTestUser(t, g, roleUser)
	tok := userToken(t, g, uname, roleUser, 1)

	// A user sees their own identity but cannot touch user management.
	if code, body := g.doAs(t, tok, "GET", "/api/me", ""); code != 200 || body["role"] != roleUser || body["username"] != uname {
		t.Fatalf("GET /api/me as user: %d %v", code, body)
	}
	for _, c := range []struct {
		method, path, body string
	}{
		{"GET", "/api/users", ""},
		{"POST", "/api/users", `{"username":"zzz","password":"Correct-horse-1","role":"user"}`},
		{"PATCH", fmt.Sprintf("/api/users/%d", id), `{"role":"admin"}`},
		{"DELETE", fmt.Sprintf("/api/users/%d", id), ""},
	} {
		if code, _ := g.doAs(t, tok, c.method, c.path, c.body); code != 403 {
			t.Fatalf("%s %s as user = %d, want 403", c.method, c.path, code)
		}
	}
	// The admin can list and sees the account.
	code, _ := g.do(t, "GET", "/api/users", "")
	if code != 200 {
		t.Fatalf("admin GET /api/users = %d", code)
	}
}

func TestUserRoleGatesConfigNotOperator(t *testing.T) {
	g := newGateServer(t)
	_, uname := createTestUser(t, g, roleUser)
	tok := userToken(t, g, uname, roleUser, 1)

	// Admin-only config writes and logs are refused with 403 (never 401, which
	// would log the operator out).
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/settings", `{"auto_approve_default":true}`},
		{"GET", "/api/logs", ""},
		{"POST", "/api/intercept/rules", `{"pattern":"x"}`},
	} {
		if code, _ := g.doAs(t, tok, c.method, c.path, c.body); code != 403 {
			t.Fatalf("%s %s as user = %d, want 403", c.method, c.path, code)
		}
	}

	// A config read stays open to the operator.
	if code, _ := g.doAs(t, tok, "GET", "/api/settings", ""); code != 200 {
		t.Fatalf("GET /api/settings as user = %d, want 200", code)
	}

	// Operator work is allowed: creating a task, and reaching an approval
	// decision (a missing id errors, but never with 403).
	code, body := g.doAs(t, tok, "POST", "/api/tasks", `{"description":"user task","goal":"`+gateTestGoal+`"}`)
	if code != 201 {
		t.Fatalf("POST /api/tasks as user = %d %v, want 201", code, body)
	}
	if tid, _ := body["id"].(string); tid != "" {
		g.cleanupTask(t, tid)
	}
	if code, _ := g.doAs(t, tok, "POST", "/api/intercept/pending/999999/decide", `{"decision":"allowed"}`); code == 403 {
		t.Fatalf("approval decide as user = 403, want operator access (any non-403)")
	}
}

func TestDeactivateEndsLiveSession(t *testing.T) {
	g := newGateServer(t)
	id, uname := createTestUser(t, g, roleUser)
	tok := userToken(t, g, uname, roleUser, 1)

	if code, _ := g.doAs(t, tok, "GET", "/api/me", ""); code != 200 {
		t.Fatalf("live session before deactivate = %d, want 200", code)
	}
	if code, _ := g.do(t, "PATCH", fmt.Sprintf("/api/users/%d", id), `{"active":false}`); code != 200 {
		t.Fatalf("deactivate = %d, want 200", code)
	}
	if code, _ := g.doAs(t, tok, "GET", "/api/me", ""); code != 401 {
		t.Fatalf("session after deactivate = %d, want 401", code)
	}
}

func TestDemoteEndsLiveAdminSession(t *testing.T) {
	g := newGateServer(t)
	id, uname := createTestUser(t, g, roleAdmin)
	tok := userToken(t, g, uname, roleAdmin, 1)

	if code, _ := g.doAs(t, tok, "GET", "/api/users", ""); code != 200 {
		t.Fatalf("admin user listing = %d, want 200", code)
	}
	// Demote bumps pwd_version; the old admin token no longer validates.
	if code, _ := g.do(t, "PATCH", fmt.Sprintf("/api/users/%d", id), `{"role":"user"}`); code != 200 {
		t.Fatalf("demote = %d, want 200", code)
	}
	if code, _ := g.doAs(t, tok, "GET", "/api/me", ""); code != 401 {
		t.Fatalf("stale admin token after demote = %d, want 401", code)
	}
}

func TestCreateUserValidation(t *testing.T) {
	g := newGateServer(t)
	_, uname := createTestUser(t, g, roleUser)
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"reserved", `{"username":"ARTEX","password":"Correct-horse-1","role":"admin"}`, 400},
		{"short password", `{"username":"shortpw","password":"abc","role":"user"}`, 400},
		{"not complex", `{"username":"weakcx","password":"alllowercaseword","role":"user"}`, 400},
		{"bad role", `{"username":"badrole","password":"Correct-horse-1","role":"root"}`, 400},
		{"duplicate", fmt.Sprintf(`{"username":%q,"password":"Correct-horse-1","role":"user"}`, uname), 409},
	} {
		if code, body := g.do(t, "POST", "/api/users", c.body); code != c.want {
			t.Fatalf("%s: %d %v, want %d", c.name, code, body, c.want)
		}
	}
}

func TestChangeOwnPasswordInvalidatesOldToken(t *testing.T) {
	g := newGateServer(t)
	_, uname := createTestUser(t, g, roleUser)
	tok := userToken(t, g, uname, roleUser, 1)

	if code, _ := g.doAs(t, tok, "POST", "/api/auth/change-password",
		`{"old_password":"Correct-horse-1","new_password":"Correct-horse-2"}`); code != 200 {
		t.Fatalf("change own password = %d, want 200", code)
	}
	// The old session (version 1) is dead; version 2 token is valid.
	if code, _ := g.doAs(t, tok, "GET", "/api/me", ""); code != 401 {
		t.Fatalf("old token after password change = %d, want 401", code)
	}
	if code, _ := g.doAs(t, userToken(t, g, uname, roleUser, 2), "GET", "/api/me", ""); code != 200 {
		t.Fatalf("new-version token = %d, want 200", code)
	}
	// Login with the new password works; the old one does not.
	if code, body := g.doAs(t, "", "POST", "/api/auth/login",
		fmt.Sprintf(`{"username":%q,"password":"Correct-horse-2"}`, uname)); code != 200 || body["token"] == nil {
		t.Fatalf("login with new password = %d %v", code, body)
	}
}
