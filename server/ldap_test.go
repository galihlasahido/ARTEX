package server

import (
	"testing"
)

func TestLDAPConfigReady(t *testing.T) {
	ok := ldapConfig{Enabled: true, URL: "ldap://h:389", DNPattern: "uid=%s,dc=x"}
	if !ok.ready() {
		t.Fatal("complete config not ready")
	}
	for _, c := range []ldapConfig{
		{Enabled: false, URL: "ldap://h", DNPattern: "uid=%s"}, // disabled
		{Enabled: true, URL: "", DNPattern: "uid=%s"},          // no url
		{Enabled: true, URL: "ldap://h", DNPattern: "uid=x"},   // pattern lacks %s
	} {
		if c.ready() {
			t.Fatalf("incomplete config reported ready: %+v", c)
		}
	}
}

func TestLDAPHost(t *testing.T) {
	for in, want := range map[string]string{
		"ldap://dir.example.com:389": "dir.example.com",
		"ldaps://10.0.0.5:636":       "10.0.0.5",
		"not a url":                  "",
	} {
		if got := ldapHost(in); got != want {
			t.Errorf("ldapHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLDAPAuthenticateGuards: an empty password (anonymous bind), an unready
// config, and an unreachable server must all fail closed.
func TestLDAPAuthenticateGuards(t *testing.T) {
	s := &Server{}
	ready := ldapConfig{Enabled: true, URL: "ldap://127.0.0.1:1", DNPattern: "uid=%s,dc=x"}
	if s.ldapAuthenticate(ready, "alice", "") {
		t.Fatal("empty password authenticated (anonymous bind leak)")
	}
	if s.ldapAuthenticate(ldapConfig{Enabled: false}, "alice", "pw") {
		t.Fatal("disabled config authenticated")
	}
	if s.ldapAuthenticate(ready, "alice", "pw") {
		t.Fatal("unreachable server authenticated")
	}
}

// TestLDAPConfigAPI: only an admin may read/write the LDAP config.
func TestLDAPConfigAPI(t *testing.T) {
	g := newGateServer(t)
	_, uname := createTestUser(t, g, roleUser)
	utok := userToken(t, g, uname, roleUser, 1)
	t.Cleanup(func() {
		for _, k := range []string{ldapEnabledKey, ldapURLKey, ldapDNPatternKey, ldapStartTLSKey, ldapInsecureKey, ldapDefaultRoleKey} {
			_, _ = g.m.pg.Exec(`DELETE FROM settings WHERE key=$1`, k)
		}
	})

	// A user may not read or write it.
	if code, _ := g.doAs(t, utok, "GET", "/api/ldap", ""); code != 403 {
		t.Fatalf("user GET /api/ldap = %d, want 403", code)
	}
	if code, _ := g.doAs(t, utok, "PUT", "/api/ldap", `{"enabled":true}`); code != 403 {
		t.Fatalf("user PUT /api/ldap = %d, want 403", code)
	}

	// Admin enables LDAP and reads it back.
	code, _ := g.do(t, "PUT", "/api/ldap",
		`{"enabled":true,"url":"ldap://dir:389","user_dn_pattern":"uid=%s,ou=people,dc=example,dc=com","default_role":"user"}`)
	if code != 200 {
		t.Fatalf("admin PUT /api/ldap = %d", code)
	}
	code, body := g.do(t, "GET", "/api/ldap", "")
	if code != 200 || body["enabled"] != true || body["url"] != "ldap://dir:389" {
		t.Fatalf("GET /api/ldap = %d %v", code, body)
	}

	// An enabled config with a bad pattern is rejected.
	if code, _ := g.do(t, "PUT", "/api/ldap", `{"enabled":true,"url":"ldap://dir","user_dn_pattern":"nopercent"}`); code != 400 {
		t.Fatalf("bad pattern accepted = %d, want 400", code)
	}
}
