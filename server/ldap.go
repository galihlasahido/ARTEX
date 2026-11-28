package server

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/bcrypt"
)

// LDAP authentication by DIRECT BIND: no service/admin account and no search
// step. The user's DN is built from a configured pattern and bound with the
// password the user typed; a successful bind is a successful authentication.
// This is the "simple bind as the user" scheme, which needs no bind DN.
//
// On a successful LDAP login the user gets a local users-table record (created
// with an unusable random password, so only LDAP can authenticate it) at the
// configured default role, which makes RBAC, task ownership and session
// validation work for LDAP users exactly as for local accounts.

const (
	ldapEnabledKey     = "ldap.enabled"
	ldapURLKey         = "ldap.url"             // ldap://host:389 or ldaps://host:636
	ldapDNPatternKey   = "ldap.user_dn_pattern" // must contain %s, e.g. uid=%s,ou=people,dc=example,dc=com or %s@corp.example.com
	ldapStartTLSKey    = "ldap.start_tls"       // STartTLS over ldap://
	ldapInsecureKey    = "ldap.insecure_tls"    // skip TLS cert verification (dev only)
	ldapDefaultRoleKey = "ldap.default_role"    // role for a new LDAP user (user|admin), default user
)

type ldapConfig struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	DNPattern   string `json:"user_dn_pattern"`
	StartTLS    bool   `json:"start_tls"`
	Insecure    bool   `json:"insecure_tls"`
	DefaultRole string `json:"default_role"`
}

func (s *Server) ldapConfig() ldapConfig {
	get := func(k string) string {
		if s.m == nil || s.m.pg == nil {
			return ""
		}
		v, _, _ := s.m.pg.GetSetting(k)
		return v
	}
	role := get(ldapDefaultRoleKey)
	if role != roleAdmin {
		role = roleUser
	}
	return ldapConfig{
		Enabled:     get(ldapEnabledKey) == "true",
		URL:         strings.TrimSpace(get(ldapURLKey)),
		DNPattern:   strings.TrimSpace(get(ldapDNPatternKey)),
		StartTLS:    get(ldapStartTLSKey) == "true",
		Insecure:    get(ldapInsecureKey) == "true",
		DefaultRole: role,
	}
}

func (c ldapConfig) ready() bool {
	return c.Enabled && c.URL != "" && strings.Contains(c.DNPattern, "%s")
}

// ldapAuthenticate binds to the directory directly as the user.
func (s *Server) ldapAuthenticate(cfg ldapConfig, username, password string) bool {
	// A direct bind with an empty password is an anonymous/unauthenticated bind
	// that many servers accept — it must never count as a login.
	if !cfg.ready() || password == "" || username == "" {
		return false
	}
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return false
	}
	defer conn.Close()
	if cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.Insecure, ServerName: ldapHost(cfg.URL)}); err != nil { //nolint:gosec // Insecure is an explicit dev opt-in
			return false
		}
	}
	dn := fmt.Sprintf(cfg.DNPattern, ldap.EscapeDN(username))
	return conn.Bind(dn, password) == nil
}

// ldapHost extracts the hostname from an ldap(s):// URL for TLS verification.
func ldapHost(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Hostname()
	}
	return ""
}

// ensureLDAPUser returns the local record for an LDAP-authenticated user,
// creating it (with an unusable local password) at the default role if absent.
func (s *Server) ensureLDAPUser(username, defaultRole string) (db.User, error) {
	store := s.m.pg.Users()
	u, err := store.GetByName(username)
	if err == nil {
		return u, nil
	}
	if err != db.ErrUserNotFound {
		return db.User{}, err
	}
	secret := make([]byte, 32)
	if _, rerr := rand.Read(secret); rerr != nil {
		return db.User{}, rerr
	}
	hash, herr := bcrypt.GenerateFromPassword(secret, bcrypt.DefaultCost)
	if herr != nil {
		return db.User{}, herr
	}
	return store.Create(username, string(hash), defaultRole)
}
