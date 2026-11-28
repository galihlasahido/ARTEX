package server

import (
	"net/http"
	"strconv"
	"strings"
)

// Admin LDAP configuration. Direct-bind LDAP has no secret (no bind DN or
// password), so the whole config is read and written in the clear.

func (s *Server) getLDAPConfig(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	writeJSON(w, 200, s.ldapConfig())
}

func (s *Server) putLDAPConfig(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req ldapConfig
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	req.DNPattern = strings.TrimSpace(req.DNPattern)
	if req.Enabled {
		if !strings.HasPrefix(req.URL, "ldap://") && !strings.HasPrefix(req.URL, "ldaps://") {
			writeErr(w, 400, "url must start with ldap:// or ldaps://")
			return
		}
		if !strings.Contains(req.DNPattern, "%s") {
			writeErr(w, 400, "user_dn_pattern must contain %s where the username goes (e.g. uid=%s,ou=people,dc=example,dc=com)")
			return
		}
	}
	role := roleUser
	if req.DefaultRole == roleAdmin {
		role = roleAdmin
	}
	set := func(k, v string) error { return pg.SetSetting(k, v) }
	for _, kv := range []struct{ k, v string }{
		{ldapEnabledKey, strconv.FormatBool(req.Enabled)},
		{ldapURLKey, req.URL},
		{ldapDNPatternKey, req.DNPattern},
		{ldapStartTLSKey, strconv.FormatBool(req.StartTLS)},
		{ldapInsecureKey, strconv.FormatBool(req.Insecure)},
		{ldapDefaultRoleKey, role},
	} {
		if err := set(kv.k, kv.v); err != nil {
			writeErr(w, 500, "settings write failed")
			return
		}
	}
	writeJSON(w, 200, s.ldapConfig())
}
