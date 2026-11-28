package server

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/mobiletun"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// The mobile node is a separate host (a rooted Android emulator) that dials IN
// to ARTEX core over a WebSocket and authenticates with a pre-shared node token
// (see docs/mobile-apk-pentest.md). Core then exposes the node's adbd at a
// LOOPBACK address so the agent's `adb connect` reaches the emulator through the
// tunnel — adb is never bound to a public interface on either side.
//
// Only one node is active at a time (v1): a new connection replaces the old.

const (
	// mobileNodeTokenKey stores a bcrypt hash of the node token in settings.
	// The raw token is shown once at generation and never persisted, like the
	// ARTEX admin password.
	mobileNodeTokenKey      = "mobile_node.token_hash"
	mobileNodeDefaultListen = "127.0.0.1:15555"
)

var mobileNodeUpgrader = websocket.Upgrader{
	ReadBufferSize:  32 << 10,
	WriteBufferSize: 32 << 10,
}

type mobileNodeHub struct {
	mu          sync.Mutex
	sess        *mobiletun.Session
	ln          net.Listener
	connectedAt time.Time
	remote      string
}

// mobileNodeListen is the loopback address core exposes the tunneled adbd on.
// It must be a loopback host so raw adb is never reachable off the box.
func mobileNodeListen() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_MOBILE_ADB_LISTEN")); v != "" {
		return v
	}
	return mobileNodeDefaultListen
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// mobileNodeConnect is the node's WebSocket entry point. It authenticates the
// node token (not a user JWT; requireAuth exempts this path), then runs the adb
// tunnel until the node disconnects.
func (s *Server) mobileNodeConnect(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, ok, err := pg.GetSetting(mobileNodeTokenKey)
	if err != nil {
		writeErr(w, 500, "settings read failed")
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "no mobile-node token is set; generate one in ARTEX first")
		return
	}
	tok := extractToken(r)
	if tok == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(tok)) != nil {
		writeErr(w, 401, "invalid mobile-node token")
		return
	}

	addr := mobileNodeListen()
	if !isLoopbackAddr(addr) {
		writeErr(w, 500, "mobile node adb listener must bind a loopback address")
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		writeErr(w, 500, "cannot open adb listener: "+err.Error())
		return
	}

	ws, err := mobileNodeUpgrader.Upgrade(w, r, nil)
	if err != nil {
		_ = ln.Close()
		return // Upgrade already wrote the error
	}
	sess := mobiletun.New(ws, true) // core dials streams
	s.mobileNode.set(sess, ln, clientIP(r, s.trustedProxies))
	log.Printf("[mobile-node] connected from %s; adb exposed at %s", clientIP(r, s.trustedProxies), addr)

	go s.mobileAcceptLoop(ln, sess)
	<-sess.Done()
	_ = ln.Close()
	s.mobileNode.clear(sess)
	log.Printf("[mobile-node] disconnected; adb listener on %s closed", addr)
}

// mobileAcceptLoop bridges each local adb TCP connection to a tunnel stream.
func (s *Server) mobileAcceptLoop(ln net.Listener, sess *mobiletun.Session) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		st, err := sess.Dial()
		if err != nil {
			_ = conn.Close()
			return
		}
		go pipeConnStream(conn, st)
	}
}

// pipeConnStream copies bytes both ways and closes both when either side ends.
func pipeConnStream(conn net.Conn, st *mobiletun.Stream) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(st, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, st); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	_ = st.Close()
}

func (h *mobileNodeHub) set(sess *mobiletun.Session, ln net.Listener, remote string) {
	h.mu.Lock()
	old, oldLn := h.sess, h.ln
	h.sess, h.ln, h.connectedAt, h.remote = sess, ln, time.Now(), remote
	h.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if oldLn != nil {
		_ = oldLn.Close()
	}
}

func (h *mobileNodeHub) clear(sess *mobiletun.Session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sess == sess {
		h.sess, h.ln, h.remote = nil, nil, ""
	}
}

func (h *mobileNodeHub) status() (connected bool, remote, addr string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ln != nil {
		addr = h.ln.Addr().String()
	}
	return h.sess != nil, h.remote, addr, h.connectedAt
}

// mobileNodeStatus (admin): whether a token is set and a node is connected.
func (s *Server) mobileNodeStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, ok, _ := pg.GetSetting(mobileNodeTokenKey)
	connected, remote, addr, at := s.mobileNode.status()
	if addr == "" {
		addr = mobileNodeListen()
	}
	out := map[string]any{
		"configured": ok && hash != "",
		"connected":  connected,
		"adb_addr":   addr,
	}
	if connected {
		out["remote"] = remote
		out["connected_at"] = at
	}
	writeJSON(w, 200, out)
}

// mobileNodeGenToken (admin) issues a new node token, stores only its hash, and
// returns the raw token once. Rotating it invalidates the old one.
func (s *Server) mobileNodeGenToken(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "token hashing failed")
		return
	}
	if err := pg.SetSetting(mobileNodeTokenKey, string(hash)); err != nil {
		writeErr(w, 500, "settings write failed")
		return
	}
	// A new token orphans any live node (its old token no longer matches).
	s.mobileNode.set(nil, nil, "")
	writeJSON(w, 200, map[string]any{
		"token": token,
		"note":  "shown once — store it in the mobile node's config now. Rotating replaces it.",
	})
}
