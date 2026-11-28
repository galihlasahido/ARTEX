package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mobiletun"
	"github.com/gorilla/websocket"
)

func mobileTestServer(t *testing.T) (*Server, *httptest.Server, string) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, mobileNodeTokenKey) })
	t.Setenv("ARTEX_MOBILE_ADB_LISTEN", "127.0.0.1:0") // free port

	s := &Server{m: &Manager{pg: d}, jwtKey: []byte("mobile-node-test-key"), mobileNode: &mobileNodeHub{}}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	admin, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	return s, srv, admin
}

func mobileDo(t *testing.T, srv *httptest.Server, method, path, body, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer rec.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&out)
	return rec.StatusCode, out
}

func wsURL(srv *httptest.Server) string { return "ws" + strings.TrimPrefix(srv.URL, "http") }

func TestMobileNodeAuth(t *testing.T) {
	_, srv, admin := mobileTestServer(t)

	// No token configured: a node is refused (403); a user without admin can't
	// even read status would be a different gate — here status as admin shows it.
	if code, out := mobileDo(t, srv, "GET", "/api/mobile-node", "", admin); code != 200 || out["configured"] != false {
		t.Fatalf("status before token: %d %v", code, out)
	}
	_, _, err := websocket.DefaultDialer.Dial(wsURL(srv)+"/api/mobile-node/connect",
		http.Header{"Authorization": {"Bearer anything"}})
	if err == nil {
		t.Fatal("connect succeeded with no token configured")
	}

	// Generate a token (admin only).
	code, out := mobileDo(t, srv, "POST", "/api/mobile-node/token", "", admin)
	if code != 200 {
		t.Fatalf("gen token: %d %v", code, out)
	}
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatal("no token returned")
	}
	if code, _ := mobileDo(t, srv, "GET", "/api/mobile-node", "", admin); code != 200 {
		t.Fatal("status after token failed")
	}

	// Wrong token is rejected. (Admin-gating of the status/token routes is
	// covered by TestUserRoleGatesConfigNotOperator with a real user record.)
	if _, _, err := websocket.DefaultDialer.Dial(wsURL(srv)+"/api/mobile-node/connect",
		http.Header{"Authorization": {"Bearer wrong-" + token}}); err == nil {
		t.Fatal("connect succeeded with wrong token")
	}
}

func TestMobileNodeTunnel(t *testing.T) {
	_, srv, admin := mobileTestServer(t)

	code, out := mobileDo(t, srv, "POST", "/api/mobile-node/token", "", admin)
	if code != 200 {
		t.Fatalf("gen token: %d %v", code, out)
	}
	token := out["token"].(string)

	// Simulate the node: dial the connect WS and run an echo acceptor (stands in
	// for adbd reflecting bytes).
	ws, _, err := websocket.DefaultDialer.Dial(wsURL(srv)+"/api/mobile-node/connect",
		http.Header{"Authorization": {"Bearer " + token}})
	if err != nil {
		t.Fatalf("node connect: %v", err)
	}
	node := mobiletun.New(ws, false)
	defer node.Close()
	go func() {
		for {
			st, err := node.Accept()
			if err != nil {
				return
			}
			go func(st *mobiletun.Stream) { defer st.Close(); _, _ = io.Copy(st, st) }(st)
		}
	}()

	// Wait for the core to register the node and learn the adb listener addr.
	var adbAddr string
	for i := 0; i < 50; i++ {
		if code, out := mobileDo(t, srv, "GET", "/api/mobile-node", "", admin); code == 200 && out["connected"] == true {
			adbAddr, _ = out["adb_addr"].(string)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if adbAddr == "" || strings.HasSuffix(adbAddr, ":0") {
		t.Fatalf("node not connected or no adb addr: %q", adbAddr)
	}

	// An "adb" client connects to the loopback listener; bytes must round-trip
	// through the tunnel to the node echo and back.
	conn, err := net.Dial("tcp", adbAddr)
	if err != nil {
		t.Fatalf("dial adb listener: %v", err)
	}
	defer conn.Close()
	want := []byte("CNXN\x00\x00\x00\x01host::features=cmd")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("tunnel echo = %q, want %q", got, want)
	}
}
