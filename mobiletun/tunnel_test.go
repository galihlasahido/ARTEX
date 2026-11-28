package mobiletun

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// nodeEcho stands in for the node: accept each stream and echo bytes back,
// like an adbd that reflects what it receives.
func nodeEcho(t *testing.T, sess *Session) {
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go func(st *Stream) {
			defer st.Close()
			_, _ = io.Copy(st, st) // echo
		}(st)
	}
}

// dialPair starts an httptest WS server whose handler builds an acceptor session
// running nodeEcho, and returns a dialer session connected to it.
func dialPair(t *testing.T) (*Session, *httptest.Server) {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		node := New(ws, false)
		nodeEcho(t, node)
	}))
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial: %v", err)
	}
	return New(ws, true), srv
}

func TestTunnelRoundTrip(t *testing.T) {
	core, srv := dialPair(t)
	defer srv.Close()
	defer core.Close()

	st, err := core.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	want := []byte("CNXN adb payload \x00\x01\x02 end")
	if _, err := st.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}
}

func TestTunnelConcurrentStreams(t *testing.T) {
	core, srv := dialPair(t)
	defer srv.Close()
	defer core.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := core.Dial()
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer st.Close()
			payload := make([]byte, 4096)
			_, _ = rand.Read(payload)
			if _, err := st.Write(payload); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(st, got); err != nil {
				t.Errorf("read %d: %v", i, err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("stream %d echo mismatch", i)
			}
		}(i)
	}
	wg.Wait()
}

func TestTunnelLargeTransfer(t *testing.T) {
	core, srv := dialPair(t)
	defer srv.Close()
	defer core.Close()

	st, err := core.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	payload := make([]byte, 256<<10) // 256 KiB, exceeds maxFramePayload (splits)
	_, _ = rand.Read(payload)
	done := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(st, got); err != nil {
			t.Errorf("read: %v", err)
			done <- nil
			return
		}
		done <- got
	}()
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if !bytes.Equal(got, payload) {
			t.Fatal("large transfer mismatch")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for echo")
	}
}

func TestTunnelCloseWakesReaders(t *testing.T) {
	core, srv := dialPair(t)
	defer srv.Close()

	st, err := core.Dial()
	if err != nil {
		t.Fatal(err)
	}
	// Closing the session must unblock a pending Read with an error.
	errc := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 16))
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	core.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Read returned nil error after session close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not unblock after session close")
	}
}
