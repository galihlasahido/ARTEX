// Command mobile-node-agent runs on a mobile node (a host with a rooted Android
// emulator) and bridges the emulator's local adbd to ARTEX core over an
// outbound WebSocket. It dials OUT to core — nothing listens on the node, so it
// works behind NAT and needs no inbound firewall rule or SSH login to core.
//
// Each stream core opens on the tunnel is bridged to the local adbd
// (127.0.0.1:5555 by default), so core's `adb connect` reaches this emulator.
// The agent reconnects with backoff if the link drops.
//
// Config (flags or env):
//
//	-url   ARTEX_CORE_WS    wss://<core-host>/api/mobile-node/connect   (required)
//	-token ARTEX_NODE_TOKEN the node token issued in ARTEX                (required)
//	-adbd  ARTEX_ADBD       local adbd address      (default 127.0.0.1:5555)
//	-insecure ARTEX_NODE_INSECURE  skip TLS verify (self-signed dev only)
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/mobiletun"
	"github.com/gorilla/websocket"
)

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	url := flag.String("url", env("ARTEX_CORE_WS", ""), "core WebSocket URL (wss://host/api/mobile-node/connect)")
	token := flag.String("token", env("ARTEX_NODE_TOKEN", ""), "mobile-node token issued in ARTEX")
	adbd := flag.String("adbd", env("ARTEX_ADBD", "127.0.0.1:5555"), "local adbd address")
	insecure := flag.Bool("insecure", env("ARTEX_NODE_INSECURE", "") != "", "skip TLS verification (self-signed dev only)")
	flag.Parse()

	if *url == "" || *token == "" {
		log.Fatal("mobile-node-agent: -url and -token are required (or ARTEX_CORE_WS / ARTEX_NODE_TOKEN)")
	}
	if *insecure {
		log.Print("mobile-node-agent: TLS verification DISABLED (dev only)")
	}

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 20 * time.Second
	if *insecure {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in dev flag
	}
	hdr := http.Header{"Authorization": {"Bearer " + *token}}

	backoff := time.Second
	for {
		if err := connectOnce(dialer, *url, hdr, *adbd); err != nil {
			log.Printf("mobile-node-agent: link down: %v; retrying in %s", err, backoff)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

// connectOnce holds one WebSocket link until it drops, bridging every stream.
func connectOnce(dialer websocket.Dialer, url string, hdr http.Header, adbd string) error {
	ws, _, err := dialer.Dial(url, hdr)
	if err != nil {
		return err
	}
	log.Printf("mobile-node-agent: connected to %s; bridging adbd %s", url, adbd)
	sess := mobiletun.New(ws, false) // node accepts the streams core opens
	defer sess.Close()
	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		go bridgeToADBD(st, adbd)
	}
}

// bridgeToADBD connects a tunnel stream to the local adbd and copies both ways.
func bridgeToADBD(st *mobiletun.Stream, adbd string) {
	conn, err := net.DialTimeout("tcp", adbd, 10*time.Second)
	if err != nil {
		log.Printf("mobile-node-agent: dial adbd %s: %v", adbd, err)
		_ = st.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, st); done <- struct{}{} }()
	go func() { _, _ = io.Copy(st, conn); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	_ = st.Close()
}
