// Package mobiletun carries many TCP streams (the adb byte streams) over one
// WebSocket connection, so ARTEX core and a remote mobile node can bridge adb
// without exposing adb on any network port.
//
// The node dials OUT to core (so no inbound port on the node, NAT-friendly) and
// becomes the ACCEPTOR; core is the DIALER. Core's loopback adb listener accepts
// a TCP connection, calls Dial to open a stream, and copies bytes both ways; the
// node's Accept hands back the matching stream, which it bridges to the local
// adbd. The transport is symmetric, so the same Session type serves both ends.
//
// Framing over the WS (binary messages): one frame is
//
//	[1 byte type][4 byte big-endian stream id][payload]
//
// type open(1): a new stream; data(2): payload bytes for a stream; close(3):
// the stream is done. gorilla/websocket allows only one concurrent writer, so a
// single writer goroutine drains a frame channel; the single reader goroutine
// demuxes to per-stream pipes. v1 has no window-based flow control — it relies
// on WS/TCP back-pressure, which is fine for adb's modest volumes.
package mobiletun

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type frameType byte

const (
	frameOpen  frameType = 1
	frameData  frameType = 2
	frameClose frameType = 3

	headerLen = 5
	// maxFramePayload bounds a single data frame; larger reads are split.
	maxFramePayload = 32 << 10
)

// ErrClosed is returned once the session is torn down.
var ErrClosed = errors.New("mobiletun: session closed")

// Session multiplexes streams over one WebSocket connection.
type Session struct {
	ws      *websocket.Conn
	dialer  bool // core = true (opens streams); node = false (accepts them)
	writeCh chan frame
	accept  chan *Stream

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	closed  bool
	done    chan struct{}
}

type frame struct {
	typ frameType
	id  uint32
	b   []byte
}

// New wraps a WebSocket connection. dialer=true for the core side.
func New(ws *websocket.Conn, dialer bool) *Session {
	s := &Session{
		ws:      ws,
		dialer:  dialer,
		writeCh: make(chan frame, 64),
		accept:  make(chan *Stream, 8),
		streams: map[uint32]*Stream{},
		done:    make(chan struct{}),
	}
	go s.writeLoop()
	go s.readLoop()
	return s
}

func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case f := <-s.writeCh:
			buf := make([]byte, headerLen+len(f.b))
			buf[0] = byte(f.typ)
			binary.BigEndian.PutUint32(buf[1:5], f.id)
			copy(buf[headerLen:], f.b)
			_ = s.ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := s.ws.WriteMessage(websocket.BinaryMessage, buf); err != nil {
				s.closeWith()
				return
			}
		}
	}
}

func (s *Session) readLoop() {
	defer s.closeWith()
	for {
		mt, data, err := s.ws.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage || len(data) < headerLen {
			continue
		}
		typ := frameType(data[0])
		id := binary.BigEndian.Uint32(data[1:5])
		payload := data[headerLen:]
		switch typ {
		case frameOpen:
			if s.dialer {
				continue // only the node accepts opens
			}
			st := s.newStream(id)
			if st == nil {
				continue
			}
			select {
			case s.accept <- st:
			case <-s.done:
				return
			}
		case frameData:
			if st := s.stream(id); st != nil {
				_, _ = st.in.Write(payload) // pipe; Read side drains it
			}
		case frameClose:
			if st := s.stream(id); st != nil {
				st.remoteClose()
			}
		}
	}
}

func (s *Session) stream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) newStream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.streams[id] != nil {
		return nil
	}
	pr, pw := io.Pipe()
	st := &Stream{sess: s, id: id, in: pw, out: pr}
	s.streams[id] = st
	return st
}

// Dial opens a new stream (core side). It errors on the node side or once closed.
func (s *Session) Dial() (*Stream, error) {
	if !s.dialer {
		return nil, errors.New("mobiletun: Dial on acceptor side")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	s.nextID++
	id := s.nextID
	pr, pw := io.Pipe()
	st := &Stream{sess: s, id: id, in: pw, out: pr}
	s.streams[id] = st
	s.mu.Unlock()
	if err := s.send(frame{typ: frameOpen, id: id}); err != nil {
		return nil, err
	}
	return st, nil
}

// Accept returns the next stream the peer opened (node side). It blocks until
// one arrives or the session closes.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.done:
		return nil, ErrClosed
	}
}

func (s *Session) send(f frame) error {
	select {
	case s.writeCh <- f:
		return nil
	case <-s.done:
		return ErrClosed
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) closeWith() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	streams := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	close(s.done)
	_ = s.ws.Close()
	for _, st := range streams {
		st.remoteClose()
	}
}

// Close tears the session down.
func (s *Session) Close() error {
	s.closeWith()
	return nil
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// Stream is one tunneled TCP connection. It is an io.ReadWriteCloser.
type Stream struct {
	sess      *Session
	id        uint32
	in        *io.PipeWriter // demux writes inbound bytes here
	out       *io.PipeReader // Read drains here
	closeOnce sync.Once
}

func (st *Stream) Read(p []byte) (int, error) { return st.out.Read(p) }

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxFramePayload {
			n = maxFramePayload
		}
		chunk := make([]byte, n)
		copy(chunk, p[:n])
		if err := st.sess.send(frame{typ: frameData, id: st.id, b: chunk}); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close ends the stream and tells the peer.
func (st *Stream) Close() error {
	st.closeOnce.Do(func() {
		_ = st.sess.send(frame{typ: frameClose, id: st.id})
		_ = st.in.Close()
		_ = st.out.Close()
		st.sess.removeStream(st.id)
	})
	return nil
}

// remoteClose handles a close initiated by the peer or the transport.
func (st *Stream) remoteClose() {
	st.closeOnce.Do(func() {
		_ = st.in.Close()
		_ = st.out.Close()
		st.sess.removeStream(st.id)
	})
}
