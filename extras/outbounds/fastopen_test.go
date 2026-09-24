package outbounds

import (
	"errors"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// daisy fork: fastOpenConn must half-close and abort like the *net.TCPConn
// it wraps, or the server's TCP relay (core/server/relay_tcp.go) falls back
// to closing gracefully for a fastOpen server.

type fastOpenPeer struct {
	conn net.Conn
	err  error
}

func fastOpenPair(t *testing.T) (*fastOpenConn, <-chan fastOpenPeer) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan fastOpenPeer, 1)
	go func() {
		c, err := l.Accept()
		accepted <- fastOpenPeer{c, err}
	}()
	d := newFastOpenDialer(&net.Dialer{Timeout: 5 * time.Second})
	// Where TFO is unavailable (Windows builds without it) tfo-go dials a
	// plain connection instead; either way the dialed conn is a
	// *net.TCPConn, which is what fastOpenConn's methods delegate to.
	d.dialer.Fallback = true
	c, err := d.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c.(*fastOpenConn), accepted
}

func acceptPeer(t *testing.T, accepted <-chan fastOpenPeer) net.Conn {
	t.Helper()
	select {
	case p := <-accepted:
		if p.err != nil {
			t.Fatal(p.err)
		}
		t.Cleanup(func() { _ = p.conn.Close() })
		_ = p.conn.SetDeadline(time.Now().Add(5 * time.Second))
		return p.conn
	case <-time.After(5 * time.Second):
		t.Fatal("the destination never saw a connection")
		return nil
	}
}

// A client that sends its request and half-closes still gets the reply.
func TestFastOpenConnCloseWriteKeepsTheReply(t *testing.T) {
	c, accepted := fastOpenPair(t)
	defer c.Close()
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	peer := acceptPeer(t, accepted)
	got, err := io.ReadAll(peer)
	if err != nil || string(got) != "request" {
		t.Fatalf("destination read %q, %v; want the request and EOF", got, err)
	}
	if _, err := peer.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("client read %q, %v; want the reply after its half-close", reply, err)
	}
}

// Nothing is dialed before the first Write: a half-close before any data
// dials first, so the destination sees a connection and then a FIN.
func TestFastOpenConnCloseWriteBeforeAnyWriteDials(t *testing.T) {
	c, accepted := fastOpenPair(t)
	defer c.Close()
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	peer := acceptPeer(t, accepted)
	got, err := io.ReadAll(peer)
	if err != nil || len(got) != 0 {
		t.Fatalf("destination read %q, %v; want an immediate EOF", got, err)
	}
	if _, err := peer.Write([]byte("banner")); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "banner" {
		t.Fatalf("client read %q, %v; want what the destination sent", reply, err)
	}
}

// SetLinger(0) then Close reaches the destination as a reset, not a FIN.
func TestFastOpenConnSetLingerZeroResets(t *testing.T) {
	c, accepted := fastOpenPair(t)
	if _, err := c.Write([]byte("part of an upload")); err != nil {
		t.Fatal(err)
	}
	peer := acceptPeer(t, accepted)
	buf := make([]byte, len("part of an upload"))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	if err := c.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, err := peer.Read(buf)
	if !isConnReset(err) {
		t.Fatalf("destination read error %v; want a connection reset", err)
	}
}

func isConnReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var errno syscall.Errno
	return runtime.GOOS == "windows" && errors.As(err, &errno) && errno == 10054 // WSAECONNRESET
}

// Before the first Write there is nothing to reset.
func TestFastOpenConnSetLingerBeforeAnyWrite(t *testing.T) {
	c, _ := fastOpenPair(t)
	if err := c.SetLinger(0); err != nil {
		t.Fatalf("SetLinger before any write: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// Codex round 3 on A4: a SetLinger(0) before the first Write is kept and
// applied to the connection that Write dials, so an abort that races the
// first dial still closes with a reset, not a FIN.
func TestFastOpenConnSetLingerBeforeTheDialIsKept(t *testing.T) {
	c, accepted := fastOpenPair(t)
	if err := c.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("part of an upload")); err != nil {
		t.Fatal(err)
	}
	peer := acceptPeer(t, accepted)
	buf := make([]byte, len("part of an upload"))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, err := peer.Read(buf)
	if !isConnReset(err) {
		t.Fatalf("destination read error %v; want a connection reset", err)
	}
}
