package server

// daisy fork: relayTCP over a real QUIC stream (loopback, the server's end
// wrapped as handleTCPRequest wraps it) and a real TCP destination.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/utils"
)

const relayTestALPN = "relay-test"

func relayTestTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: relayTestALPN},
		DNSNames:     []string{relayTestALPN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	server = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{relayTestALPN}}
	// The client trusts exactly the certificate generated above.
	client = &tls.Config{RootCAs: roots, ServerName: relayTestALPN, NextProtos: []string{relayTestALPN}}
	return server, client
}

// relayRig is one proxied flow: the client's end of the QUIC stream, the
// server's end as the relay gets it, and a TCP connection to a destination.
type relayRig struct {
	client *quic.Stream
	server *utils.QStream
	remote net.Conn
	dest   *net.TCPConn
}

// newRelayRig opens the flow. The client's first bytes are "request" (a QUIC
// stream is announced to the peer by its first data).
func newRelayRig(t *testing.T, clientConf *quic.Config) *relayRig {
	t.Helper()
	serverTLS, clientTLS := relayTestTLS(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cconn, err := quic.DialAddr(ctx, ln.Addr().String(), clientTLS, clientConf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cconn.CloseWithError(0, "") })
	sconn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sconn.CloseWithError(0, "") })
	cs, err := cconn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	ss, err := sconn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	remote, err := net.Dial("tcp", tl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = remote.Close() })
	dest, err := tl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dest.Close() })
	return &relayRig{client: cs, server: &utils.QStream{Stream: ss}, remote: remote, dest: dest.(*net.TCPConn)}
}

func (r *relayRig) start() <-chan error {
	done := make(chan error, 1)
	go func() { done <- relayTCPFast(r.server, r.remote) }()
	return done
}

func waitRelay(t *testing.T, done <-chan error, why string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal(why)
		return nil
	}
}

func isConnReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var errno syscall.Errno
	return runtime.GOOS == "windows" && errors.As(err, &errno) && errno == 10054 // WSAECONNRESET
}

// destinationSeesReset reads until the destination's connection reports how
// it ended after any EOF it already read: an RST must arrive within 3 s.
func destinationSeesReset(t *testing.T, dest *net.TCPConn) {
	t.Helper()
	_ = dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, err := dest.Read(buf)
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			time.Sleep(10 * time.Millisecond)
		case isConnReset(err):
			return
		default:
			t.Fatalf("the destination must see a reset, got %v", err)
		}
	}
}

// The ordinary half-close: the client sends its request and FIN, the
// destination answers after reading that EOF, and the reply reaches the
// client whole.
func TestRelayTCPHalfCloseCarriesTheReply(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = r.dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(r.dest)
	if err != nil || string(got) != "request" {
		t.Fatalf("destination read %q, %v; want the request, then EOF", got, err)
	}
	if _, err := r.dest.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := r.dest.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = r.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := io.ReadAll(r.client)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("client read %q, %v; want the reply, then EOF", reply, err)
	}
	if err := waitRelay(t, done, "the relay must end after both directions ended"); err != nil {
		t.Fatalf("a clean relay returned %v", err)
	}
}

// A client that resets its stream mid-upload: the destination sees a reset,
// not an EOF that reads as a complete upload.
func TestRelayTCPClientResetResetsTheDestination(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	_ = r.dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len("request"))
	if _, err := io.ReadFull(r.dest, buf); err != nil {
		t.Fatal(err)
	}
	r.client.CancelWrite(7)
	r.client.CancelRead(7)
	waitRelay(t, done, "the relay must end on the client's reset")
	destinationSeesReset(t, r.dest)
}

// destinationReleased: the server has let go of the destination's
// connection, so the destination's writes start failing. (After a FIN the
// destination has already read, how the connection then ends is not
// visible to it on Windows: a later RST never surfaces on a read, and a
// write fails the same way after an abortive close as after a graceful
// one — measured 2026-09-24. The upload was complete by then; what matters
// is that the server does not hold the connection.)
func destinationReleased(t *testing.T, dest *net.TCPConn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := dest.Write([]byte("x")); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the destination's connection is still held open by the server")
}

// Codex round 1 on A4, P2: a client that half-closes (request + FIN) and
// then gives up while the destination is still silent. The client's reset
// reaches the server's write side as STOP_SENDING, and the download
// direction, parked in remote.Read, never writes to notice it: the relay
// must watch the stream's context, abort the destination and return,
// instead of holding the destination until it speaks.
func TestRelayTCPClientStopAfterItsFINReleasesTheDestination(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = r.dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(r.dest)
	if err != nil || string(got) != "request" {
		t.Fatalf("destination read %q, %v; want the request, then EOF", got, err)
	}
	// The destination says nothing; the client stops waiting for a reply.
	r.client.CancelRead(7)
	waitRelay(t, done, "the relay is still parked on a silent destination after the client stopped reading")
	destinationReleased(t, r.dest)
}

// noHalfClose hides CloseWrite: a remote connection on the fallback path.
type noHalfClose struct{ net.Conn }

// Codex round 1 on A4, P2: on the fallback path (no CloseWrite) the first
// clean end ends the relay, as upstream's copyTwoWay did. The other copy may
// be blocked in stream.Write by flow control, which neither remote.Close
// nor CancelRead releases, so the relay must not wait for it.
func TestRelayTCPFallbackReturnsWhileTheDownloadIsBlocked(t *testing.T) {
	// A client that never reads: its stream window stays small, and full.
	r := newRelayRig(t, &quic.Config{InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10})
	done := make(chan error, 1)
	go func() { done <- relayTCPFast(r.server, noHalfClose{r.remote}) }()
	go func() { _, _ = r.dest.Write(make([]byte, 4<<20)) }()
	// Let the download fill the window and block in stream.Write.
	time.Sleep(300 * time.Millisecond)
	// The client finishes its upload: the first direction ends cleanly.
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	waitRelay(t, done, "the fallback is waiting on a download blocked by flow control")
	// Release the blocked writer.
	r.client.CancelRead(0)
}
