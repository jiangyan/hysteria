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

// destinationSeesReset reads until the destination's connection ends: it must
// end in a reset within 3 s. An EOF first fails it: a FIN, then a reset, is
// the defect itself (the transfer read as complete).
func destinationSeesReset(t *testing.T, dest *net.TCPConn) {
	t.Helper()
	_ = dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, err := dest.Read(buf)
		switch {
		case err == nil:
		case isConnReset(err):
			return
		default:
			t.Fatalf("the destination must see a reset (and no EOF first), got %v", err)
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

// officialClientClose closes the client's end the way the official hysteria
// client does on EVERY end of its side, clean or not (QStream.Close):
// STOP_SENDING with code 0, then FIN.
func officialClientClose(t *testing.T, s *quic.Stream) {
	t.Helper()
	s.CancelRead(0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// The official client's ordinary close is not an abort (the independent
// review of A4): the destination gets the whole upload and its EOF, and the
// relay ends without an error (no WARN "TCP error" per flow).
func TestRelayTCPOfficialClientCloseIsAnOrdinaryClose(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	upload := make([]byte, 64<<10)
	if _, err := r.client.Write(upload); err != nil {
		t.Fatal(err)
	}
	officialClientClose(t, r.client)
	_ = r.dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(r.dest)
	if err != nil || len(got) != len("request")+len(upload) {
		t.Fatalf("destination read %d bytes, %v; want %d, then EOF", len(got), err, len("request")+len(upload))
	}
	if err := waitRelay(t, done, "the relay must end on the client's close"); err != nil {
		t.Fatalf("an ordinary close ended the relay with %v", err)
	}
}

// The same close while the destination is still sending, so the copy
// toward the client fails on the STOP_SENDING before the upload has been
// read to its end: the relay must still let the upload finish.
func TestRelayTCPOfficialClientCloseDuringADownloadKeepsTheUpload(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		chunk := make([]byte, 16<<10)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := r.dest.Write(chunk); err != nil {
				return
			}
		}
	}()
	upload := make([]byte, 256<<10)
	if _, err := r.client.Write(upload); err != nil {
		t.Fatal(err)
	}
	officialClientClose(t, r.client)
	_ = r.dest.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(r.dest)
	if err != nil || len(got) != len("request")+len(upload) {
		t.Fatalf("destination read %d bytes, %v; want %d, then EOF", len(got), err, len("request")+len(upload))
	}
	if err := waitRelay(t, done, "the relay must end on the client's close"); err != nil {
		t.Fatalf("an ordinary close ended the relay with %v", err)
	}
}

// The other half of "a failure aborts both sides": a destination that resets
// mid-download resets the client's stream, not an EOF.
func TestRelayTCPDestinationResetResetsTheClient(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	if _, err := r.dest.Write([]byte("part of a download")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("part of a download"))
	_ = r.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(r.client, buf); err != nil {
		t.Fatal(err)
	}
	if err := r.dest.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = r.dest.Close()
	_, err := io.ReadAll(r.client)
	var se *quic.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("the client must see its stream reset, got %v", err)
	}
	waitRelay(t, done, "the relay must end on the destination's reset")
}

// The destination closes first: its reply and FIN reach the client, and the
// client's upload after that still reaches the destination, with its EOF.
func TestRelayTCPDestinationFirstHalfCloseCarriesTheUpload(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
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
	if _, err := r.client.Write([]byte(" and more")); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = r.dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(r.dest)
	if err != nil || string(got) != "request and more" {
		t.Fatalf("destination read %q, %v; want the whole upload, then EOF", got, err)
	}
	if err := waitRelay(t, done, "the relay must end after both directions ended"); err != nil {
		t.Fatalf("a clean relay returned %v", err)
	}
}
