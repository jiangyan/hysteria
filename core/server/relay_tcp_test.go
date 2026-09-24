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
	"sync"
	"sync/atomic"
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

// start runs the relay and then closes both sides the way handleTCPRequest
// does right after it returns (tConn.Close, stream.Close), so a test sees
// what production's final close does (Codex round 3 on A4).
func (r *relayRig) start() <-chan error {
	return r.startWith(r.remote)
}

func (r *relayRig) startWith(remote net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		err := relayTCPFast(r.server, remote)
		_ = remote.Close()
		_ = r.server.Close()
		done <- err
	}()
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
	old := fallbackWriteGrace
	fallbackWriteGrace = 300 * time.Millisecond
	reset := make(chan struct{})
	fallbackGraceReset = func() { close(reset) }
	t.Cleanup(func() { fallbackWriteGrace, fallbackGraceReset = old, nil })
	// A client that never reads: its stream window stays small, and full.
	r := newRelayRig(t, &quic.Config{InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10})
	done := r.startWith(noHalfClose{r.remote})
	written := streamInto(t, r.dest)
	// The download fills the client's window and blocks in stream.Write:
	// proven when the destination's own writes stall (nobody reads the
	// server's socket any more), not assumed after a sleep.
	waitStalled(t, written)
	// The client finishes its upload: the first direction ends cleanly.
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	waitRelay(t, done, "the fallback is waiting on a download blocked by flow control")
	// The blocked copy is not left for ever (Codex round 3 on A4): after the
	// grace its stream side is reset. Wait for that reset itself (reading
	// first would release the copy and prove nothing), then read: the client
	// gets the reset, not an EOF that makes the cut download look complete.
	select {
	case <-reset:
	case <-time.After(5 * time.Second):
		t.Fatal("the grace never reset the blocked copy's stream")
	}
	_ = r.client.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.ReadAll(r.client)
	var se *quic.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("the blocked download must end in a reset after the grace, got %v", err)
	}
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
	// The destination closes its side once the upload has ended, as servers
	// do; until then the relay drains it (readerGoneDrain).
	if err := r.dest.CloseWrite(); err != nil {
		t.Fatal(err)
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
	stopped := make(chan struct{}, 1)
	go func() {
		chunk := make([]byte, 16<<10)
		for {
			select {
			case <-stopped:
				_ = r.dest.CloseWrite()
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
	// The upload is done: the destination stops sending and closes its side,
	// which ends the relay's drain.
	stopped <- struct{}{}
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

// Codex round 3 on A4, P1: the client stops reading (code 0) while its
// upload is still arriving, and the destination then half-closes. The
// download copy's Close fails with quic-go's untyped "close called for
// canceled stream"; read as a failure it aborted the destination and cut the
// rest of the upload. The upload must still arrive whole.
func TestRelayTCPStopThenDestinationEOFKeepsTheUpload(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	r.client.CancelRead(0) // the official client's STOP_SENDING, before its FIN
	select {
	case <-r.server.Context().Done(): // it reached the server
	case <-time.After(3 * time.Second):
		t.Fatal("the client's STOP_SENDING never reached the server")
	}
	if err := r.dest.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := r.client.Write([]byte(" and the rest")); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = r.dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(r.dest)
	if err != nil || string(got) != "request and the rest" {
		t.Fatalf("destination read %q, %v; want the whole upload, then EOF", got, err)
	}
	if err := waitRelay(t, done, "the relay must end"); err != nil {
		t.Fatalf("an ordinary close ended the relay with %v", err)
	}
}

// Codex round 3 on A4, P1: after the official client's close, a destination
// that is still sending must not have its socket closed under it with unread
// data (Linux resets such a close, discarding the upload's queued tail): the
// relay drains it and ends only at its EOF.
func TestRelayTCPOfficialClientCloseWaitsForTheDestinationsEOF(t *testing.T) {
	r := newRelayRig(t, nil)
	done := r.start()
	stopSending := make(chan struct{})
	go func() {
		chunk := make([]byte, 4<<10)
		for {
			select {
			case <-stopSending:
				_ = r.dest.CloseWrite()
				return
			default:
			}
			if _, err := r.dest.Write(chunk); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	officialClientClose(t, r.client)
	time.Sleep(400 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("the relay ended (%v) while the destination was still sending", err)
	default:
	}
	close(stopSending)
	if err := waitRelay(t, done, "the relay must end at the destination's EOF"); err != nil {
		t.Fatalf("an ordinary close ended the relay with %v", err)
	}
	_ = r.dest.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(r.dest)
	if err != nil || string(got) != "request" {
		t.Fatalf("destination read %q, %v; want the upload, then EOF", got, err)
	}
}

// The drain is bounded: a destination that never stops sending holds the
// relay for readerGoneDrain after the upload, no longer.
func TestRelayTCPOfficialClientCloseDrainIsBounded(t *testing.T) {
	old := readerGoneDrain
	readerGoneDrain = 300 * time.Millisecond
	t.Cleanup(func() { readerGoneDrain = old })
	r := newRelayRig(t, nil)
	done := r.start()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		chunk := make([]byte, 4<<10)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := r.dest.Write(chunk); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	officialClientClose(t, r.client)
	waitRelay(t, done, "the drain must end at its bound")
}

// tlsOnTCP is a TLS client over a TCP connection to a TLS server on the
// destination side: an outbound wrapped the way the HTTPS outbound wraps
// its socket.
func tlsOnTCP(t *testing.T, r *relayRig) (*tls.Conn, *tls.Conn) {
	t.Helper()
	serverTLS, clientTLS := relayTestTLS(t)
	client := tls.Client(r.remote, clientTLS)
	server := tls.Server(r.dest, serverTLS)
	errs := make(chan error, 1)
	go func() { errs <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	return client, server
}

// Codex round 3 on A4, P2: an abort through a wrapped outbound (*tls.Conn)
// used to skip the linger and close gracefully (close_notify, then FIN).
// The socket under it must be reset.
func TestRelayTCPAbortResetsTheSocketUnderATLSOutbound(t *testing.T) {
	r := newRelayRig(t, nil)
	remote, dest := tlsOnTCP(t, r)
	done := r.startWith(remote)
	// The destination reads CONCURRENTLY, as a proxy does: whatever reaches
	// it first decides what it sees (Codex round 4 on A4 — a reader that
	// only reads after the relay ends cannot tell a close_notify that
	// arrived first from the RST).
	ends := make(chan error, 1)
	readRequest := make(chan struct{})
	go func() {
		_ = dest.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		if _, err := io.ReadFull(dest, buf[:len("request")]); err != nil {
			ends <- err
			return
		}
		close(readRequest)
		for {
			if _, err := dest.Read(buf); err != nil {
				ends <- err
				return
			}
		}
	}()
	<-readRequest // the reader is past the request, on its next Read
	r.client.CancelWrite(7)
	r.client.CancelRead(7)
	waitRelay(t, done, "the relay must end on the client's reset")
	err := <-ends
	if errors.Is(err, io.EOF) {
		t.Fatalf("the TLS destination took the abort as a clean end (close_notify before the RST): %v", err)
	}
	if !isConnReset(err) {
		t.Fatalf("the TLS destination must see a reset, got %v", err)
	}
}

// socketUnder walks NetConn wrappers down to the socket (cachedConn is in
// extras, so a stand-in wrapper here).
type netConnWrapper struct{ net.Conn }

func (w netConnWrapper) NetConn() net.Conn { return w.Conn }

func TestLingerTargetFindsTheSocketUnderWrappers(t *testing.T) {
	r := newRelayRig(t, nil)
	tcp := r.remote.(*net.TCPConn)
	if socketUnder(netConnWrapper{netConnWrapper{tcp}}) != net.Conn(tcp) {
		t.Fatal("socketUnder must find the TCP socket under nested NetConn wrappers")
	}
	if socketUnder(noHalfClose{tcp}) != nil {
		t.Fatal("a wrapper without NetConn has no linger target")
	}
}

// closeSendSide on a send side the client has already stopped reports the
// client's StreamError, not quic-go's untyped Close error, so a code-0 stop
// is still told apart from an abort when the copy's result reaches the relay
// before the context's cancellation does (Codex round 3 on A4, P1).
func TestCloseSendSideReportsTheClientsStop(t *testing.T) {
	for _, code := range []quic.StreamErrorCode{0, 7} {
		r := newRelayRig(t, nil)
		r.client.CancelRead(code)
		select {
		case <-r.server.Context().Done():
		case <-time.After(3 * time.Second):
			t.Fatal("the client's STOP_SENDING never reached the server")
		}
		err := closeSendSide(r.server)
		var se *quic.StreamError
		if !errors.As(err, &se) || se.ErrorCode != code || !se.Remote {
			t.Fatalf("code %d: closeSendSide returned %v; want the client's StreamError", code, err)
		}
		if clientStoppedReading(err) != (code == 0) {
			t.Fatalf("code %d: clientStoppedReading(%v) = %v", code, err, clientStoppedReading(err))
		}
	}
}

// streamInto writes to dest in 16 KiB chunks until a write fails (the rig
// closes dest at cleanup), counting the bytes written. Unbounded on purpose:
// a writer that stopped by itself would look like a stalled one.
func streamInto(t *testing.T, dest *net.TCPConn) *atomic.Int64 {
	t.Helper()
	var written atomic.Int64
	go func() {
		chunk := make([]byte, 16<<10)
		for {
			n, err := dest.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	return &written
}

// waitStalled waits until the byte count stops moving for 300 ms: the
// destination's writes are blocked because nobody reads the other end.
func waitStalled(t *testing.T, written *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := written.Load()
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		now := written.Load()
		if now == last && now > 0 {
			return
		}
		last = now
	}
	t.Fatalf("the destination's writes never stalled (%d bytes written)", written.Load())
}

// Codex round 4 on A4: after a code-0 stop the drain went through a plain
// io.Copy, which neither counted the bytes nor asked the traffic logger, and
// the relay then accepted any end of the download, so a disconnect the
// logger requested was swallowed. The drain now goes through the relay's
// own copy function, and errDisconnect always ends the relay with that
// error (the handler then closes the client's connection).
func TestRelayTCPDrainStillHonoursTheTrafficLogger(t *testing.T) {
	r := newRelayRig(t, nil)
	plain := func(dst io.Writer, src io.Reader) error {
		_, err := io.Copy(dst, src)
		return err
	}
	// The logger's verdict comes while the relay drains (dst is io.Discard):
	// it asks for a disconnect.
	kickWhileDraining := func(dst io.Writer, src io.Reader) error {
		if dst == io.Discard {
			return copyBufferLog(dst, src, func(uint64) bool { return false })
		}
		_, err := io.Copy(dst, src)
		return err
	}
	done := make(chan error, 1)
	go func() {
		err := relayTCP(r.server, r.remote, plain, kickWhileDraining)
		_ = r.remote.Close()
		_ = r.server.Close()
		done <- err
	}()
	streamInto(t, r.dest)
	officialClientClose(t, r.client)
	if err := waitRelay(t, done, "the relay must end on the logger's disconnect"); !errors.Is(err, errDisconnect) {
		t.Fatalf("the relay must end with errDisconnect so the handler disconnects the client, got %v", err)
	}
}

// Codex round 4 on A4: the drain's deadline was armed only once the upload
// was done, so a client that stopped reading (code 0) but kept its upload
// open let the destination stream into the drain for as long as it liked.
// The deadline now runs from the client's stop: after it, nothing reads the
// destination any more and its writes stall.
func TestRelayTCPDrainIsBoundedFromTheClientsStop(t *testing.T) {
	old := readerGoneDrain
	readerGoneDrain = 300 * time.Millisecond
	t.Cleanup(func() { readerGoneDrain = old })
	r := newRelayRig(t, nil)
	done := r.start()
	written := streamInto(t, r.dest)
	r.client.CancelRead(0) // stops reading; its upload stays open
	waitStalled(t, written)
	// The relay still waits for the upload, which ends now.
	if err := r.client.Close(); err != nil {
		t.Fatal(err)
	}
	waitRelay(t, done, "the relay must end once the upload ends")
}

// closeRecorder records which connection abortTCP closes, in order.
type closeRecorder struct{ order []string }

// recordedSocket stands for the TCP socket under a wrapper: it can set its
// linger, and its Close is recorded.
type recordedSocket struct {
	net.Conn
	rec *closeRecorder
}

func (s recordedSocket) SetLinger(int) error { return nil }
func (s recordedSocket) Close() error {
	s.rec.order = append(s.rec.order, "socket")
	return nil
}

// recordedWrapper stands for a *tls.Conn: its NetConn is the socket, and its
// own Close is recorded (a real one would write close_notify here).
type recordedWrapper struct {
	net.Conn
	inner net.Conn
	rec   *closeRecorder
}

func (w recordedWrapper) NetConn() net.Conn { return w.inner }
func (w recordedWrapper) Close() error {
	w.rec.order = append(w.rec.order, "wrapper")
	return nil
}

// Codex round 5 on A4, P3: the order abortTCP closes in, asserted directly
// (the TLS row can only observe it through timing): the socket under a
// wrapper first, so the wrapper's graceful close finds it already reset.
func TestAbortTCPClosesTheSocketBeforeTheWrapper(t *testing.T) {
	r := newRelayRig(t, nil)
	rec := &closeRecorder{}
	sock := recordedSocket{Conn: r.remote, rec: rec}
	abortTCP(r.server, recordedWrapper{Conn: r.remote, inner: sock, rec: rec})
	if len(rec.order) != 2 || rec.order[0] != "socket" || rec.order[1] != "wrapper" {
		t.Fatalf("abortTCP must close the socket, then the wrapper; got %v", rec.order)
	}
}

// Codex round 5 on A4, P2: fail() drained the other copy's result without
// looking at it, so a disconnect the traffic logger asked for in the drain
// was lost behind a competing upload failure. The order is forced: the
// upload fails only once the drain has begun, and the drain reports the
// disconnect only after the abort closes its socket.
func TestRelayTCPADisconnectOutranksACompetingFailure(t *testing.T) {
	r := newRelayRig(t, nil)
	draining := make(chan struct{})
	errUpload := errors.New("the upload failed")
	upload := func(dst io.Writer, src io.Reader) error {
		<-draining
		return errUpload
	}
	download := func(dst io.Writer, src io.Reader) error {
		if dst != io.Discard {
			_, err := io.Copy(dst, src)
			return err
		}
		close(draining)
		buf := make([]byte, 1)
		for {
			if _, err := src.Read(buf); err != nil {
				// The abort closed the socket: the logger's verdict, now.
				return errDisconnect
			}
		}
	}
	done := make(chan error, 1)
	go func() { done <- relayTCP(r.server, r.remote, upload, download) }()
	r.client.CancelRead(0) // the client reads no more
	select {
	case <-r.server.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the client's STOP_SENDING never reached the server")
	}
	// A write toward the client now fails on the stop: the download drains.
	if _, err := r.dest.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := waitRelay(t, done, "the relay must end"); !errors.Is(err, errDisconnect) {
		t.Fatalf("the logger's disconnect must outrank the upload's failure, got %v", err)
	}
}

// stuckReadConn is a remote whose Read ignores read deadlines and blocks
// until Close, as a *tls.Conn's Read does while it writes a KeyUpdate
// response to a destination that no longer accepts writes.
type stuckReadConn struct {
	*net.TCPConn
	closed chan struct{}
	once   sync.Once
}

func (c *stuckReadConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *stuckReadConn) SetReadDeadline(time.Time) error { return nil }
func (c *stuckReadConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.TCPConn.Close()
}

// Codex round 5 on A4, P2: a drain stuck where its read deadline does not
// reach held the relay (and the destination) past the bound. The relay now
// aborts it at readerGoneDrain + drainOverrun.
func TestRelayTCPAStuckDrainIsAbortedAtItsBound(t *testing.T) {
	oldDrain, oldOverrun := readerGoneDrain, drainOverrun
	readerGoneDrain, drainOverrun = 100*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { readerGoneDrain, drainOverrun = oldDrain, oldOverrun })
	r := newRelayRig(t, nil)
	stuck := &stuckReadConn{TCPConn: r.remote.(*net.TCPConn), closed: make(chan struct{})}
	done := r.startWith(stuck)
	r.client.CancelRead(0) // the client reads no more; its upload stays open
	if err := waitRelay(t, done, "a stuck drain must be aborted at its bound"); !errors.Is(err, errDrainOverrun) {
		t.Fatalf("the relay must end with errDrainOverrun, got %v", err)
	}
}
