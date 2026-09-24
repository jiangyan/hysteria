package server

// daisy fork (dg1400 branch, 2026-09-24): relay a proxied TCP stream so that
// how one side ENDS reaches the other side unchanged.
//
// Upstream's copyTwoWay returns as soon as EITHER direction ends, clean or
// not, and handleTCPRequest then closes both sides gracefully. Two defects
// follow:
//   - half-close is lost: a client that sends its request, half-closes (FIN)
//     and then reads the reply gets its stream closed before the reply
//     arrives, because the client's EOF ended the whole relay;
//   - an abort reads as a completed transfer: a client that RESETS its stream
//     mid-upload, or a destination that resets mid-download, still reaches the
//     other end as an ordinary FIN, and a protocol without its own length
//     framing (FTP's data connection) stores the truncated transfer as a
//     success.
//
// relayTCP keeps both directions running until both have ended:
//   - a direction that reaches a clean EOF half-closes its destination (the
//     remote connection's CloseWrite; the stream's send side) and the other
//     direction carries on;
//   - a direction that FAILS aborts both sides: the remote connection is
//     closed with an RST (SetLinger(0)) and the stream is reset both ways;
//   - a client that gives up is noticed even when the remaining copy is
//     parked in remote.Read on a silent destination: its STOP_SENDING cancels
//     the stream's context (below);
//   - STOP_SENDING with code 0 is not an abort. The official client closes
//     every stream that way (QStream.Close: CancelRead(0) + Close) whenever
//     its side ends, so code 0 means "I will read no more": the upload is
//     still carried to its end. The destination may still be sending, so the
//     download copy keeps consuming (and dropping) what it sends until its
//     EOF, for up to readerGoneDrain after the client stopped reading: a
//     socket closed with unread data is RESET by Linux, which would discard
//     the upload's tail still queued behind it. The drain goes through the
//     same copy function, so its bytes are counted and the traffic logger can
//     still disconnect the client. Past that bound the caller's close may
//     reset the destination, as upstream's always could, and a reset is a
//     visible failure there, not a silent one. daisy aborts with a nonzero
//     code.
//     (The independent review of A4: reading code 0 as an abort reset the
//     destination under every official client, and cut uploads short:
//     122 524 of 262 151 bytes in relay_tcp_test.go. Codex round 3: the
//     drain, and quic-go's untyped error from Close on a stopped stream.)
//   - an abort reaches the destination as an RST wherever the outbound's TCP
//     socket can be found: the connection itself, or the socket under a
//     wrapper that exposes NetConn (*tls.Conn for the HTTPS outbound,
//     cachedConn for HTTP CONNECT). That socket is closed first, so a
//     wrapper's own graceful close (a TLS close_notify) never reaches the
//     peer ahead of the RST. Anything else closes as it closes.
// A remote connection that cannot half-close (no CloseWrite) keeps upstream's
// behaviour for a clean end: the first direction to end ends the relay. The
// other copy is not waited for; if it is still blocked on the client's flow
// control fallbackWriteGrace later, its stream side is reset so the
// goroutine ends (upstream's copyTwoWay leaked it for as long as the client
// kept the connection without reading).
//
// Known gap, shared with upstream: once the remote → client copy has ended
// cleanly, a client reset while the client → remote copy is parked in
// remote.Write (a destination that stopped reading) is noticed only when the
// destination reads again or closes. The stream's receive side has no
// context to watch.

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/utils"
)

// streamAbortCode is the application error code a relayed stream is reset
// with when its transfer failed. Clients treat any reset as an abort.
const streamAbortCode quic.StreamErrorCode = 0

// readerGoneDrain bounds how long, after the client stopped reading (a
// code-0 STOP_SENDING), the relay keeps consuming what a destination still
// sends, so that the destination's socket is closed with nothing unread.
// Counted from the stop, not from the upload's end, so a client that keeps
// its upload open cannot keep the destination streaming into the drain
// (Codex round 4 on A4). A variable so tests can shorten it.
var readerGoneDrain = 5 * time.Second

// fallbackWriteGrace bounds how long the no-CloseWrite fallback leaves a
// copy blocked in stream.Write by the client's flow control before it resets
// the stream's send side. A variable so tests can shorten it.
var fallbackWriteGrace = 30 * time.Second

// fallbackGraceReset, when set (tests only), is called after the fallback's
// grace reset a copy still blocked on the client's flow control.
var fallbackGraceReset func()

type closeWriter interface {
	CloseWrite() error
}

type lingerSetter interface {
	SetLinger(sec int) error
}

// copyFunc copies src into dst until src's EOF (nil) or an error.
type copyFunc func(dst io.Writer, src io.Reader) error

// relayEnd is how one direction's copy ended.
type relayEnd struct {
	toRemote bool // the client → remote direction
	err      error
}

// clientStoppedReading reports whether err is the client's ORDINARY close of
// its reading side: STOP_SENDING with code 0 (a write failing on it, or the
// stream context's cause). The official client sends it on every close;
// daisy's abort uses a nonzero code.
func clientStoppedReading(err error) bool {
	var se *quic.StreamError
	return errors.As(err, &se) && se.Remote && se.ErrorCode == 0
}

// relayTCPEx is relayTCP with traffic logging and stream stats, the
// counterpart of copyTwoWayEx.
func relayTCPEx(id string, stream *utils.QStream, remote net.Conn, l TrafficLogger, stats *StreamStats) error {
	toRemote := func(dst io.Writer, src io.Reader) error {
		return copyBufferLog(dst, src, func(n uint64) bool {
			stats.LastActiveTime.Store(time.Now())
			stats.Tx.Add(n)
			return l.LogTraffic(id, n, 0)
		})
	}
	toClient := func(dst io.Writer, src io.Reader) error {
		return copyBufferLog(dst, src, func(n uint64) bool {
			stats.LastActiveTime.Store(time.Now())
			stats.Rx.Add(n)
			return l.LogTraffic(id, 0, n)
		})
	}
	return relayTCP(stream, remote, toRemote, toClient)
}

// relayTCPFast is relayTCP without logging, the counterpart of copyTwoWay.
func relayTCPFast(stream *utils.QStream, remote net.Conn) error {
	plain := func(dst io.Writer, src io.Reader) error {
		_, err := io.Copy(dst, src)
		return err
	}
	return relayTCP(stream, remote, plain, plain)
}

func relayTCP(stream *utils.QStream, remote net.Conn, toRemote, toClient copyFunc) error {
	cw, halfClose := remote.(closeWriter)
	results := make(chan relayEnd, 2)
	go func() {
		// client -> remote
		err := toRemote(remote, stream)
		if err == nil && halfClose {
			// The client finished sending: pass its FIN on, keep the reply flowing.
			err = cw.CloseWrite()
		}
		results <- relayEnd{toRemote: true, err: err}
	}()
	go func() {
		// remote -> client
		err := toClient(stream, remote)
		if err == nil && halfClose {
			// The remote finished sending: FIN the stream's send side only.
			// QStream.Close would also cancel the read side, cutting off
			// whatever the client is still uploading.
			err = closeSendSide(stream)
		}
		if halfClose && clientStoppedReading(err) {
			// The client reads no more, but the destination may still be
			// sending: keep consuming it until its EOF, or until the read
			// deadline the relay sets when the client stopped, so its socket
			// is not closed with unread data (see readerGoneDrain). Through
			// toClient, so the bytes are still counted and a disconnect the
			// traffic logger asks for still ends the relay (Codex round 4 on
			// A4: a plain io.Copy bypassed both).
			if derr := toClient(io.Discard, remote); errors.Is(derr, errDisconnect) {
				err = derr
			}
		}
		results <- relayEnd{toRemote: false, err: err}
	}()

	if !halfClose {
		first := <-results
		if first.err != nil && !(!first.toRemote && clientStoppedReading(first.err)) {
			abortTCP(stream, remote)
			<-results
			return first.err
		}
		// Upstream's behaviour: the first clean end ends the relay; the
		// caller closes both sides gracefully. Closing the remote ends the
		// other copy if it is reading. One blocked in stream.Write by flow
		// control is released only by new credit from the client, its
		// STOP_SENDING, a CancelWrite or the connection's end — not by Close
		// or CancelRead — so it is not waited for here (Codex round 1 on A4);
		// upstream's copyTwoWay never waited for it either. `results` is
		// buffered, so its late send does not block. If it is still blocked
		// fallbackWriteGrace later, reset the stream's send side so the
		// goroutine ends (Codex round 3 on A4).
		_ = remote.Close()
		stream.CancelRead(streamAbortCode)
		time.AfterFunc(fallbackWriteGrace, func() {
			select {
			case <-results:
			default:
				stream.CancelWrite(streamAbortCode)
				if fallbackGraceReset != nil {
					fallbackGraceReset()
				}
			}
		})
		return nil
	}

	pending := 2                     // copies still running
	upDone, downDone := false, false // each direction ended without a failure
	readerGone := false              // the client closed its reading side (code 0)
	draining := false                // the drain's deadline is set
	// While a copy is still running it may be parked in remote.Read on a
	// silent destination, where nothing tells it the client has since given
	// up: a client reset after its FIN arrives as STOP_SENDING on the
	// stream's write side, which only a write would notice (Codex round 1 on
	// A4). quic-go cancels the write side's context on it with the peer's
	// StreamError as the cause; on our own Close with no cause
	// (context.Canceled); and with the connection's error when it dies.
	ctx := stream.Context()
	ctxDone := ctx.Done()
	fail := func(err error) error {
		abortTCP(stream, remote)
		for ; pending > 0; pending-- {
			<-results
		}
		return err
	}
	for !(upDone && downDone) {
		select {
		case r := <-results:
			pending--
			switch {
			case r.err == nil && r.toRemote:
				upDone = true
			case r.err == nil:
				downDone = true
			case errors.Is(r.err, errDisconnect):
				// The traffic logger asked for the client to be disconnected:
				// never swallowed as an ordinary end (Codex round 4 on A4).
				return fail(r.err)
			case !r.toRemote && (readerGone || clientStoppedReading(r.err)):
				// The client reads no more (the download copy has drained
				// what the destination sent, or its drain was cut); its
				// upload may still be arriving.
				downDone, readerGone = true, true
			default:
				return fail(r.err)
			}
		case <-ctxDone:
			ctxDone = nil
			switch cause := context.Cause(ctx); {
			case cause == context.Canceled:
				// Our own Close: the remote → client copy finished its write
				// side cleanly, and its result is on its way.
			case clientStoppedReading(cause):
				readerGone = true
			default:
				// Stopped by the peer, or the connection is gone: the
				// transfer will not complete.
				return fail(cause)
			}
		}
		if readerGone && !downDone && !draining {
			// The client reads no more. Give the destination up to
			// readerGoneDrain to finish while the download copy consumes what
			// it still sends; the copy's result marks the download done. A
			// copy parked on a silent destination ends at the deadline. The
			// loop then still waits for the upload.
			_ = remote.SetReadDeadline(time.Now().Add(readerGoneDrain))
			draining = true
		}
	}
	return nil
}

// closeSendSide FINs the stream's send side. On a send side the peer has
// already stopped, quic-go's Close returns an untyped error ("close called
// for canceled stream"); the context's cause carries the peer's StreamError,
// which is returned instead, so the relay tells a code-0 close from an abort
// even when this result reaches it before the context's cancellation does
// (Codex round 3 on A4).
func closeSendSide(stream *utils.QStream) error {
	err := stream.Stream.Close()
	if err != nil {
		if cause := context.Cause(stream.Context()); cause != nil && cause != context.Canceled {
			return cause
		}
	}
	return err
}

// socketUnder finds the connection whose close decides what the
// destination sees: remote itself when it can set its linger, or the TCP
// socket under a wrapper that exposes NetConn (*tls.Conn for the HTTPS
// outbound, cachedConn for HTTP CONNECT). Without it, an abort through a
// wrapped outbound closed gracefully (Codex round 3 on A4). The result
// implements lingerSetter; nil when there is none.
func socketUnder(remote net.Conn) net.Conn {
	for c := remote; c != nil; {
		if _, ok := c.(lingerSetter); ok {
			return c
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		next := u.NetConn()
		if next == c {
			return nil
		}
		c = next
	}
	return nil
}

// abortTCP ends a failed transfer so that neither end reads it as complete:
// the remote connection with an RST, the stream with a reset both ways.
func abortTCP(stream *utils.QStream, remote net.Conn) {
	if sock := socketUnder(remote); sock != nil {
		_ = sock.(lingerSetter).SetLinger(0)
		// The socket FIRST: a wrapper's own Close may still write — a
		// *tls.Conn sends close_notify, which a TLS peer reading at that
		// moment takes as a clean end the RST cannot undo (Codex round 4 on
		// A4). Closed underneath, that write fails and nothing but the RST
		// is sent.
		_ = sock.Close()
	}
	_ = remote.Close()
	stream.CancelRead(streamAbortCode)
	stream.CancelWrite(streamAbortCode)
}
