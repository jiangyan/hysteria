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
//   - while one direction has ended cleanly and the other is still running,
//     a client that gives up is noticed even if the remaining copy is parked
//     in remote.Read on a silent destination: the client's STOP_SENDING
//     cancels the stream's context (below).
// A remote connection that cannot half-close (no CloseWrite) keeps upstream's
// behaviour for a clean end: the first direction to end ends the relay, and
// the other copy is not waited for.

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/utils"
)

// streamAbortCode is the application error code a relayed stream is reset
// with when its transfer failed. Clients treat any reset as an abort.
const streamAbortCode quic.StreamErrorCode = 0

type closeWriter interface {
	CloseWrite() error
}

type lingerSetter interface {
	SetLinger(sec int) error
}

// copyFunc copies src into dst until src's EOF (nil) or an error.
type copyFunc func(dst io.Writer, src io.Reader) error

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
	results := make(chan error, 2)
	go func() {
		// client -> remote
		err := toRemote(remote, stream)
		if err == nil && halfClose {
			// The client finished sending: pass its FIN on, keep the reply flowing.
			err = cw.CloseWrite()
		}
		results <- err
	}()
	go func() {
		// remote -> client
		err := toClient(stream, remote)
		if err == nil && halfClose {
			// The remote finished sending: FIN the stream's send side only.
			// QStream.Close would also cancel the read side, cutting off
			// whatever the client is still uploading.
			err = stream.Stream.Close()
		}
		results <- err
	}()

	first := <-results
	if first != nil {
		abortTCP(stream, remote)
		<-results
		return first
	}
	if !halfClose {
		// Upstream's behaviour: the first clean end ends the relay; the
		// caller closes both sides gracefully. Closing the remote ends the
		// other copy if it is reading; one blocked in stream.Write by flow
		// control is released only when the caller closes the stream, so it
		// is not waited for here (Codex round 1 on A4) — upstream's
		// copyTwoWay never waited for it either. `results` is buffered, so
		// its late send does not block.
		_ = remote.Close()
		stream.CancelRead(streamAbortCode)
		return nil
	}
	// One direction ended cleanly; the other is still running. It may be
	// parked in remote.Read on a silent destination, where nothing tells it
	// the client has since given up: a client reset after its FIN arrives as
	// STOP_SENDING on the stream's write side, which only a write would
	// notice (Codex round 1 on A4). quic-go cancels the write side's context
	// on it, with the peer's StreamError as the cause.
	ctx := stream.Context()
	select {
	case second := <-results:
		return finishSecond(stream, remote, second)
	case <-ctx.Done():
	}
	if cause := context.Cause(ctx); cause != context.Canceled {
		// Stopped by the peer, or the connection is gone: the transfer will
		// not complete.
		abortTCP(stream, remote)
		<-results
		return cause
	}
	// Canceled without a cause is our own Close: the remote → client copy
	// finished its write side cleanly, and its result is on its way. The
	// client → remote copy still running reads the stream, so a client
	// reset reaches it as a read error.
	return finishSecond(stream, remote, <-results)
}

// finishSecond ends the relay on the second direction's result.
func finishSecond(stream *utils.QStream, remote net.Conn, second error) error {
	if second != nil {
		abortTCP(stream, remote)
		return second
	}
	return nil
}

// abortTCP ends a failed transfer so that neither end reads it as complete:
// the remote connection with an RST, the stream with a reset both ways.
func abortTCP(stream *utils.QStream, remote net.Conn) {
	if l, ok := remote.(lingerSetter); ok {
		_ = l.SetLinger(0)
	}
	_ = remote.Close()
	stream.CancelRead(streamAbortCode)
	stream.CancelWrite(streamAbortCode)
}
