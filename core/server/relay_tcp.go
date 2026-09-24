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
//     closed with an RST (SetLinger(0)) and the stream is reset both ways.
// A remote connection that cannot half-close (no CloseWrite) keeps upstream's
// behaviour for a clean end: the first direction to end ends the relay.

import (
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
		// caller closes both sides gracefully. Closing the remote here ends
		// the other direction's copy (its error is expected and ignored).
		_ = remote.Close()
		stream.CancelRead(streamAbortCode)
		<-results
		return nil
	}
	if second := <-results; second != nil {
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
