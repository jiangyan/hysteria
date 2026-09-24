package outbounds

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/database64128/tfo-go/v2"
)

type fastOpenDialer struct {
	dialer *tfo.Dialer
}

func newFastOpenDialer(netDialer *net.Dialer) *fastOpenDialer {
	return &fastOpenDialer{
		dialer: &tfo.Dialer{
			Dialer: *netDialer,
		},
	}
}

// Dial returns immediately without actually establishing a connection.
// The connection will be established by the first Write() call.
func (d *fastOpenDialer) Dial(network, address string) (net.Conn, error) {
	return &fastOpenConn{
		dialer:    d.dialer,
		network:   network,
		address:   address,
		readyChan: make(chan struct{}),
	}, nil
}

type fastOpenConn struct {
	dialer  *tfo.Dialer
	network string
	address string

	conn      net.Conn
	connLock  sync.RWMutex
	readyChan chan struct{}

	// States before connection ready
	deadline      *time.Time
	readDeadline  *time.Time
	writeDeadline *time.Time
	linger        *int
}

func (c *fastOpenConn) Read(b []byte) (n int, err error) {
	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn != nil {
		return conn.Read(b)
	}

	// Wait until the connection is ready or closed
	<-c.readyChan

	if c.conn == nil {
		// This is equivalent to isClosedBeforeReady() == true
		return 0, net.ErrClosed
	}

	return c.conn.Read(b)
}

func (c *fastOpenConn) Write(b []byte) (n int, err error) {
	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn != nil {
		return conn.Write(b)
	}

	c.connLock.RLock()
	closed := c.isClosedBeforeReady()
	c.connLock.RUnlock()

	if closed {
		return 0, net.ErrClosed
	}

	c.connLock.Lock()
	defer c.connLock.Unlock()

	if c.isClosedBeforeReady() {
		// Closed by other goroutine
		return 0, net.ErrClosed
	}

	conn = c.conn
	if conn != nil {
		// Established by other goroutine
		return conn.Write(b)
	}

	conn, err = c.dialer.Dial(c.network, c.address, b)
	if err != nil {
		close(c.readyChan)
		return 0, err
	}

	// Apply pre-set states
	if c.deadline != nil {
		_ = conn.SetDeadline(*c.deadline)
	}
	if c.readDeadline != nil {
		_ = conn.SetReadDeadline(*c.readDeadline)
	}
	if c.writeDeadline != nil {
		_ = conn.SetWriteDeadline(*c.writeDeadline)
	}
	if c.linger != nil {
		if l, ok := conn.(interface{ SetLinger(sec int) error }); ok {
			_ = l.SetLinger(*c.linger)
		}
	}

	c.conn = conn
	close(c.readyChan)
	return len(b), nil
}

func (c *fastOpenConn) Close() error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	if c.conn != nil {
		return c.conn.Close()
	}

	close(c.readyChan)
	return nil
}

// isClosedBeforeReady returns true if the connection is closed before the real connection is established.
// This function should be called with connLock.RLock().
func (c *fastOpenConn) isClosedBeforeReady() bool {
	select {
	case <-c.readyChan:
		if c.conn == nil {
			return true
		}
	default:
	}
	return false
}

func (c *fastOpenConn) LocalAddr() net.Addr {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	if c.conn != nil {
		return c.conn.LocalAddr()
	}

	return nil
}

func (c *fastOpenConn) RemoteAddr() net.Addr {
	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn != nil {
		return conn.RemoteAddr()
	}

	addr, err := net.ResolveTCPAddr(c.network, c.address)
	if err != nil {
		return nil
	}
	return addr
}

func (c *fastOpenConn) SetDeadline(t time.Time) error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	c.deadline = &t

	if c.conn != nil {
		return c.conn.SetDeadline(t)
	}

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	return nil
}

func (c *fastOpenConn) SetReadDeadline(t time.Time) error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	c.readDeadline = &t

	if c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	return nil
}

func (c *fastOpenConn) SetWriteDeadline(t time.Time) error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	c.writeDeadline = &t

	if c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	return nil
}

// daisy fork: the server's TCP relay (core/server/relay_tcp.go) passes a
// clean end on with CloseWrite and aborts a failed transfer with
// SetLinger(0), and falls back to closing gracefully when the remote
// connection has neither. Without the two methods below, a server with
// fastOpen enabled lost both: a half-closed client lost its reply and an
// aborted transfer reached the destination as a FIN. The dialed connection
// is a *net.TCPConn on every tfo-go path, so both delegate.

// CloseWrite half-closes the connection. Nothing is dialed before the
// first Write, so a client that ends its upload without sending a byte is
// dialed here (an empty first write is a plain connect): the destination
// sees what a server without fastOpen shows it — a connection, then a FIN.
func (c *fastOpenConn) CloseWrite() error {
	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn == nil {
		if _, err := c.Write(nil); err != nil {
			return err
		}
		c.connLock.RLock()
		conn = c.conn
		c.connLock.RUnlock()
	}

	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// SetLinger sets SO_LINGER on the connection (0: Close sends an RST).
// Before the first Write nothing was dialed: the setting is kept and applied
// to the connection a later Write dials, like the deadlines are (Codex
// round 3 on A4: an abort's SetLinger(0) racing the first Write was lost,
// and the new connection closed with a FIN).
func (c *fastOpenConn) SetLinger(sec int) error {
	c.connLock.Lock()
	conn := c.conn
	if conn == nil {
		c.linger = &sec
		c.connLock.Unlock()
		return nil
	}
	c.connLock.Unlock()

	if l, ok := conn.(interface{ SetLinger(sec int) error }); ok {
		return l.SetLinger(sec)
	}
	return errors.ErrUnsupported
}

var (
	_ net.Conn                          = (*fastOpenConn)(nil)
	_ interface{ CloseWrite() error }   = (*fastOpenConn)(nil)
	_ interface{ SetLinger(int) error } = (*fastOpenConn)(nil)
)
