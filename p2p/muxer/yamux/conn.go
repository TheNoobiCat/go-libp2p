package yamux

import (
	"context"

	"github.com/TheNoobiCat/go-libp2p/core/network"

	"github.com/libp2p/go-yamux/v5"
)

// conn implements mux.MuxedConn over yamux.Session.
type conn yamux.Session

var _ network.MuxedConn = &conn{}

// NewMuxedConn constructs a new MuxedConn from a yamux.Session.
func NewMuxedConn(m *yamux.Session) network.MuxedConn {
	return (*conn)(m)
}

// Close closes underlying yamux
func (c *conn) Close() error {
	return c.yamux().Close()
}

func (c *conn) CloseWithError(errCode network.ConnErrorCode) error {
	return c.yamux().CloseWithError(uint32(errCode))
}

// IsClosed checks if yamux.Session is in closed state.
func (c *conn) IsClosed() bool {
	return c.yamux().IsClosed()
}

// OpenStream creates a new stream.
func (c *conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	s, err := c.yamux().OpenStream(ctx)
	if err != nil {
		return nil, parseError(err)
	}

	return (*stream)(s), nil
}

// AcceptStream accepts a stream opened by the other side.
func (c *conn) AcceptStream() (network.MuxedStream, error) {
	s, err := c.yamux().AcceptStream()
	return (*stream)(s), parseError(err)
}

func (c *conn) yamux() *yamux.Session {
	return (*yamux.Session)(c)
}
