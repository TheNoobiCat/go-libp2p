package gostream

import (
	"context"
	"net"

	"github.com/TheNoobiCat/go-libp2p/core/host"
	"github.com/TheNoobiCat/go-libp2p/core/network"
	"github.com/TheNoobiCat/go-libp2p/core/protocol"
)

// listener is an implementation of net.Listener which handles
// http-tagged streams from a libp2p connection.
// A listener can be built with Listen()
type listener struct {
	host     host.Host
	ctx      context.Context
	tag      protocol.ID
	cancel   func()
	streamCh chan network.Stream
	// ignoreEOF is a flag that tells the listener to return conns that ignore EOF errors.
	// Necessary because the default responsewriter will consider a connection closed if it reads EOF.
	// But when on streams, it's fine for us to read EOF, but still be able to write.
	ignoreEOF bool
}

// Accept returns the next a connection to this listener.
// It blocks if there are no connections. Under the hood,
// connections are libp2p streams.
func (l *listener) Accept() (net.Conn, error) {
	select {
	case s := <-l.streamCh:
		return newConn(s, l.ignoreEOF), nil
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	}
}

// Close terminates this listener. It will no longer handle any
// incoming streams
func (l *listener) Close() error {
	l.cancel()
	l.host.RemoveStreamHandler(l.tag)
	return nil
}

// Addr returns the address for this listener, which is its libp2p Peer ID.
func (l *listener) Addr() net.Addr {
	return &addr{l.host.ID()}
}

// Listen provides a standard net.Listener ready to accept "connections".
// Under the hood, these connections are libp2p streams tagged with the
// given protocol.ID.
func Listen(h host.Host, tag protocol.ID, opts ...ListenerOption) (net.Listener, error) {
	ctx, cancel := context.WithCancel(context.Background())

	l := &listener{
		host:     h,
		ctx:      ctx,
		cancel:   cancel,
		tag:      tag,
		streamCh: make(chan network.Stream),
	}
	for _, opt := range opts {
		if err := opt(l); err != nil {
			return nil, err
		}
	}

	h.SetStreamHandler(tag, func(s network.Stream) {
		select {
		case l.streamCh <- s:
		case <-ctx.Done():
			s.Reset()
		}
	})

	return l, nil
}

type ListenerOption func(*listener) error

func IgnoreEOF() ListenerOption {
	return func(l *listener) error {
		l.ignoreEOF = true
		return nil
	}
}
