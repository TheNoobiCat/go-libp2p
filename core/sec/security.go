// Package sec provides secure connection and transport interfaces for libp2p.
package sec

import (
	"context"
	"fmt"
	"net"

	"github.com/TheNoobiCat/go-libp2p/core/network"
	"github.com/TheNoobiCat/go-libp2p/core/peer"
	"github.com/TheNoobiCat/go-libp2p/core/protocol"
)

// SecureConn is an authenticated, encrypted connection.
type SecureConn interface {
	net.Conn
	network.ConnSecurity
}

// A SecureTransport turns inbound and outbound unauthenticated,
// plain-text, native connections into authenticated, encrypted connections.
type SecureTransport interface {
	// SecureInbound secures an inbound connection.
	// If p is empty, connections from any peer are accepted.
	SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (SecureConn, error)

	// SecureOutbound secures an outbound connection.
	SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (SecureConn, error)

	// ID is the protocol ID of the security protocol.
	ID() protocol.ID
}

type ErrPeerIDMismatch struct {
	Expected peer.ID
	Actual   peer.ID
}

func (e ErrPeerIDMismatch) Error() string {
	return fmt.Sprintf("peer id mismatch: expected %s, but remote key matches %s", e.Expected, e.Actual)
}

var _ error = (*ErrPeerIDMismatch)(nil)
