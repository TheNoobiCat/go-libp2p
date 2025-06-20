package autonat

import (
	"context"
	"io"

	"github.com/TheNoobiCat/go-libp2p/core/network"
	"github.com/TheNoobiCat/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// AutoNAT is the interface for NAT autodiscovery
type AutoNAT interface {
	// Status returns the current NAT status
	Status() network.Reachability
	io.Closer
}

// Client is a stateless client interface to AutoNAT peers
type Client interface {
	// DialBack requests from a peer providing AutoNAT services to test dial back
	// and report the address on a successful connection.
	DialBack(ctx context.Context, p peer.ID) error
}

// AddrFunc is a function returning the candidate addresses for the local host.
type AddrFunc func() []ma.Multiaddr

// Option is an Autonat option for configuration
type Option func(*config) error
