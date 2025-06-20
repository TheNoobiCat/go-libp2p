package libp2p

import (
	"github.com/TheNoobiCat/go-libp2p/config"
	"github.com/TheNoobiCat/go-libp2p/core/host"
)

// Config describes a set of settings for a libp2p node.
type Config = config.Config

// Option is a libp2p config option that can be given to the libp2p constructor
// (`libp2p.New`).
type Option = config.Option

// ChainOptions chains multiple options into a single option.
func ChainOptions(opts ...Option) Option {
	return func(cfg *Config) error {
		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(cfg); err != nil {
				return err
			}
		}
		return nil
	}
}

// New constructs a new libp2p node with the given options, falling back on
// reasonable defaults. The defaults are:
//
// - If no transport and listen addresses are provided, the node listens to
// the multiaddresses "/ip4/0.0.0.0/tcp/0" and "/ip6/::/tcp/0";
//
// - If no transport options are provided, the node uses TCP, websocket and QUIC
// transport protocols;
//
// - If no multiplexer configuration is provided, the node is configured by
// default to use yamux;
//
// - If no security transport is provided, the host uses the go-libp2p's noise
// and/or tls encrypted transport to encrypt all traffic;
//
// - If no peer identity is provided, it generates a random Ed25519 key-pair
// and derives a new identity from it;
//
// - If no peerstore is provided, the host is initialized with an empty
// peerstore.
//
// To stop/shutdown the returned libp2p node, the user needs to call `Close` on the returned Host.
func New(opts ...Option) (host.Host, error) {
	return NewWithoutDefaults(append(opts, FallbackDefaults)...)
}

// NewWithoutDefaults constructs a new libp2p node with the given options but
// *without* falling back on reasonable defaults.
//
// Warning: This function should not be considered a stable interface. We may
// choose to add required services at any time and, by using this function, you
// opt-out of any defaults we may provide.
func NewWithoutDefaults(opts ...Option) (host.Host, error) {
	var cfg Config
	if err := cfg.Apply(opts...); err != nil {
		return nil, err
	}
	return cfg.NewNode()
}
