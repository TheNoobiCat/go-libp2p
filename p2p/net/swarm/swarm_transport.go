package swarm

import (
	"fmt"
	"strings"

	"github.com/TheNoobiCat/go-libp2p/core/peer"
	"github.com/TheNoobiCat/go-libp2p/core/transport"

	ma "github.com/multiformats/go-multiaddr"
)

// TransportForDialing retrieves the appropriate transport for dialing the given
// multiaddr.
func (s *Swarm) TransportForDialing(a ma.Multiaddr) transport.Transport {
	if a == nil {
		return nil
	}
	protocols := a.Protocols()
	if len(protocols) == 0 {
		return nil
	}

	s.transports.RLock()
	defer s.transports.RUnlock()

	if len(s.transports.m) == 0 {
		// make sure we're not just shutting down.
		if s.transports.m != nil {
			log.Error("you have no transports configured")
		}
		return nil
	}
	if isRelayAddr(a) {
		return s.transports.m[ma.P_CIRCUIT]
	}
	if id, _ := peer.IDFromP2PAddr(a); id != "" {
		// This addr has a p2p component. Drop it so we can check transport.
		a, _ = ma.SplitLast(a)
		if a == nil {
			return nil
		}
	}
	for _, t := range s.transports.m {
		if t.CanDial(a) {
			return t
		}
	}
	return nil
}

// TransportForListening retrieves the appropriate transport for listening on
// the given multiaddr.
func (s *Swarm) TransportForListening(a ma.Multiaddr) transport.Transport {
	protocols := a.Protocols()
	if len(protocols) == 0 {
		return nil
	}

	s.transports.RLock()
	defer s.transports.RUnlock()
	if len(s.transports.m) == 0 {
		return nil
	}

	selected := s.transports.m[protocols[len(protocols)-1].Code]
	for _, p := range protocols {
		transport, ok := s.transports.m[p.Code]
		if !ok {
			continue
		}
		if transport.Proxy() {
			selected = transport
		}
	}
	return selected
}

// AddTransport adds a transport to this swarm.
//
// Satisfies the Network interface from go-libp2p-transport.
func (s *Swarm) AddTransport(t transport.Transport) error {
	protocols := t.Protocols()

	if len(protocols) == 0 {
		return fmt.Errorf("useless transport handles no protocols: %T", t)
	}

	s.transports.Lock()
	defer s.transports.Unlock()
	if s.transports.m == nil {
		return ErrSwarmClosed
	}
	var registered []string
	for _, p := range protocols {
		if _, ok := s.transports.m[p]; ok {
			proto := ma.ProtocolWithCode(p)
			name := proto.Name
			if name == "" {
				name = fmt.Sprintf("unknown (%d)", p)
			}
			registered = append(registered, name)
		}
	}
	if len(registered) > 0 {
		return fmt.Errorf(
			"transports already registered for protocol(s): %s",
			strings.Join(registered, ", "),
		)
	}

	for _, p := range protocols {
		s.transports.m[p] = t
	}
	return nil
}
