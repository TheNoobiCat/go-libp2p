package pstoremem

import (
	"errors"
	"sync"

	"github.com/TheNoobiCat/go-libp2p/core/peer"
	pstore "github.com/TheNoobiCat/go-libp2p/core/peerstore"
	"github.com/TheNoobiCat/go-libp2p/core/protocol"
)

type protoSegment struct {
	sync.RWMutex
	protocols map[peer.ID]map[protocol.ID]struct{}
}

type protoSegments [256]*protoSegment

func (s *protoSegments) get(p peer.ID) *protoSegment {
	return s[p[len(p)-1]]
}

var errTooManyProtocols = errors.New("too many protocols")

type memoryProtoBook struct {
	segments protoSegments

	maxProtos int
}

var _ pstore.ProtoBook = (*memoryProtoBook)(nil)

type ProtoBookOption func(book *memoryProtoBook) error

func WithMaxProtocols(num int) ProtoBookOption {
	return func(pb *memoryProtoBook) error {
		pb.maxProtos = num
		return nil
	}
}

func NewProtoBook(opts ...ProtoBookOption) (*memoryProtoBook, error) {
	pb := &memoryProtoBook{
		segments: func() (ret protoSegments) {
			for i := range ret {
				ret[i] = &protoSegment{
					protocols: make(map[peer.ID]map[protocol.ID]struct{}),
				}
			}
			return ret
		}(),
		maxProtos: 128,
	}

	for _, opt := range opts {
		if err := opt(pb); err != nil {
			return nil, err
		}
	}
	return pb, nil
}

func (pb *memoryProtoBook) SetProtocols(p peer.ID, protos ...protocol.ID) error {
	if len(protos) > pb.maxProtos {
		return errTooManyProtocols
	}

	newprotos := make(map[protocol.ID]struct{}, len(protos))
	for _, proto := range protos {
		newprotos[proto] = struct{}{}
	}

	s := pb.segments.get(p)
	s.Lock()
	s.protocols[p] = newprotos
	s.Unlock()

	return nil
}

func (pb *memoryProtoBook) AddProtocols(p peer.ID, protos ...protocol.ID) error {
	s := pb.segments.get(p)
	s.Lock()
	defer s.Unlock()

	protomap, ok := s.protocols[p]
	if !ok {
		protomap = make(map[protocol.ID]struct{})
		s.protocols[p] = protomap
	}
	if len(protomap)+len(protos) > pb.maxProtos {
		return errTooManyProtocols
	}

	for _, proto := range protos {
		protomap[proto] = struct{}{}
	}
	return nil
}

func (pb *memoryProtoBook) GetProtocols(p peer.ID) ([]protocol.ID, error) {
	s := pb.segments.get(p)
	s.RLock()
	defer s.RUnlock()

	out := make([]protocol.ID, 0, len(s.protocols[p]))
	for k := range s.protocols[p] {
		out = append(out, k)
	}

	return out, nil
}

func (pb *memoryProtoBook) RemoveProtocols(p peer.ID, protos ...protocol.ID) error {
	s := pb.segments.get(p)
	s.Lock()
	defer s.Unlock()

	protomap, ok := s.protocols[p]
	if !ok {
		// nothing to remove.
		return nil
	}

	for _, proto := range protos {
		delete(protomap, proto)
	}
	if len(protomap) == 0 {
		delete(s.protocols, p)
	}
	return nil
}

func (pb *memoryProtoBook) SupportsProtocols(p peer.ID, protos ...protocol.ID) ([]protocol.ID, error) {
	s := pb.segments.get(p)
	s.RLock()
	defer s.RUnlock()

	out := make([]protocol.ID, 0, len(protos))
	for _, proto := range protos {
		if _, ok := s.protocols[p][proto]; ok {
			out = append(out, proto)
		}
	}

	return out, nil
}

func (pb *memoryProtoBook) FirstSupportedProtocol(p peer.ID, protos ...protocol.ID) (protocol.ID, error) {
	s := pb.segments.get(p)
	s.RLock()
	defer s.RUnlock()

	for _, proto := range protos {
		if _, ok := s.protocols[p][proto]; ok {
			return proto, nil
		}
	}
	return "", nil
}

func (pb *memoryProtoBook) RemovePeer(p peer.ID) {
	s := pb.segments.get(p)
	s.Lock()
	delete(s.protocols, p)
	s.Unlock()
}
