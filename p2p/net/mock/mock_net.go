package mocknet

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"sync"

	ic "github.com/TheNoobiCat/go-libp2p/core/crypto"
	"github.com/TheNoobiCat/go-libp2p/core/host"
	"github.com/TheNoobiCat/go-libp2p/core/network"
	"github.com/TheNoobiCat/go-libp2p/core/peer"
	"github.com/TheNoobiCat/go-libp2p/core/peerstore"
	bhost "github.com/TheNoobiCat/go-libp2p/p2p/host/basic"
	"github.com/TheNoobiCat/go-libp2p/p2p/host/eventbus"
	"github.com/TheNoobiCat/go-libp2p/p2p/host/peerstore/pstoremem"

	ma "github.com/multiformats/go-multiaddr"
)

// IP6 range that gets blackholed (in case our traffic ever makes it out onto
// the internet).
var blackholeIP6 = net.ParseIP("100::")

// mocknet implements mocknet.Mocknet
type mocknet struct {
	nets  map[peer.ID]*peernet
	hosts map[peer.ID]host.Host

	// links make it possible to connect two peers.
	// think of links as the physical medium.
	// usually only one, but there could be multiple
	// **links are shared between peers**
	links map[peer.ID]map[peer.ID]map[*link]struct{}

	linkDefaults LinkOptions

	ctxCancel context.CancelFunc
	ctx       context.Context
	sync.Mutex
}

func New() Mocknet {
	mn := &mocknet{
		nets:  map[peer.ID]*peernet{},
		hosts: map[peer.ID]host.Host{},
		links: map[peer.ID]map[peer.ID]map[*link]struct{}{},
	}
	mn.ctx, mn.ctxCancel = context.WithCancel(context.Background())
	return mn
}

func (mn *mocknet) Close() error {
	mn.ctxCancel()
	for _, h := range mn.hosts {
		h.Close()
	}
	for _, n := range mn.nets {
		n.Close()
	}
	return nil
}

func (mn *mocknet) GenPeer() (host.Host, error) {
	return mn.GenPeerWithOptions(PeerOptions{})
}

func (mn *mocknet) GenPeerWithOptions(opts PeerOptions) (host.Host, error) {
	if err := mn.addDefaults(&opts); err != nil {
		return nil, err
	}
	sk, _, err := ic.GenerateECDSAKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}
	id, err := peer.IDFromPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	suffix := id
	if len(id) > 8 {
		suffix = id[len(id)-8:]
	}
	ip := append(net.IP{}, blackholeIP6...)
	copy(ip[net.IPv6len-len(suffix):], suffix)
	a, err := ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/tcp/4242", ip))
	if err != nil {
		return nil, fmt.Errorf("failed to create test multiaddr: %s", err)
	}

	var ps peerstore.Peerstore
	if opts.ps == nil {
		ps, err = pstoremem.NewPeerstore()
		if err != nil {
			return nil, err
		}
	} else {
		ps = opts.ps
	}
	p, err := mn.updatePeerstore(sk, a, ps)
	if err != nil {
		return nil, err
	}
	h, err := mn.AddPeerWithOptions(p, opts)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (mn *mocknet) AddPeer(k ic.PrivKey, a ma.Multiaddr) (host.Host, error) {
	ps, err := pstoremem.NewPeerstore()
	if err != nil {
		return nil, err
	}
	p, err := mn.updatePeerstore(k, a, ps)
	if err != nil {
		return nil, err
	}

	return mn.AddPeerWithPeerstore(p, ps)
}

func (mn *mocknet) AddPeerWithPeerstore(p peer.ID, ps peerstore.Peerstore) (host.Host, error) {
	return mn.AddPeerWithOptions(p, PeerOptions{ps: ps})
}

func (mn *mocknet) AddPeerWithOptions(p peer.ID, opts PeerOptions) (host.Host, error) {
	bus := eventbus.NewBus()
	if err := mn.addDefaults(&opts); err != nil {
		return nil, err
	}
	n, err := newPeernet(mn, p, opts, bus)
	if err != nil {
		return nil, err
	}

	hostOpts := &bhost.HostOpts{
		NegotiationTimeout:      -1,
		DisableSignedPeerRecord: true,
		EventBus:                bus,
	}

	h, err := bhost.NewHost(n, hostOpts)
	if err != nil {
		return nil, err
	}
	h.Start()

	mn.Lock()
	mn.nets[n.peer] = n
	mn.hosts[n.peer] = h
	mn.Unlock()
	return h, nil
}

func (mn *mocknet) addDefaults(opts *PeerOptions) error {
	if opts.ps == nil {
		ps, err := pstoremem.NewPeerstore()
		if err != nil {
			return err
		}
		opts.ps = ps
	}
	return nil
}

func (mn *mocknet) updatePeerstore(k ic.PrivKey, a ma.Multiaddr, ps peerstore.Peerstore) (peer.ID, error) {
	p, err := peer.IDFromPublicKey(k.GetPublic())
	if err != nil {
		return "", err
	}

	ps.AddAddr(p, a, peerstore.PermanentAddrTTL)
	err = ps.AddPrivKey(p, k)
	if err != nil {
		return "", err
	}
	err = ps.AddPubKey(p, k.GetPublic())
	if err != nil {
		return "", err
	}
	return p, nil
}

func (mn *mocknet) Peers() []peer.ID {
	mn.Lock()
	defer mn.Unlock()

	cp := make([]peer.ID, 0, len(mn.nets))
	for _, n := range mn.nets {
		cp = append(cp, n.peer)
	}
	sort.Sort(peer.IDSlice(cp))
	return cp
}

func (mn *mocknet) Host(pid peer.ID) host.Host {
	mn.Lock()
	host := mn.hosts[pid]
	mn.Unlock()
	return host
}

func (mn *mocknet) Net(pid peer.ID) network.Network {
	mn.Lock()
	n := mn.nets[pid]
	mn.Unlock()
	return n
}

func (mn *mocknet) Hosts() []host.Host {
	mn.Lock()
	defer mn.Unlock()

	cp := make([]host.Host, 0, len(mn.hosts))
	for _, h := range mn.hosts {
		cp = append(cp, h)
	}

	sort.Sort(hostSlice(cp))
	return cp
}

func (mn *mocknet) Nets() []network.Network {
	mn.Lock()
	defer mn.Unlock()

	cp := make([]network.Network, 0, len(mn.nets))
	for _, n := range mn.nets {
		cp = append(cp, n)
	}
	sort.Sort(netSlice(cp))
	return cp
}

// Links returns a copy of the internal link state map.
// (wow, much map. so data structure. how compose. ahhh pointer)
func (mn *mocknet) Links() LinkMap {
	mn.Lock()
	defer mn.Unlock()

	links := map[string]map[string]map[Link]struct{}{}
	for p1, lm := range mn.links {
		sp1 := string(p1)
		links[sp1] = map[string]map[Link]struct{}{}
		for p2, ls := range lm {
			sp2 := string(p2)
			links[sp1][sp2] = map[Link]struct{}{}
			for l := range ls {
				links[sp1][sp2][l] = struct{}{}
			}
		}
	}
	return links
}

func (mn *mocknet) LinkAll() error {
	nets := mn.Nets()
	for _, n1 := range nets {
		for _, n2 := range nets {
			if _, err := mn.LinkNets(n1, n2); err != nil {
				return err
			}
		}
	}
	return nil
}

func (mn *mocknet) LinkPeers(p1, p2 peer.ID) (Link, error) {
	mn.Lock()
	n1 := mn.nets[p1]
	n2 := mn.nets[p2]
	mn.Unlock()

	if n1 == nil {
		return nil, fmt.Errorf("network for p1 not in mocknet")
	}

	if n2 == nil {
		return nil, fmt.Errorf("network for p2 not in mocknet")
	}

	return mn.LinkNets(n1, n2)
}

func (mn *mocknet) validate(n network.Network) (*peernet, error) {
	// WARNING: assumes locks acquired

	nr, ok := n.(*peernet)
	if !ok {
		return nil, fmt.Errorf("network not supported (use mock package nets only)")
	}

	if _, found := mn.nets[nr.peer]; !found {
		return nil, fmt.Errorf("network not on mocknet. is it from another mocknet?")
	}

	return nr, nil
}

func (mn *mocknet) LinkNets(n1, n2 network.Network) (Link, error) {
	mn.Lock()
	n1r, err1 := mn.validate(n1)
	n2r, err2 := mn.validate(n2)
	ld := mn.linkDefaults
	mn.Unlock()

	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	l := newLink(mn, ld)
	l.nets = append(l.nets, n1r, n2r)
	mn.addLink(l)
	return l, nil
}

func (mn *mocknet) Unlink(l2 Link) error {

	l, ok := l2.(*link)
	if !ok {
		return fmt.Errorf("only links from mocknet are supported")
	}

	mn.removeLink(l)
	return nil
}

func (mn *mocknet) UnlinkPeers(p1, p2 peer.ID) error {
	ls := mn.LinksBetweenPeers(p1, p2)
	if ls == nil {
		return fmt.Errorf("no link between p1 and p2")
	}

	for _, l := range ls {
		if err := mn.Unlink(l); err != nil {
			return err
		}
	}
	return nil
}

func (mn *mocknet) UnlinkNets(n1, n2 network.Network) error {
	return mn.UnlinkPeers(n1.LocalPeer(), n2.LocalPeer())
}

// get from the links map. and lazily construct.
func (mn *mocknet) linksMapGet(p1, p2 peer.ID) map[*link]struct{} {

	l1, found := mn.links[p1]
	if !found {
		mn.links[p1] = map[peer.ID]map[*link]struct{}{}
		l1 = mn.links[p1] // so we make sure it's there.
	}

	l2, found := l1[p2]
	if !found {
		m := map[*link]struct{}{}
		l1[p2] = m
		l2 = l1[p2]
	}

	return l2
}

func (mn *mocknet) addLink(l *link) {
	mn.Lock()
	defer mn.Unlock()

	n1, n2 := l.nets[0], l.nets[1]
	mn.linksMapGet(n1.peer, n2.peer)[l] = struct{}{}
	mn.linksMapGet(n2.peer, n1.peer)[l] = struct{}{}
}

func (mn *mocknet) removeLink(l *link) {
	mn.Lock()
	defer mn.Unlock()

	n1, n2 := l.nets[0], l.nets[1]
	delete(mn.linksMapGet(n1.peer, n2.peer), l)
	delete(mn.linksMapGet(n2.peer, n1.peer), l)
}

func (mn *mocknet) ConnectAllButSelf() error {
	nets := mn.Nets()
	for _, n1 := range nets {
		for _, n2 := range nets {
			if n1 == n2 {
				continue
			}

			if _, err := mn.ConnectNets(n1, n2); err != nil {
				return err
			}
		}
	}
	return nil
}

func (mn *mocknet) ConnectPeers(a, b peer.ID) (network.Conn, error) {
	return mn.Net(a).DialPeer(mn.ctx, b)
}

func (mn *mocknet) ConnectNets(a, b network.Network) (network.Conn, error) {
	return a.DialPeer(mn.ctx, b.LocalPeer())
}

func (mn *mocknet) DisconnectPeers(p1, p2 peer.ID) error {
	return mn.Net(p1).ClosePeer(p2)
}

func (mn *mocknet) DisconnectNets(n1, n2 network.Network) error {
	return n1.ClosePeer(n2.LocalPeer())
}

func (mn *mocknet) LinksBetweenPeers(p1, p2 peer.ID) []Link {
	mn.Lock()
	defer mn.Unlock()

	ls2 := mn.linksMapGet(p1, p2)
	cp := make([]Link, 0, len(ls2))
	for l := range ls2 {
		cp = append(cp, l)
	}
	return cp
}

func (mn *mocknet) LinksBetweenNets(n1, n2 network.Network) []Link {
	return mn.LinksBetweenPeers(n1.LocalPeer(), n2.LocalPeer())
}

func (mn *mocknet) SetLinkDefaults(o LinkOptions) {
	mn.Lock()
	mn.linkDefaults = o
	mn.Unlock()
}

func (mn *mocknet) LinkDefaults() LinkOptions {
	mn.Lock()
	defer mn.Unlock()
	return mn.linkDefaults
}

// netSlice for sorting by peer
type netSlice []network.Network

func (es netSlice) Len() int           { return len(es) }
func (es netSlice) Swap(i, j int)      { es[i], es[j] = es[j], es[i] }
func (es netSlice) Less(i, j int) bool { return string(es[i].LocalPeer()) < string(es[j].LocalPeer()) }

// hostSlice for sorting by peer
type hostSlice []host.Host

func (es hostSlice) Len() int           { return len(es) }
func (es hostSlice) Swap(i, j int)      { es[i], es[j] = es[j], es[i] }
func (es hostSlice) Less(i, j int) bool { return string(es[i].ID()) < string(es[j].ID()) }
