// Package websocket implements a websocket based transport for go-libp2p.
package websocket

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/TheNoobiCat/go-libp2p/core/network"
	"github.com/TheNoobiCat/go-libp2p/core/peer"
	"github.com/TheNoobiCat/go-libp2p/core/transport"
	"github.com/TheNoobiCat/go-libp2p/p2p/transport/tcpreuse"

	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"

	ws "github.com/gorilla/websocket"
)

// WsFmt is multiaddr formatter for WsProtocol
var WsFmt = mafmt.And(mafmt.TCP, mafmt.Base(ma.P_WS))

var dialMatcher = mafmt.And(
	mafmt.Or(mafmt.IP, mafmt.DNS),
	mafmt.Base(ma.P_TCP),
	mafmt.Or(
		mafmt.Base(ma.P_WS),
		mafmt.And(
			mafmt.Or(
				mafmt.And(
					mafmt.Base(ma.P_TLS),
					mafmt.Base(ma.P_SNI)),
				mafmt.Base(ma.P_TLS),
			),
			mafmt.Base(ma.P_WS)),
		mafmt.Base(ma.P_WSS)))

var (
	wssComponent, _ = ma.NewComponent("wss", "")
	tlsComponent, _ = ma.NewComponent("tls", "")
	wsComponent, _  = ma.NewComponent("ws", "")
	tlsWsAddr       = ma.Multiaddr{*tlsComponent, *wsComponent}
)

func init() {
	manet.RegisterFromNetAddr(ParseWebsocketNetAddr, "websocket")
	manet.RegisterToNetAddr(ConvertWebsocketMultiaddrToNetAddr, "ws")
	manet.RegisterToNetAddr(ConvertWebsocketMultiaddrToNetAddr, "wss")
}

type Option func(*WebsocketTransport) error

// WithTLSClientConfig sets a TLS client configuration on the WebSocket Dialer. Only
// relevant for non-browser usages.
//
// Some useful use cases include setting InsecureSkipVerify to `true`, or
// setting user-defined trusted CA certificates.
func WithTLSClientConfig(c *tls.Config) Option {
	return func(t *WebsocketTransport) error {
		t.tlsClientConf = c
		return nil
	}
}

// WithTLSConfig sets a TLS configuration for the WebSocket listener.
func WithTLSConfig(conf *tls.Config) Option {
	return func(t *WebsocketTransport) error {
		t.tlsConf = conf
		return nil
	}
}

var defaultHandshakeTimeout = 15 * time.Second

// WithHandshakeTimeout sets a timeout for the websocket upgrade.
func WithHandshakeTimeout(timeout time.Duration) Option {
	return func(t *WebsocketTransport) error {
		t.handshakeTimeout = timeout
		return nil
	}
}

// WebsocketTransport is the actual go-libp2p transport
type WebsocketTransport struct {
	upgrader         transport.Upgrader
	rcmgr            network.ResourceManager
	tlsClientConf    *tls.Config
	tlsConf          *tls.Config
	sharedTcp        *tcpreuse.ConnMgr
	handshakeTimeout time.Duration
}

var _ transport.Transport = (*WebsocketTransport)(nil)

func New(u transport.Upgrader, rcmgr network.ResourceManager, sharedTCP *tcpreuse.ConnMgr, opts ...Option) (*WebsocketTransport, error) {
	if rcmgr == nil {
		rcmgr = &network.NullResourceManager{}
	}
	t := &WebsocketTransport{
		upgrader:         u,
		rcmgr:            rcmgr,
		tlsClientConf:    &tls.Config{},
		sharedTcp:        sharedTCP,
		handshakeTimeout: defaultHandshakeTimeout,
	}
	for _, opt := range opts {
		if err := opt(t); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *WebsocketTransport) CanDial(a ma.Multiaddr) bool {
	return dialMatcher.Matches(a)
}

func (t *WebsocketTransport) Protocols() []int {
	return []int{ma.P_WS, ma.P_WSS}
}

func (t *WebsocketTransport) Proxy() bool {
	return false
}

func (t *WebsocketTransport) Resolve(_ context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	parsed, err := parseWebsocketMultiaddr(maddr)
	if err != nil {
		return nil, err
	}

	if !parsed.isWSS {
		// No /tls/ws component, this isn't a secure websocket multiaddr. We can just return it here
		return []ma.Multiaddr{maddr}, nil
	}

	if parsed.sni == nil {
		var err error
		// We don't have an sni component, we'll use dns
	loop:
		for _, c := range parsed.restMultiaddr {
			switch c.Protocol().Code {
			case ma.P_DNS, ma.P_DNS4, ma.P_DNS6:
				// err shouldn't happen since this means we couldn't parse a dns hostname for an sni value.
				parsed.sni, err = ma.NewComponent("sni", c.Value())
				break loop
			}
		}
		if err != nil {
			return nil, err
		}
	}

	if parsed.sni == nil {
		// we didn't find anything to set the sni with. So we just return the given multiaddr
		return []ma.Multiaddr{maddr}, nil
	}

	return []ma.Multiaddr{parsed.toMultiaddr()}, nil
}

// Dial will dial the given multiaddr and expect the given peer. If an
// HTTPS_PROXY env is set, it will use that for the dial out.
func (t *WebsocketTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	connScope, err := t.rcmgr.OpenConnection(network.DirOutbound, true, raddr)
	if err != nil {
		return nil, err
	}
	c, err := t.dialWithScope(ctx, raddr, p, connScope)
	if err != nil {
		connScope.Done()
		return nil, err
	}
	return c, nil
}

func (t *WebsocketTransport) dialWithScope(ctx context.Context, raddr ma.Multiaddr, p peer.ID, connScope network.ConnManagementScope) (transport.CapableConn, error) {
	macon, err := t.maDial(ctx, raddr, connScope)
	if err != nil {
		return nil, err
	}
	conn, err := t.upgrader.Upgrade(ctx, t, macon, network.DirOutbound, p, connScope)
	if err != nil {
		return nil, err
	}
	return &capableConn{CapableConn: conn}, nil
}

func (t *WebsocketTransport) maDial(ctx context.Context, raddr ma.Multiaddr, scope network.ConnManagementScope) (manet.Conn, error) {
	wsurl, err := parseMultiaddr(raddr)
	if err != nil {
		return nil, err
	}
	isWss := wsurl.Scheme == "wss"
	dialer := ws.Dialer{
		HandshakeTimeout: t.handshakeTimeout,
		// Inherit the default proxy behavior
		Proxy: ws.DefaultDialer.Proxy,
	}
	if isWss {
		sni := ""
		sni, err = raddr.ValueForProtocol(ma.P_SNI)
		if err != nil {
			sni = ""
		}

		if sni != "" {
			copytlsClientConf := t.tlsClientConf.Clone()
			copytlsClientConf.ServerName = sni
			dialer.TLSClientConfig = copytlsClientConf
			ipPortAddr := wsurl.Host
			// We set the `.Host` to the sni field so that the host header gets properly set.
			wsurl.Host = sni + ":" + wsurl.Port()
			// Setting the NetDial because we already have the resolved IP address, so we can avoid another resolution.
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				var tcpAddr *net.TCPAddr
				var err error
				if address == wsurl.Host {
					tcpAddr, err = net.ResolveTCPAddr(network, ipPortAddr) // Use our already resolved IP address
				} else {
					tcpAddr, err = net.ResolveTCPAddr(network, address)
				}
				if err != nil {
					return nil, err
				}
				return net.DialTCP("tcp", nil, tcpAddr)
			}
		} else {
			dialer.TLSClientConfig = t.tlsClientConf
		}
	}

	wscon, _, err := dialer.DialContext(ctx, wsurl.String(), nil)
	if err != nil {
		return nil, err
	}

	mnc, err := manet.WrapNetConn(newConn(wscon, isWss, scope))
	if err != nil {
		wscon.Close()
		return nil, err
	}
	return mnc, nil
}

func (t *WebsocketTransport) gatedMaListen(a ma.Multiaddr) (transport.GatedMaListener, error) {
	var tlsConf *tls.Config
	if t.tlsConf != nil {
		tlsConf = t.tlsConf.Clone()
	}
	l, err := newListener(a, tlsConf, t.sharedTcp, t.upgrader, t.handshakeTimeout)
	if err != nil {
		return nil, err
	}
	go l.serve()
	return l, nil
}

func (t *WebsocketTransport) Listen(a ma.Multiaddr) (transport.Listener, error) {
	gmal, err := t.gatedMaListen(a)
	if err != nil {
		return nil, err
	}
	return &transportListener{Listener: t.upgrader.UpgradeGatedMaListener(t, gmal)}, nil
}

// transportListener wraps a transport.Listener to provide connections with a `ConnState() network.ConnectionState` method.
type transportListener struct {
	transport.Listener
}

type capableConn struct {
	transport.CapableConn
}

func (c *capableConn) ConnState() network.ConnectionState {
	cs := c.CapableConn.ConnState()
	cs.Transport = "websocket"
	return cs
}

func (l *transportListener) Accept() (transport.CapableConn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &capableConn{CapableConn: conn}, nil
}
