package tailnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/key"
	tslogger "tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func init() {
	netns.SetEnabled(false)
}

// Options configures a WireGuard connection.
type Options struct {
	ID        uuid.UUID
	Addresses []netip.Prefix
	DERPMap   *tailcfg.DERPMap
	Logger    *slog.Logger
}

// Conn wraps a Tailscale WireGuard engine + netstack to provide net.Listener
// and DialContextTCP over WireGuard.
type Conn struct {
	mu     sync.Mutex
	closed chan struct{}

	id        uuid.UUID
	nodeKey   key.NodePrivate
	discoKey  key.DiscoPublic
	addrs     []netip.Prefix
	logger    *slog.Logger

	sys       *tsd.System
	lb        *ipnlocal.LocalBackend
	engine    wgengine.Engine
	magicConn *magicsock.Conn
	netStack  *netstack.Impl
	netMon    *netmon.Monitor
	dialer    *tsdial.Dialer
	listeners map[listenKey]*listener

	// Node tracking
	preferredDERP int
	endpoints     []netip.AddrPort
	derpLatency   map[string]float64
	nodeCb        func(*Node)
}

// NodeID creates a tailcfg.NodeID from a UUID.
func NodeID(uid uuid.UUID) tailcfg.NodeID {
	id := int64(binary.BigEndian.Uint64(uid[8:]))
	y := id >> 63
	id = (id ^ y) - y
	return tailcfg.NodeID(id)
}

// NewConn creates a new WireGuard connection.
func NewConn(opts *Options) (*Conn, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	nodePrivKey := key.NewNode()

	logf := tslogger.Logf(func(format string, args ...any) {
		opts.Logger.Debug(fmt.Sprintf(format, args...))
	})

	sys := tsd.NewSystem()

	netMon, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, fmt.Errorf("netmon: %w", err)
	}

	dialer := &tsdial.Dialer{Logf: logf}

	engine, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		NetMon:        netMon,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      sys.Bus.Get(),
	})
	if err != nil {
		netMon.Close()
		return nil, fmt.Errorf("wgengine: %w", err)
	}

	engine = wgengine.NewWatchdog(engine)
	sys.Set(engine)
	sys.Set(new(mem.Store))

	mc := sys.MagicSock.Get()
	if err := mc.SetPrivateKey(nodePrivKey); err != nil {
		engine.Close()
		netMon.Close()
		return nil, fmt.Errorf("set private key: %w", err)
	}

	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := engine.PeerForIP(ip)
		return ok
	}

	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		engine.Close()
		netMon.Close()
		return nil, fmt.Errorf("local backend: %w", err)
	}

	ns, err := netstack.Create(
		logf,
		sys.Tun.Get(),
		engine,
		mc,
		dialer,
		sys.DNSManager.Get(),
		sys.ProxyMapper(),
	)
	if err != nil {
		lb.Shutdown()
		engine.Close()
		netMon.Close()
		return nil, fmt.Errorf("netstack: %w", err)
	}

	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}
	ns.ProcessLocalIPs = true

	if err := ns.Start(lb); err != nil {
		lb.Shutdown()
		engine.Close()
		netMon.Close()
		return nil, fmt.Errorf("netstack start: %w", err)
	}

	c := &Conn{
		closed:    make(chan struct{}),
		id:        opts.ID,
		nodeKey:   nodePrivKey,
		discoKey:  mc.DiscoPublicKey(),
		addrs:     opts.Addresses,
		logger:    opts.Logger,
		sys:       sys,
		lb:        lb,
		engine:    engine,
		magicConn: mc,
		netStack:  ns,
		netMon:    netMon,
		dialer:    dialer,
		listeners: make(map[listenKey]*listener),
	}

	// Track endpoint and DERP changes via magicsock callbacks.
	mc.SetNetInfoCallback(func(ni *tailcfg.NetInfo) {
		c.mu.Lock()
		c.preferredDERP = ni.PreferredDERP
		c.derpLatency = ni.DERPLatency
		cb := c.nodeCb
		c.mu.Unlock()
		if cb != nil {
			cb(c.Node())
		}
	})
	engine.SetStatusCallback(func(s *wgengine.Status, err error) {
		if err != nil {
			return
		}
		eps := make([]netip.AddrPort, len(s.LocalAddrs))
		for i, ep := range s.LocalAddrs {
			eps[i] = ep.Addr
		}
		c.mu.Lock()
		c.endpoints = eps
		cb := c.nodeCb
		c.mu.Unlock()
		if cb != nil {
			cb(c.Node())
		}
	})

	// Apply initial config.
	c.applyNetworkMap(nil)
	if opts.DERPMap != nil {
		mc.SetDERPMap(opts.DERPMap)
	}

	return c, nil
}

// SetNodeCallback sets a callback invoked when local node info changes.
func (c *Conn) SetNodeCallback(cb func(*Node)) {
	c.mu.Lock()
	c.nodeCb = cb
	c.mu.Unlock()
	if cb != nil {
		cb(c.Node())
	}
}

// SetDERPMap updates the DERP map.
func (c *Conn) SetDERPMap(dm *tailcfg.DERPMap) {
	c.magicConn.SetDERPMap(dm)
}

// UpdatePeers configures the WireGuard engine with the given peer nodes.
func (c *Conn) UpdatePeers(peers []*Node) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return fmt.Errorf("conn closed")
	default:
	}
	c.applyNetworkMap(peers)
	return nil
}

func (c *Conn) applyNetworkMap(peers []*Node) {
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:        NodeID(c.id),
			Key:       c.nodeKey.Public(),
			Addresses: c.addrs,
		}).View(),
		NodeKey: c.nodeKey.Public(),
	}

	for _, p := range peers {
		node := &tailcfg.Node{
			ID:         NodeID(p.ID),
			Key:        p.Key,
			DiscoKey:   p.DiscoKey,
			Addresses:  p.Addresses,
			AllowedIPs: p.Addresses,
			Endpoints:  p.Endpoints,
			HomeDERP:   p.PreferredDERP,
		}
		nm.Peers = append(nm.Peers, node.View())
	}

	c.engine.SetNetworkMap(nm)
	if err := c.engine.Reconfig(nmToCfg(nm), &router.Config{LocalAddrs: c.addrs}, &dns.Config{}); err != nil {
		c.logger.Warn("reconfig failed", "error", err)
	}
}

// Listen returns a net.Listener on the tailnet address.
func (c *Conn) Listen(network, addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	lk := listenKey{network, host, port}
	ln := &listener{
		s:      c,
		key:    lk,
		addr:   addr,
		closed: make(chan struct{}),
		conn:   make(chan net.Conn),
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, fmt.Errorf("conn closed")
	default:
	}
	if _, ok := c.listeners[lk]; ok {
		c.mu.Unlock()
		return nil, fmt.Errorf("listener already open for %s %s", network, addr)
	}
	c.listeners[lk] = ln
	c.mu.Unlock()

	// Register TCP forwarding for this listener.
	c.netStack.GetTCPHandlerForFlow = c.forwardTCP
	return ln, nil
}

// DialContextTCP dials a TCP connection over the WireGuard tunnel.
func (c *Conn) DialContextTCP(ctx context.Context, dst netip.AddrPort) (*gonet.TCPConn, error) {
	return c.netStack.DialContextTCP(ctx, dst)
}

// Node returns the current node info for coordination.
func (c *Conn) Node() *Node {
	c.mu.Lock()
	defer c.mu.Unlock()
	derp := c.preferredDERP
	if derp == 0 {
		derp = 1
	}
	return &Node{
		ID:            c.id,
		AsOf:          time.Now(),
		Key:           c.nodeKey.Public(),
		DiscoKey:      c.discoKey,
		PreferredDERP: derp,
		Endpoints:     append([]netip.AddrPort(nil), c.endpoints...),
		Addresses:     append([]netip.Prefix(nil), c.addrs...),
	}
}

// Close shuts down the WireGuard engine.
func (c *Conn) Close() error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
	}
	close(c.closed)
	for _, l := range c.listeners {
		_ = l.closeNoLock()
	}
	c.listeners = nil
	c.mu.Unlock()

	_ = c.netStack.Close()
	c.lb.Shutdown()
	_ = c.netMon.Close()
	_ = c.dialer.Close()
	c.engine.Close()
	return nil
}

func (c *Conn) forwardTCP(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
	c.mu.Lock()
	ln, ok := c.listeners[listenKey{"tcp", "", fmt.Sprint(dst.Port())}]
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	return func(conn net.Conn) {
		t := time.NewTimer(time.Second)
		defer t.Stop()
		select {
		case ln.conn <- conn:
		case <-ln.closed:
			conn.Close()
		case <-c.closed:
			conn.Close()
		case <-t.C:
			conn.Close()
		}
	}, true
}

func nmToCfg(nm *netmap.NetworkMap) *wgcfg.Config {
	cfg := &wgcfg.Config{}
	for _, pv := range nm.Peers {
		pcfg := wgcfg.Peer{
			PublicKey: pv.Key(),
			DiscoKey:  pv.DiscoKey(),
		}
		for _, a := range pv.AllowedIPs().All() {
			pcfg.AllowedIPs = append(pcfg.AllowedIPs, a)
		}
		cfg.Peers = append(cfg.Peers, pcfg)
	}
	return cfg
}

// listenKey + listener: identical to Coder's pattern for tailnet TCP listeners.
type listenKey struct {
	network string
	host    string
	port    string
}

type listener struct {
	s      *Conn
	key    listenKey
	addr   string
	conn   chan net.Conn
	closed chan struct{}
}

func (ln *listener) Accept() (net.Conn, error) {
	select {
	case c := <-ln.conn:
		return c, nil
	case <-ln.closed:
		return nil, net.ErrClosed
	}
}

func (ln *listener) Addr() net.Addr { return lnAddr{ln.addr} }

func (ln *listener) Close() error {
	ln.s.mu.Lock()
	defer ln.s.mu.Unlock()
	return ln.closeNoLock()
}

func (ln *listener) closeNoLock() error {
	if v, ok := ln.s.listeners[ln.key]; ok && v == ln {
		delete(ln.s.listeners, ln.key)
		close(ln.closed)
	}
	return nil
}

type lnAddr struct{ s string }

func (a lnAddr) Network() string { return "tcp" }
func (a lnAddr) String() string  { return a.s }
