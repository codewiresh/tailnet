package tailnet

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// NewDERPServer creates an embedded DERP relay server.
func NewDERPServer() *derpserver.Server {
	logf := func(format string, args ...any) {
		log.Printf("[derp-server] "+format, args...)
	}
	return derpserver.New(key.NewNode(), logf)
}

// DERPHandler returns an HTTP handler for the DERP server with WebSocket support.
// Mount at /derp on the chi router.
func DERPHandler(srv *derpserver.Server) (http.Handler, func()) {
	baseHandler := derpserver.Handler(srv)
	return WithWebsocketSupport(srv, baseHandler)
}

// WithWebsocketSupport upgrades WebSocket connections with the "derp" subprotocol
// and passes them to the DERP server. Falls back to the base handler for non-WS.
// Adapted from Coder's tailnet/derp.go.
func WithWebsocketSupport(s *derpserver.Server, base http.Handler) (http.Handler, func()) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			up := strings.ToLower(r.Header.Get("Upgrade"))
			if up != "websocket" || !strings.Contains(r.Header.Get("Sec-Websocket-Protocol"), "derp") {
				base.ServeHTTP(w, r)
				return
			}

			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				return
			}
			wg.Add(1)
			mu.Unlock()
			defer wg.Done()

			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
				Subprotocols:    []string{"derp"},
				OriginPatterns:  []string{"*"},
				CompressionMode: websocket.CompressionDisabled,
			})
			if err != nil {
				log.Printf("derp websocket accept error: remote=%s err=%v", r.RemoteAddr, err)
				return
			}
			defer c.Close(websocket.StatusInternalError, "closing")

			if c.Subprotocol() != "derp" {
				c.Close(websocket.StatusPolicyViolation, "client must speak the derp subprotocol")
				return
			}

			log.Printf("derp websocket accepted: remote=%s subproto=%s", r.RemoteAddr, c.Subprotocol())
			wc := websocket.NetConn(ctx, c, websocket.MessageBinary)
			brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
			s.Accept(ctx, wc, brw, r.RemoteAddr)
			log.Printf("derp session ended: remote=%s", r.RemoteAddr)
		}), func() {
			cancel()
			mu.Lock()
			wg.Wait()
			mu.Unlock()
		}
}

// DefaultSTUNServers are public STUN servers used for NAT traversal.
// These enable direct WireGuard peering by letting peers discover their
// public IP:port. The servers only see a single UDP probe packet per
// connection attempt; they never relay actual traffic.
var DefaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
	"stun3.l.google.com:19302",
}

// NewDERPMap creates a DERPMap pointing to an embedded DERP server.
func NewDERPMap(hostname string, port int, insecure bool) *tailcfg.DERPMap {
	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "cw",
				RegionName: "Codewire Embedded",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "1a",
						RegionID:         1,
						HostName:         hostname,
						DERPPort:         port,
						STUNPort:         -1,
						InsecureForTests: insecure,
					},
				},
			},
		},
	}
	for i, addr := range DefaultSTUNServers {
		host, rawPort, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		stunPort, err := strconv.Atoi(rawPort)
		if err != nil {
			continue
		}
		regionID := 9000 + i + 1
		dm.Regions[regionID] = &tailcfg.DERPRegion{
			RegionID:   regionID,
			RegionCode: fmt.Sprintf("stun%d", i+1),
			RegionName: fmt.Sprintf("STUN %d", i+1),
			Nodes: []*tailcfg.DERPNode{{
				Name:     fmt.Sprintf("%dstun", regionID),
				RegionID: regionID,
				HostName: host,
				STUNOnly: true,
				STUNPort: stunPort,
			}},
		}
	}
	return dm
}
