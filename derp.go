package tailnet

import (
	"bufio"
	"context"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	tslogger "tailscale.com/types/logger"
)

// NewDERPServer creates an embedded DERP relay server.
func NewDERPServer() *derpserver.Server {
	return derpserver.New(key.NewNode(), tslogger.Discard)
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
				log.Printf("derp websocket accept: %v", err)
				return
			}
			defer c.Close(websocket.StatusInternalError, "closing")

			if c.Subprotocol() != "derp" {
				c.Close(websocket.StatusPolicyViolation, "client must speak the derp subprotocol")
				return
			}

			wc := websocket.NetConn(ctx, c, websocket.MessageBinary)
			brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
			s.Accept(ctx, wc, brw, r.RemoteAddr)
		}), func() {
			cancel()
			mu.Lock()
			wg.Wait()
			mu.Unlock()
		}
}

// NewDERPMap creates a DERPMap pointing to an embedded DERP server.
func NewDERPMap(hostname string, port int, insecure bool) *tailcfg.DERPMap {
	derpPort := 443
	if insecure {
		derpPort = port
	}
	return &tailcfg.DERPMap{
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
						DERPPort:         derpPort,
						InsecureForTests: insecure,
					},
				},
			},
		},
	}
}
