package tailnet

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"tailscale.com/tailcfg"
)

// testEnv bundles a DERP server + coordinator for integration tests.
type testEnv struct {
	DERPMap     *tailcfg.DERPMap
	Coordinator *Coordinator
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	derpSrv := NewDERPServer()
	handler, derpCleanup := DERPHandler(derpSrv)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("DERP server: %s %s (Upgrade: %s)", r.Method, r.URL.Path, r.Header.Get("Upgrade"))
		switch r.URL.Path {
		case "/derp":
			handler.ServeHTTP(w, r)
		case "/derp/latency-check":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	httpSrv := httptest.NewTLSServer(mux)
	t.Cleanup(func() { httpSrv.Close(); derpCleanup(); derpSrv.Close() })

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := 443
	fmt.Sscanf(u.Port(), "%d", &port)

	coord := NewCoordinator(slog.Default())
	t.Cleanup(func() { coord.Close() })

	return &testEnv{
		DERPMap:     NewDERPMap(u.Hostname(), port, true),
		Coordinator: coord,
	}
}

// wireUp registers both conns with the coordinator, adds a tunnel,
// and starts goroutines to relay peer updates.
func (e *testEnv) wireUp(t *testing.T, clientID, agentID uuid.UUID, client, agent *Conn) {
	t.Helper()

	agentCh := e.Coordinator.Register(agentID, "agent")
	clientCh := e.Coordinator.Register(clientID, "client")
	e.Coordinator.AddTunnel(clientID, agentID)

	agent.SetNodeCallback(func(n *Node) {
		t.Logf("agent node cb: derp=%d endpoints=%v", n.PreferredDERP, n.Endpoints)
		e.Coordinator.UpdateNode(agentID, n)
	})
	client.SetNodeCallback(func(n *Node) {
		t.Logf("client node cb: derp=%d endpoints=%v", n.PreferredDERP, n.Endpoints)
		e.Coordinator.UpdateNode(clientID, n)
	})

	go func() {
		for nodes := range agentCh {
			t.Logf("agent got %d peer(s)", len(nodes))
			_ = agent.UpdatePeers(nodes)
		}
	}()
	go func() {
		for nodes := range clientCh {
			t.Logf("client got %d peer(s)", len(nodes))
			_ = client.UpdatePeers(nodes)
		}
	}()
}

// echoServer accepts connections on ln and echoes data back.
func echoServer(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
}

// TestTunnelTCP verifies two Conns can exchange TCP data over the WireGuard
// tunnel. The initial connection bootstraps via DERP relay. On localhost,
// magicsock will discover a direct UDP path after a few seconds and upgrade
// transparently.
func TestTunnelTCP(t *testing.T) {
	env := newTestEnv(t)

	agentID := uuid.New()
	clientID := uuid.New()
	agentAddr := CWServicePrefix.PrefixFromUUID(agentID)
	clientAddr := CWServicePrefix.PrefixFromUUID(clientID)

	agent, err := NewConn(&Options{
		ID:        agentID,
		Addresses: []netip.Prefix{agentAddr},
		DERPMap:   env.DERPMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	client, err := NewConn(&Options{
		ID:        clientID,
		Addresses: []netip.Prefix{clientAddr},
		DERPMap:   env.DERPMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ln, err := agent.Listen("tcp", ":9999")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	echoServer(t, ln)
	env.wireUp(t, clientID, agentID, client, agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tcpConn, err := client.DialContextTCP(ctx, netip.AddrPortFrom(agentAddr.Addr(), 9999))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tcpConn.Close()

	msg := []byte("hello-wireguard")
	if _, err := tcpConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(tcpConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}
