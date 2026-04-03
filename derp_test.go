package tailnet

import "testing"

func TestNewDERPMap_IncludesSTUNRegions(t *testing.T) {
	dm := NewDERPMap("derp.example.com", 443, false)

	// Region 1 is the DERP relay
	relay := dm.Regions[1]
	if relay == nil {
		t.Fatal("missing DERP relay region")
	}
	// Relay node should use default STUNPort (0 = 3478). We don't set -1
	// because that prevents netcheck from measuring HTTPS latency, which
	// causes the relay to lose preferred_derp to STUN-only regions.
	if relay.Nodes[0].STUNPort != 0 {
		t.Fatalf("relay node STUNPort = %d, want 0 (default)", relay.Nodes[0].STUNPort)
	}

	// Should have at least one STUN-only region
	stunCount := 0
	for _, r := range dm.Regions {
		for _, n := range r.Nodes {
			if n.STUNOnly {
				stunCount++
			}
		}
	}
	if stunCount == 0 {
		t.Fatal("no STUNOnly regions in DERPMap")
	}
}

func TestNewDERPMap_RelayNodePreserved(t *testing.T) {
	dm := NewDERPMap("test.example.com", 8443, true)

	relay := dm.Regions[1]
	if relay == nil {
		t.Fatal("missing DERP relay region")
	}
	node := relay.Nodes[0]
	if node.HostName != "test.example.com" {
		t.Fatalf("hostname = %q, want %q", node.HostName, "test.example.com")
	}
	if node.DERPPort != 8443 {
		t.Fatalf("DERPPort = %d, want 8443", node.DERPPort)
	}
	if !node.InsecureForTests {
		t.Fatal("InsecureForTests should be true")
	}
}
