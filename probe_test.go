package xpfw

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func resetProbes() {
	probeMu.Lock()
	probeBuf = nil
	probeDropped = 0
	probeMu.Unlock()
}

// TestProbeBufferIsBounded: a flood cannot grow the buffer without limit; the
// oldest are shed and counted.
func TestProbeBufferIsBounded(t *testing.T) {
	resetProbes()
	t.Cleanup(resetProbes)
	for i := 0; i < probeBufferMax+50; i++ {
		recordProbe(ProbeEvent{SrcIP: fmt.Sprintf("10.0.0.%d", i%256), Kind: probeNoTLS})
	}
	events, dropped := drainProbes()
	if len(events) != probeBufferMax {
		t.Errorf("buffer held %d, want the cap %d", len(events), probeBufferMax)
	}
	if dropped != 50 {
		t.Errorf("dropped = %d, want 50", dropped)
	}
	events, dropped = drainProbes()
	if events != nil || dropped != 0 {
		t.Errorf("a second drain returned %d events / %d dropped, want empty", len(events), dropped)
	}
}

func TestBlocklistMatching(t *testing.T) {
	setBlocklist(1, []string{"203.0.113.5", "198.51.100.0/24", "2001:db8:1::/48"})
	t.Cleanup(func() { setBlocklist(999, nil) })

	blocked := []string{"203.0.113.5:12345", "198.51.100.77:9", "[2001:db8:1:2::9]:443"}
	for _, a := range blocked {
		if !blockedAddr(a) {
			t.Errorf("%s should be blocked", a)
		}
	}
	allowed := []string{"203.0.113.6:12345", "198.51.101.1:9", "[2001:db8:2::1]:443"}
	for _, a := range allowed {
		if blockedAddr(a) {
			t.Errorf("%s should be allowed", a)
		}
	}
}

// TestBlocklistVersionGating: an older or equal version does not replace the
// list, and version 0 never clears it, so a panel too old to send one cannot
// unban everyone by omission.
func TestBlocklistVersionGating(t *testing.T) {
	setBlocklist(5, []string{"203.0.113.5"})
	t.Cleanup(func() { setBlocklist(999, nil) })
	setBlocklist(0, nil) // "none issued": ignored
	if !blockedAddr("203.0.113.5:1") {
		t.Error("version 0 cleared the list")
	}
	setBlocklist(5, []string{}) // same version: ignored
	if !blockedAddr("203.0.113.5:1") {
		t.Error("an equal version replaced the list")
	}
	setBlocklist(6, []string{"198.51.100.9"}) // newer: replaces
	if blockedAddr("203.0.113.5:1") || !blockedAddr("198.51.100.9:1") {
		t.Error("a newer version did not replace the list")
	}
}

// TestSNIMissGoesToFallbackAndIsRecorded: an unmatched SNI connection reaches
// the camouflage site, not default_backend, and is booked as a probe with the
// hostname and a fingerprint.
func TestSNIMissGoesToFallbackAndIsRecorded(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	resetProbes()
	t.Cleanup(resetProbes)

	def := bannerBackend(t, "DEFAULT")
	fb := bannerBackend(t, "FALLBACK")
	configMu.Lock()
	globalConfig.DefaultBackend = def
	globalConfig.FallbackBackend = fb
	configMu.Unlock()
	if err := applyRules([]Rule{sniRule(1, "known.example.com", bannerBackend(t, "REAL"))}, 1); err != nil {
		t.Fatal(err)
	}
	proxy := startSNIProxy(t)

	conn, banner := dialSNI(t, proxy, "unknown.example.com")
	if banner != "FALLBACK" {
		t.Errorf("an unknown SNI reached %q, want the camouflage FALLBACK", banner)
	}
	// The probe is booked when the connection ends, so close it and wait.
	conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		probeMu.Lock()
		n := len(probeBuf)
		probeMu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	events, _ := drainProbes()
	var found *ProbeEvent
	for i := range events {
		if events[i].SNI == "unknown.example.com" {
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatalf("no probe event recorded for the unknown SNI; got %d events", len(events))
	}
	if found.Kind != probeNoRule || found.FP == "" || !found.IsTLS {
		t.Errorf("probe = %+v, want kind no_rule, a fingerprint, and IsTLS", *found)
	}
}

// TestSameProbeFingerprintFromManyIPs: the point of the fingerprint is that the
// same crafted ClientHello hashes alike however many sources replay it, which
// is what the panel keys its replay detection on.
func TestSameProbeFingerprintFromManyIPs(t *testing.T) {
	hello := fakeClientHello("probe.example.com")
	fp := fingerprintFirstBytes(hello)
	if fp == "" {
		t.Fatal("empty fingerprint for a real ClientHello")
	}
	if fingerprintFirstBytes(fakeClientHello("probe.example.com")) != fp {
		t.Error("the same bytes hashed to different fingerprints")
	}
	if fingerprintFirstBytes(fakeClientHello("other.example.com")) == fp {
		t.Error("different bytes collided")
	}
}

func TestIPOnly(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5:443":   "203.0.113.5",
		"[2001:db8::1]:443": "2001:db8::1",
		"203.0.113.5":       "203.0.113.5",
	}
	for in, want := range cases {
		if got := ipOnly(in); got != want {
			t.Errorf("ipOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

var _ = net.ParseIP

func resetReal() {
	realMu.Lock()
	realSeen = map[string]*realEntry{}
	realPending = map[string]struct{}{}
	realMu.Unlock()
}

// TestRealSourcesReportedOncePerWindow: a group is queued the first time it
// transfers real data, drained once, not re-queued within realReportEvery, and
// put back when the heartbeat carrying it fails.
func TestRealSourcesReportedOncePerWindow(t *testing.T) {
	resetReal()
	noteRealTraffic("1.2.3.4", 5000)
	got := drainRealSources()
	if len(got) != 1 || got[0].G != "1.2.3.4" || got[0].B != 5000 {
		t.Fatalf("first drain = %+v, want one entry 1.2.3.4/5000", got)
	}
	noteRealTraffic("1.2.3.4", 7000)
	if again := drainRealSources(); len(again) != 0 {
		t.Fatalf("re-reported within the window: %+v", again)
	}
	requeueRealSources(got)
	back := drainRealSources()
	if len(back) != 1 || back[0].B != 12000 {
		t.Fatalf("requeued drain = %+v, want 1.2.3.4 with accumulated 12000 bytes", back)
	}
}

// TestRealSourcesDrainIsCapped: a burst larger than realReportMax goes out over
// several heartbeats, nothing lost.
func TestRealSourcesDrainIsCapped(t *testing.T) {
	resetReal()
	total := realReportMax + 37
	for i := 0; i < total; i++ {
		noteRealTraffic(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), 4096)
	}
	first := drainRealSources()
	second := drainRealSources()
	if len(first) != realReportMax || len(first)+len(second) != total {
		t.Fatalf("drained %d then %d, want %d then %d", len(first), len(second), realReportMax, total-realReportMax)
	}
}

// TestSrcGroupNormalisesMappedV4: the node keys sources exactly like the panel.
func TestSrcGroupNormalisesMappedV4(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":                  "1.2.3.4",
		"::ffff:1.2.3.4":           "1.2.3.4",
		"2409:8a5c:3a32:b670::1":   "2409:8a5c:3a32:b670::/64",
		"2409:8a5c:3a32:b670:a::9": "2409:8a5c:3a32:b670::/64",
	}
	for in, want := range cases {
		if got := srcGroup(in); got != want {
			t.Errorf("srcGroup(%q) = %q, want %q", in, got, want)
		}
	}
}
