package xpfw

import (
	"encoding/json"
	"sync"
	"testing"
)

func resetTrafficState() {
	trafficMu.Lock()
	trafficByRule = make(map[int]*ruleCounters)
	trafficMu.Unlock()
	reachableMu.Lock()
	reachedDest = make(map[string]bool)
	attemptedDst = make(map[string]bool)
	reachableMu.Unlock()
	sniMissCount.Store(0)
}

func TestCounterForIsStableAndSkipsUnattributed(t *testing.T) {
	resetTrafficState()

	// A zero rule id means the connection matched no rule, so there is nothing to
	// attribute it to and callers must cope with a nil counter.
	if counterFor(0) != nil {
		t.Error("rule id 0 must not get a counter")
	}
	if counterFor(-1) != nil {
		t.Error("negative rule id must not get a counter")
	}

	a, b := counterFor(7), counterFor(7)
	if a == nil || a != b {
		t.Error("repeated lookups must return the same counter")
	}
	if counterFor(8) == a {
		t.Error("different rules must not share a counter")
	}
}

func TestCounterForIsRaceFree(t *testing.T) {
	resetTrafficState()
	// Counters are created lazily from the accept path, so several connections for
	// a rule can race on first use.
	var wg sync.WaitGroup
	got := make([]*ruleCounters, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = counterFor(42)
		}(i)
	}
	wg.Wait()
	for i, c := range got {
		if c == nil || c != got[0] {
			t.Fatalf("goroutine %d saw a different counter instance", i)
		}
	}
}

func TestLoopbackDestinationsAreNeverCounted(t *testing.T) {
	resetTrafficState()

	// These are node-local by definition: whether they answer depends on which
	// host the rule landed on, so a failure says nothing about the backend.
	// Includes bare addresses with no port and "localhost", both of which are
	// realistic things to type into a rule and have the same node-local problem.
	for _, d := range []string{"127.0.0.1:8080", "127.0.0.53:53", "[::1]:443", "127.0.0.1", "::1", "localhost:8080", "LOCALHOST:1"} {
		if !isLoopback(d) {
			t.Errorf("%q should be treated as loopback", d)
		}
		if destEverReachable(d) {
			t.Errorf("%q must never count as reachable", d)
		}
	}

	for _, d := range []string{"10.0.0.5:443", "203.0.113.9:443", "example.com:443", "[2001:db8::1]:443"} {
		if isLoopback(d) {
			t.Errorf("%q should not be treated as loopback", d)
		}
	}

	// Recording a loopback result must not make it eligible either.
	noteDialResult("127.0.0.1:8080", true)
	if destEverReachable("127.0.0.1:8080") {
		t.Error("loopback stayed excluded even after a successful dial")
	}
}

func TestDialFailuresOnlyCountAfterFirstSuccess(t *testing.T) {
	resetTrafficState()
	const dest = "203.0.113.9:443"

	// Never reached from this node: the rule probably points at something only a
	// different node can see, so failures here are expected, not signal.
	if destEverReachable(dest) {
		t.Fatal("a destination should not start out reachable")
	}
	noteDialResult(dest, false)
	if destEverReachable(dest) {
		t.Error("a failed dial must not mark a destination reachable")
	}

	// Once it has answered once, later failures are real.
	noteDialResult(dest, true)
	if !destEverReachable(dest) {
		t.Error("a successful dial must mark the destination reachable")
	}
	noteDialResult(dest, false)
	if !destEverReachable(dest) {
		t.Error("reachability must be sticky once proven")
	}
}

func TestCollectTrafficCountersOmitsIdleRulesAndSorts(t *testing.T) {
	resetTrafficState()
	bootID = "boot-test"

	counterFor(30).bytesDown.Add(5000)
	counterFor(10).bytesUp.Add(1000)
	counterFor(10).conns.Add(3)
	counterFor(20) // touched but never used: must be omitted
	counterFor(40).dialFail.Add(2)
	sniMissCount.Add(9)

	got := collectTrafficCounters()
	if got.BootID != "boot-test" {
		t.Errorf("BootID = %q, want boot-test", got.BootID)
	}
	if got.SNIMisses != 9 {
		t.Errorf("SNIMisses = %d, want 9", got.SNIMisses)
	}

	var ids []int
	for _, r := range got.Rules {
		ids = append(ids, r.RuleID)
	}
	want := []int{10, 30, 40}
	if len(ids) != len(want) {
		t.Fatalf("reported rules %v, want %v (an all-zero rule must be dropped)", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("reported rules %v, want %v in ascending order", ids, want)
		}
	}

	if got.Rules[0].BytesUp != 1000 || got.Rules[0].Conns != 3 {
		t.Errorf("rule 10 = %+v, want up=1000 conns=3", got.Rules[0])
	}
	if got.Rules[1].BytesDown != 5000 {
		t.Errorf("rule 30 down = %d, want 5000", got.Rules[1].BytesDown)
	}
	if got.Rules[2].DialFail != 2 {
		t.Errorf("rule 40 dial_fail = %d, want 2", got.Rules[2].DialFail)
	}
}

func TestCountersAreMonotonicAcrossCollections(t *testing.T) {
	resetTrafficState()
	bootID = "boot-test"

	// The panel derives deltas from these, so a later report must never come back
	// smaller than an earlier one within the same boot.
	counterFor(1).bytesDown.Add(100)
	first := collectTrafficCounters()
	counterFor(1).bytesDown.Add(250)
	second := collectTrafficCounters()

	if first.Rules[0].BytesDown != 100 {
		t.Fatalf("first report = %d, want 100", first.Rules[0].BytesDown)
	}
	if second.Rules[0].BytesDown != 350 {
		t.Fatalf("second report = %d, want 350 (cumulative, not a delta)", second.Rules[0].BytesDown)
	}
}

func TestHeartbeatOmitsTrafficWhenEmpty(t *testing.T) {
	// omitempty on the wire keeps the heartbeat small for a node with no matched
	// traffic yet, and lets an older panel ignore the field entirely.
	body, err := json.Marshal(HeartbeatRequest{NodeID: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); contains(got, "traffic") {
		t.Errorf("empty traffic should be omitted, got %s", got)
	}

	resetTrafficState()
	bootID = "b"
	counterFor(1).bytesUp.Add(1)
	body, err = json.Marshal(HeartbeatRequest{NodeID: "n1", Traffic: collectTrafficCounters()})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"traffic"`, `"boot_id":"b"`, `"rule_id":1`, `"up":1`} {
		if !contains(string(body), want) {
			t.Errorf("payload %s is missing %s", body, want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
