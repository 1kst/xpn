package xpfw

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// bannerBackend is a backend that says who it is: it writes name and a newline
// on accept, then echoes. Telling backends apart is the whole point of these
// tests, so an anonymous echo server will not do.
func bannerBackend(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen %s: %v", name, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(name + "\n"))
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// deadAddr is a loopback address nothing listens on, so a dial fails at once.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// resetForwarding returns the process-wide forwarding state to empty after the
// test, so listeners and tracked connections do not leak between tests.
func resetForwarding(t *testing.T) {
	t.Helper()
	configMu.RLock()
	savedConfig := globalConfig
	configMu.RUnlock()
	reset := func() {
		configMu.Lock()
		globalConfig = savedConfig
		configMu.Unlock()
		stopAllPortForwarders()
		for _, c := range snapshotConns() {
			c.close()
		}
		activeConnsMu.Lock()
		activeConns = make(map[*trackedConn]struct{})
		activeConnsMu.Unlock()
		failoverMu.Lock()
		pinnedTargets = make(map[string]*pinnedTarget)
		failoverEvents = nil
		failoverMu.Unlock()
		listenFailMu.Lock()
		listenFails = make(map[int]listenFailure)
		listenFailMu.Unlock()
		clearConfigReject()
		configVersionMu.Lock()
		configVersionCounter = 0
		configVersionMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

type relayedConn struct {
	net.Conn
	r *bufio.Reader
}

// readLine reads one line or fails the test; a closed connection is reported
// as an error, not as a line.
func (c *relayedConn) readLine(t *testing.T) (string, error) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := c.r.ReadString('\n')
	return strings.TrimSpace(line), err
}

// echoWorks proves the relay is still up end to end.
func (c *relayedConn) echoWorks(t *testing.T) bool {
	t.Helper()
	if _, err := c.Write([]byte("ping\n")); err != nil {
		return false
	}
	line, err := c.readLine(t)
	return err == nil && line == "ping"
}

// isClosed waits for the relay to close the connection. A timeout means it is
// still open.
func (c *relayedConn) isClosed(t *testing.T) bool {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.r.ReadString('\n')
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true
}

// dialPort connects through a port forwarder and returns the backend's banner.
// The listener is bound asynchronously, so the first attempts may be refused.
func dialPort(t *testing.T, port int) (*relayedConn, string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			rc := &relayedConn{Conn: c, r: bufio.NewReader(c)}
			t.Cleanup(func() { c.Close() })
			banner, err := rc.readLine(t)
			if err != nil {
				t.Fatalf("read banner through :%d: %v", port, err)
			}
			return rc, banner
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial :%d: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startSNIProxy runs handleSNIConn on a loopback listener.
func startSNIProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSNIConn(c, ctx)
		}
	}()
	return ln.Addr().String()
}

func dialSNI(t *testing.T, proxy, host string) (*relayedConn, string) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Write(fakeClientHello(host)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	rc := &relayedConn{Conn: c, r: bufio.NewReader(c)}
	banner, err := rc.readLine(t)
	if err != nil {
		t.Fatalf("read banner for %s: %v", host, err)
	}
	// The backend echoes the ClientHello back; it has no newline to stop at, so
	// it is drained by length.
	hello := fakeClientHello(host)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(rc.r, make([]byte, len(hello))); err != nil {
		t.Fatalf("drain echoed hello: %v", err)
	}
	return rc, banner
}

func portRule(id, port int, dest ...string) Rule {
	return Rule{ID: id, Name: fmt.Sprintf("port-%d", id), Type: RuleTypePort, ListenPort: port, Dest: dest, LBStrategy: LBFirstOnly, Enabled: true}
}

func sniRule(id int, host string, dest ...string) Rule {
	return Rule{ID: id, Name: fmt.Sprintf("sni-%d", id), Type: RuleTypeSNI, SNI: host, Dest: dest, LBStrategy: LBFirstOnly, Enabled: true}
}

// TestConfigPushKeepsUnchangedPortConnections is the regression this change is
// for: every push used to close every port listener on the node, cutting all
// port-forwarded connections, including ones whose rule had not changed at all.
func TestConfigPushKeepsUnchangedPortConnections(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	port := freePort(t)
	if err := applyRules([]Rule{portRule(1, port, a)}, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	conn, banner := dialPort(t, port)
	if banner != "A" {
		t.Fatalf("banner = %q, want A", banner)
	}

	portListenersMu.Lock()
	before := portListeners[port]
	portListenersMu.Unlock()

	// A different rule changes; this one does not.
	other := bannerBackend(t, "other")
	if err := applyRules([]Rule{portRule(1, port, a), sniRule(2, "x.example.com", other)}, 2); err != nil {
		t.Fatalf("applyRules: %v", err)
	}

	if !conn.echoWorks(t) {
		t.Fatal("a connection on an unchanged port rule was cut by an unrelated config push")
	}
	portListenersMu.Lock()
	after := portListeners[port]
	portListenersMu.Unlock()
	if before != after {
		t.Error("the listener of an unchanged port rule was replaced")
	}
}

// TestConfigPushMovesPortConnectionsAtOnce covers the switch the operator asked
// for: when a rule's target changes, its connections are closed immediately so
// clients reconnect to the new target, while the listener itself stays up.
func TestConfigPushMovesPortConnectionsAtOnce(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	b := bannerBackend(t, "B")
	port := freePort(t)
	keptPort := freePort(t)
	kept := bannerBackend(t, "kept")
	if err := applyRules([]Rule{portRule(1, port, a), portRule(2, keptPort, kept)}, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	moved, _ := dialPort(t, port)
	untouched, _ := dialPort(t, keptPort)

	if err := applyRules([]Rule{portRule(1, port, b), portRule(2, keptPort, kept)}, 2); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	if !moved.isClosed(t) {
		t.Fatal("a connection on the old target stayed open after the rule moved")
	}
	if !untouched.echoWorks(t) {
		t.Error("a connection of another rule was cut")
	}
	if _, banner := dialPort(t, port); banner != "B" {
		t.Errorf("new connection went to %q, want B", banner)
	}
}

// TestConfigPushKeepsConnectionWhoseAddressStays: adding a target, or changing
// only the strategy, leaves the address a connection is on still valid, so the
// connection is not closed for nothing.
func TestConfigPushKeepsConnectionWhoseAddressStays(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	b := bannerBackend(t, "B")
	port := freePort(t)
	if err := applyRules([]Rule{portRule(1, port, a)}, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	conn, _ := dialPort(t, port)

	next := portRule(1, port, a, b)
	next.LBStrategy = LBRoundRobin
	next.Name = "renamed"
	if err := applyRules([]Rule{next}, 2); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	if !conn.echoWorks(t) {
		t.Fatal("a connection whose address is still a target was closed")
	}
}

// TestConfigPushRemovingPortRuleClosesIt: a port no longer configured stops
// listening and its connections go with it.
func TestConfigPushRemovingPortRuleClosesIt(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	port := freePort(t)
	keep := sniRule(9, "keep.example.com", a)
	if err := applyRules([]Rule{portRule(1, port, a), keep}, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	conn, _ := dialPort(t, port)
	if err := applyRules([]Rule{keep}, 2); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	if !conn.isClosed(t) {
		t.Fatal("connection of a removed port rule is still open")
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		t.Error("the removed port is still listening")
	}
}

// TestConfigPushMovesSNIConnectionsAtOnce: SNI connections used to stay on the
// old backend until they ended, even after the rule was deleted. They now
// follow the rule, and connections of other rules are left alone.
func TestConfigPushMovesSNIConnectionsAtOnce(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	b := bannerBackend(t, "B")
	other := bannerBackend(t, "other")
	proxy := startSNIProxy(t)

	rules := []Rule{sniRule(1, "a.example.com", a), sniRule(2, "o.example.com", other)}
	if err := applyRules(rules, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	moved, banner := dialSNI(t, proxy, "a.example.com")
	if banner != "A" {
		t.Fatalf("banner = %q, want A", banner)
	}
	untouched, _ := dialSNI(t, proxy, "o.example.com")

	rules[0].Dest = []string{b}
	if err := applyRules(rules, 2); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	if !moved.isClosed(t) {
		t.Fatal("an SNI connection stayed on the old target after the rule moved")
	}
	if !untouched.echoWorks(t) {
		t.Error("an SNI connection of an unchanged rule was cut")
	}
	if _, banner := dialSNI(t, proxy, "a.example.com"); banner != "B" {
		t.Errorf("new connection went to %q, want B", banner)
	}

	// Deleting the rule closes what it carried: unmatched traffic belongs to
	// default_backend, and this connection is not there.
	again, _ := dialSNI(t, proxy, "a.example.com")
	if err := applyRules(rules[1:], 3); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	if !again.isClosed(t) {
		t.Error("an SNI connection of a deleted rule stayed open")
	}
}

// TestPinnedLandingFallsBackOnDial: a user connecting while the pinned landing
// is unreachable is sent to the fallback instead of failing.
func TestPinnedLandingFallsBackOnDial(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	def := bannerBackend(t, "default")
	port := freePort(t)
	r := portRule(1, port, deadAddr(t))
	r.Fallback = []string{def}
	if err := applyRules([]Rule{r}, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	if _, banner := dialPort(t, port); banner != "default" {
		t.Errorf("connection went to %q, want the fallback", banner)
	}

	// Without a fallback the rule behaves as it always did: the dial fails.
	plain := portRule(1, port, deadAddr(t))
	if err := applyRules([]Rule{plain}, 2); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	rc := &relayedConn{Conn: c, r: bufio.NewReader(c)}
	if !rc.isClosed(t) {
		t.Error("an unpinned rule with a dead target still relayed somewhere")
	}
}

// TestFailoverStateMachine covers the monitor: three failures mark a landing
// down and close what is still on it, new connections then go straight to the
// fallback, three successes bring it back without touching connections on the
// fallback, and each transition is reported until acknowledged.
func TestFailoverStateMachine(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	const landing = "192.0.2.10:2222"
	def := bannerBackend(t, "default")
	r := sniRule(5, "pin.example.com", landing)
	r.Fallback = []string{def}
	setPinnedTargets([]Rule{r})
	entry := &sniRouteEntry{ruleID: 5, dests: []string{landing}, fallback: []string{def}, strategy: LBFirstOnly}
	sniRouteMu.Lock()
	prevRoutes := sniRouteCache
	sniRouteCache = map[string]*sniRouteEntry{"pin.example.com": entry}
	sniRouteMu.Unlock()
	t.Cleanup(func() {
		sniRouteMu.Lock()
		sniRouteCache = prevRoutes
		sniRouteMu.Unlock()
	})

	// A connection on the landing, and one already on the fallback.
	onLanding, onLandingPeer := net.Pipe()
	defer onLandingPeer.Close()
	up1, up1Peer := net.Pipe()
	defer up1Peer.Close()
	onFallback, onFallbackPeer := net.Pipe()
	defer onFallbackPeer.Close()
	up2, up2Peer := net.Pipe()
	defer up2Peer.Close()
	landingConn := &trackedConn{kind: connKindSNI, sni: "pin.example.com", ruleID: 5, backend: landing, client: onLanding, upstream: up1}
	fallbackConn := &trackedConn{kind: connKindSNI, sni: "pin.example.com", ruleID: 5, backend: def, viaFallback: true, client: onFallback, upstream: up2}
	activeConnsMu.Lock()
	activeConns[landingConn] = struct{}{}
	activeConns[fallbackConn] = struct{}{}
	activeConnsMu.Unlock()

	fail := errors.New("connect: connection refused")

	for i := 0; i < failoverThreshold-1; i++ {
		failoverObserve(landing, fail)
	}
	if failoverIsDown(landing) {
		t.Fatal("marked down before the threshold")
	}
	// A success in between resets the count: failures have to be consecutive.
	failoverObserve(landing, nil)
	for i := 0; i < failoverThreshold-1; i++ {
		failoverObserve(landing, fail)
	}
	if failoverIsDown(landing) {
		t.Fatal("non-consecutive failures marked the landing down")
	}
	failoverObserve(landing, fail)
	if !failoverIsDown(landing) {
		t.Fatal("not marked down after consecutive failures")
	}

	if _, err := onLandingPeer.Write([]byte("x")); err == nil {
		t.Error("the connection on the landing was not closed when it went down")
	}
	if backend, via := entry.pick(); backend != def || !via {
		t.Errorf("pick while down = (%q, %v), want the fallback", backend, via)
	}

	rep := failoverReport()
	if rep == nil || len(rep.Down) != 1 || rep.Down[0].Target != landing || len(rep.Events) != 1 || !rep.Events[0].Down {
		t.Fatalf("report while down = %+v", rep)
	}
	if rep.Events[0].RuleIDs[0] != 5 || !strings.Contains(rep.Events[0].Error, "refused") {
		t.Errorf("down event = %+v, want rule 5 and the dial error", rep.Events[0])
	}

	for i := 0; i < failoverThreshold; i++ {
		failoverObserve(landing, nil)
	}
	if failoverIsDown(landing) {
		t.Fatal("still down after consecutive successes")
	}
	if backend, via := entry.pick(); backend != landing || via {
		t.Errorf("pick after recovery = (%q, %v), want the landing", backend, via)
	}
	// The connection that moved to the fallback stays there.
	done := make(chan error, 1)
	go func() { _, err := onFallbackPeer.Write([]byte("x")); done <- err }()
	buf := make([]byte, 1)
	onFallback.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := onFallback.Read(buf); err != nil {
		t.Errorf("the connection on the fallback was closed by the recovery: %v", err)
	}
	<-done

	rep = failoverReport()
	if rep == nil || len(rep.Down) != 0 || len(rep.Events) != 2 || rep.Events[1].Down {
		t.Fatalf("report after recovery = %+v", rep)
	}
	ackFailoverEvents(rep.Events[0].Seq)
	if rep = failoverReport(); rep == nil || len(rep.Events) != 1 {
		t.Fatalf("after acking the first event = %+v, want the second left", rep)
	}
	ackFailoverEvents(rep.Events[0].Seq)
	if rep = failoverReport(); rep != nil {
		t.Errorf("after acking everything = %+v, want nothing to report", rep)
	}
}

// TestSetPinnedTargetsKeepsState: a push that only changes some other rule must
// not reset a landing that is down back to up.
func TestSetPinnedTargetsKeepsState(t *testing.T) {
	resetForwarding(t)
	const landing = "192.0.2.11:443"
	r := sniRule(1, "p.example.com", landing)
	r.Fallback = []string{"192.0.2.99:443"}
	setPinnedTargets([]Rule{r})
	for i := 0; i < failoverThreshold; i++ {
		failoverObserve(landing, errors.New("timeout"))
	}
	setPinnedTargets([]Rule{r, sniRule(2, "other.example.com", "192.0.2.50:443")})
	if !failoverIsDown(landing) {
		t.Error("an unrelated push reset the landing's state")
	}
	setPinnedTargets([]Rule{sniRule(2, "other.example.com", "192.0.2.50:443")})
	if failoverIsDown(landing) {
		t.Error("a landing that is no longer pinned is still monitored")
	}
}

// TestFallbackSurvivesRestart: the node runs from its local table while the
// panel is unreachable, so the fallback has to be stored there.
func TestFallbackSurvivesRestart(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	r := sniRule(3, "f.example.com", "192.0.2.20:2222")
	r.Fallback = []string{"192.0.2.1:443", "192.0.2.2:443"}
	if err := applyRules([]Rule{r}, 4); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	stored, err := getAllRules()
	if err != nil || len(stored) != 1 {
		t.Fatalf("getAllRules = %v, %v", stored, err)
	}
	if strings.Join(stored[0].Fallback, ",") != "192.0.2.1:443,192.0.2.2:443" {
		t.Errorf("stored fallback = %v", stored[0].Fallback)
	}

	sniRouteMu.Lock()
	sniRouteCache = map[string]*sniRouteEntry{}
	sniRouteMu.Unlock()
	if err := rebuildSniRouteCacheFromDB(); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	entry, ok := lookupSNIRoute("f.example.com")
	if !ok || !entry.pinned() || len(entry.fallback) != 2 {
		t.Errorf("rebuilt route = %+v, want the fallback restored", entry)
	}
}

// TestRejectsEmptyConfigUnlessAllowed: a panel reinstalled or restored with an
// empty database must not wipe a node that has rules.
func TestRejectsEmptyConfigUnlessAllowed(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	if err := applyRules([]Rule{sniRule(1, "a.example.com", a)}, 5); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	configVersionMu.Lock()
	configVersionCounter = 5
	configVersionMu.Unlock()

	applyConfigFromPanel(ConfigResponse{ConfigVersion: 6, Guarded: true})
	if localRuleCount() != 1 {
		t.Fatal("an empty config wiped the node's rules")
	}
	if rej := currentConfigReject(); rej == nil || rej.Reason != "empty" || rej.PanelVersion != 6 || rej.LocalVersion != 5 {
		t.Fatalf("reject = %+v, want empty from 6 over 5", rej)
	}

	applyConfigFromPanel(ConfigResponse{ConfigVersion: 7, Guarded: true, AllowEmpty: true})
	if localRuleCount() != 0 {
		t.Error("an empty config marked deliberate was not applied")
	}
	if currentConfigReject() != nil {
		t.Error("a successful apply left the rejection reported")
	}
}

// TestRejectsOlderConfig: a panel restored from an old backup must not roll a
// node back, which it would the moment the node restarted and pulled.
func TestRejectsOlderConfig(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	b := bannerBackend(t, "B")
	if err := applyRules([]Rule{sniRule(1, "a.example.com", a)}, 40); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	configVersionMu.Lock()
	configVersionCounter = 40
	configVersionMu.Unlock()

	applyConfigFromPanel(ConfigResponse{ConfigVersion: 12, Guarded: true, Rules: []Rule{sniRule(1, "a.example.com", b)}})
	if e, _ := lookupSNIRoute("a.example.com"); e == nil || e.dests[0] != a {
		t.Fatal("an older config replaced the node's rules")
	}
	if rej := currentConfigReject(); rej == nil || rej.Reason != "older" {
		t.Fatalf("reject = %+v, want older", rej)
	}

	// The same version is accepted: the panel re-sends it when only this node's
	// view of a rule changed.
	applyConfigFromPanel(ConfigResponse{ConfigVersion: 40, Guarded: true, Rules: []Rule{sniRule(1, "a.example.com", b)}})
	if e, _ := lookupSNIRoute("a.example.com"); e == nil || e.dests[0] != b {
		t.Error("a config at the node's own version was refused")
	}
}

// TestListenFailureIsRetriedAndReported: a port that will not bind used to be a
// single attempt whose error was thrown away.
func TestListenFailureIsRetriedAndReported(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a retry")
	}
	withTestDB(t)
	resetForwarding(t)

	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := blocker.Addr().(*net.TCPAddr).Port
	a := bannerBackend(t, "A")
	if err := applyRules([]Rule{portRule(8, port, a)}, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var errs []ListenError
	for time.Now().Before(deadline) {
		if errs = listenErrors(); len(errs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(errs) != 1 || errs[0].Port != port || errs[0].RuleID != 8 {
		t.Fatalf("listen errors = %+v, want port %d of rule 8", errs, port)
	}

	blocker.Close()
	if _, banner := dialPort(t, port); banner != "A" {
		t.Errorf("after the port was freed the rule went to %q, want A", banner)
	}
	if errs := listenErrors(); len(errs) != 0 {
		t.Errorf("listen errors after a successful retry = %+v", errs)
	}
}

// TestUnguardedPanelKeepsOldBehaviour: a panel that does not say it can resolve
// a refusal, an older release or the panel built into this binary, must not be
// refused. It would have no way to undo it.
func TestUnguardedPanelKeepsOldBehaviour(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	a := bannerBackend(t, "A")
	if err := applyRules([]Rule{sniRule(1, "a.example.com", a)}, 9); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	configVersionMu.Lock()
	configVersionCounter = 9
	configVersionMu.Unlock()

	applyConfigFromPanel(ConfigResponse{ConfigVersion: 3})
	if localRuleCount() != 0 || currentConfigReject() != nil {
		t.Errorf("an unguarded panel's config was refused: rules=%d reject=%+v", localRuleCount(), currentConfigReject())
	}
}

// TestConnectionPinnedAfterItWasMadeFollowsFailover: a connection made before
// its rule pinned this entry sits on the landing all the same, and must be
// closed when the landing goes down.
func TestConnectionPinnedAfterItWasMadeFollowsFailover(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	const landing = "192.0.2.30:443"
	onLanding, peer := net.Pipe()
	defer peer.Close()
	up, upPeer := net.Pipe()
	defer upPeer.Close()
	c := &trackedConn{kind: connKindSNI, sni: "late.example.com", ruleID: 8, backend: landing, client: onLanding, upstream: up}
	activeConnsMu.Lock()
	activeConns[c] = struct{}{}
	activeConnsMu.Unlock()

	pinned := sniRule(8, "late.example.com", landing)
	pinned.Fallback = []string{"192.0.2.31:443"}
	if err := applyRules([]Rule{pinned}, 2); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	for i := 0; i < failoverThreshold; i++ {
		failoverObserve(landing, errors.New("timeout"))
	}
	if _, err := peer.Write([]byte("x")); err == nil {
		t.Error("a connection made before the rule was pinned stayed on the landing after it went down")
	}
}

// TestUserDialFailuresDoNotMarkDown: failed user connections prompt a probe but
// cannot on their own mark a landing down, since that closes every connection
// on it.
func TestUserDialFailuresDoNotMarkDown(t *testing.T) {
	resetForwarding(t)
	const landing = "192.0.2.40:443"
	r := sniRule(1, "u.example.com", landing)
	r.Fallback = []string{"192.0.2.41:443"}
	setPinnedTargets([]Rule{r})

	failoverMu.Lock()
	probing[landing] = true // a probe is already in flight
	failoverMu.Unlock()
	for i := 0; i < 10; i++ {
		failoverSuspect(landing)
	}
	if failoverIsDown(landing) {
		t.Error("user dial failures alone marked the landing down")
	}
	failoverMu.Lock()
	delete(probing, landing)
	failoverMu.Unlock()
}

// TestActiveConnCountIsReported: the heartbeat carries how many connections are
// being relayed, zero included, so the panel can tell zero from a node too old
// to report it.
func TestActiveConnCountIsReported(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)

	b, _ := json.Marshal(HeartbeatRequest{})
	if !strings.Contains(string(b), `"active_conns":0`) {
		t.Errorf("a heartbeat with no connections omits the count: %s", b)
	}

	a := bannerBackend(t, "A")
	port := freePort(t)
	if err := applyRules([]Rule{portRule(1, port, a)}, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}
	c1, _ := dialPort(t, port)
	c2, _ := dialPort(t, port)
	if n := activeConnCount(); n != 2 {
		t.Errorf("active = %d with two relayed connections, want 2", n)
	}
	c1.Close()
	c2.Close()
	deadline := time.Now().Add(3 * time.Second)
	for activeConnCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := activeConnCount(); n != 0 {
		t.Errorf("active = %d after both closed, want 0", n)
	}
}

// countingBackend accepts connections and counts them, and never reads or
// writes: a backend that accepted and went silent.
func countingBackend(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		n     atomic.Int64
		held  []net.Conn
		heldM = make(chan net.Conn, 64)
	)
	t.Cleanup(func() {
		ln.Close()
		close(heldM)
		for c := range heldM {
			held = append(held, c)
		}
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			select {
			case heldM <- c:
			default:
				c.Close()
			}
		}
	}()
	return ln.Addr().String(), &n
}

// TestEmptyConnectionIsNotRelayed: a bare connect that sends nothing used to
// dial default_backend and relay nothing until the idle timeout.
func TestEmptyConnectionIsNotRelayed(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	def, accepted := countingBackend(t)
	configMu.Lock()
	globalConfig.DefaultBackend = def
	configMu.Unlock()
	proxy := startSNIProxy(t)

	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	time.Sleep(300 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Errorf("an empty connection reached default_backend %d time(s)", accepted.Load())
	}

	// Something that is not TLS but did send bytes still goes there, as before.
	c, err = net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	deadline := time.Now().Add(3 * time.Second)
	for accepted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	c.Close()
	if accepted.Load() != 1 {
		t.Errorf("plain bytes reached default_backend %d time(s), want 1", accepted.Load())
	}
}

// TestHalfClosedConnectionEndsSoon: when the client closes its side and the
// backend neither answers nor closes, the connection used to linger for the
// full idle timeout.
func TestHalfClosedConnectionEndsSoon(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	prev := halfCloseIdle
	halfCloseIdle = 300 * time.Millisecond
	t.Cleanup(func() { halfCloseIdle = prev })

	silent, _ := countingBackend(t)
	port := freePort(t)
	if err := applyRules([]Rule{portRule(1, port, silent)}, 1); err != nil {
		t.Fatal(err)
	}
	var c net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		var err error
		c, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c == nil {
		t.Fatal("port never listened")
	}
	defer c.Close()
	deadline = time.Now().Add(2 * time.Second)
	for activeConnCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if activeConnCount() == 0 {
		t.Fatal("the connection was never relayed")
	}
	c.(*net.TCPConn).CloseWrite()
	deadline = time.Now().Add(3 * time.Second)
	for activeConnCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := activeConnCount(); n != 0 {
		t.Errorf("a half-closed connection to a silent backend is still relayed after 3s (%d active)", n)
	}
}

// TestDeadTargetIsSkipped: with several targets, a dead one used to fail its
// whole share of connections.
func TestDeadTargetIsSkipped(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	alive := bannerBackend(t, "alive")
	port := freePort(t)
	if err := applyRules([]Rule{portRule(1, port, deadAddr(t), alive)}, 1); err != nil {
		t.Fatal(err)
	}
	if _, banner := dialPort(t, port); banner != "alive" {
		t.Errorf("connection went to %q, want the live target", banner)
	}
}

// TestHealthCheckIgnoresUnprobedTarget: a target with no probe result yet used
// to count as 0ms and win outright.
func TestHealthCheckIgnoresUnprobedTarget(t *testing.T) {
	probeCacheMu.Lock()
	prev := probeCache
	probeCache = map[string]*probeState{
		"a:1": {lastMS: 40, probed: true},
		"b:1": {},
	}
	probeCacheMu.Unlock()
	t.Cleanup(func() {
		probeCacheMu.Lock()
		probeCache = prev
		probeCacheMu.Unlock()
	})
	if got := selectBackend([]string{"b:1", "a:1"}, LBHealthCheck, nil); got != "a:1" {
		t.Errorf("health_check chose %q, want the probed target", got)
	}
	// A user connection that failed takes the target out until it probes well.
	markProbeFailed("a:1")
	probeCacheMu.Lock()
	failed := probeCache["a:1"].lastMS
	probeCacheMu.Unlock()
	if failed != -1 {
		t.Errorf("after a failed dial lastMS = %d, want -1", failed)
	}
}

// TestDNSKeepsLastGoodAnswer: a failed refresh used to throw the working
// addresses away with it.
func TestDNSKeepsLastGoodAnswer(t *testing.T) {
	const host = "stale-test.invalid"
	dnsCacheMu.Lock()
	dnsCache[host] = &dnsCacheEntry{ips: []string{"192.0.2.55"}, expiresAt: time.Now().Add(-time.Second)}
	dnsCacheMu.Unlock()
	t.Cleanup(func() {
		dnsCacheMu.Lock()
		delete(dnsCache, host)
		dnsCacheMu.Unlock()
	})
	ips, err := resolveHostCached(host)
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.55" {
		t.Errorf("after a failed refresh = (%v, %v), want the previous address", ips, err)
	}
}

// TestLogThrottleStillThrottlesWhenFull: a full table used to let every new key
// through unthrottled, forever.
func TestLogThrottleStillThrottlesWhenFull(t *testing.T) {
	resetLogThrottle()
	t.Cleanup(resetLogThrottle)
	for i := 0; i < logThrottleMaxKeys; i++ {
		throttledLog(fmt.Sprintf("k%d", i))
	}
	emitted := 0
	for i := 0; i < 50; i++ {
		if _, ok := throttledLog(fmt.Sprintf("new%d", i)); ok {
			emitted++
		}
	}
	if emitted > 1 {
		t.Errorf("%d of 50 new keys were logged with the table full, want at most 1", emitted)
	}
}

// TestCountedNICs: loopback, virtual and tunnel devices carry traffic that is
// counted elsewhere already, or is not traffic to the outside at all.
func TestCountedNICs(t *testing.T) {
	for _, name := range []string{"lo", "docker0", "veth12ab", "br-3f", "wg0", "tun0", "tailscale0", "cali1"} {
		if countedNIC(name) {
			t.Errorf("%s is counted", name)
		}
	}
	if runtime.GOOS != "linux" {
		for _, name := range []string{"eth0", "ens3", "enp1s0", "bond0"} {
			if !countedNIC(name) {
				t.Errorf("%s is not counted", name)
			}
		}
	}
}

// TestHandshakeBytesAreCounted: the ClientHello and what came with it are client
// upload like the rest, and used to go uncounted.
func TestHandshakeBytesAreCounted(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	resetTrafficState()
	a := bannerBackend(t, "A")
	proxy := startSNIProxy(t)
	if err := applyRules([]Rule{sniRule(3, "count.example.com", a)}, 1); err != nil {
		t.Fatal(err)
	}
	c, _ := dialSNI(t, proxy, "count.example.com")
	c.Close()
	want := uint64(len(fakeClientHello("count.example.com")))
	if got := counterFor(3).bytesUp.Load(); got < want {
		t.Errorf("upload counted %d bytes, want at least the %d byte ClientHello", got, want)
	}
}

// TestMalformedConfigIsRefused: a 200 with {} or an error object used to decode
// to an empty config and wipe the node.
func TestMalformedConfigIsRefused(t *testing.T) {
	for _, body := range []string{`{}`, `{"code":401,"msg":"login required"}`, `[]`, `<html>`} {
		if _, err := decodeConfigResponse([]byte(body)); err == nil {
			t.Errorf("%s was accepted as a config", body)
		}
	}
	good := `{"config":{"sni_listen":":443"},"rules":null,"config_version":0}`
	if _, err := decodeConfigResponse([]byte(good)); err != nil {
		t.Errorf("a real (empty) panel config was refused: %v", err)
	}
}

// TestMissingListenAddressKeepsTheLocalOne: an empty sni_listen used to be
// stored and leave the node without an SNI listener after its next restart.
func TestMissingListenAddressKeepsTheLocalOne(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	configMu.Lock()
	globalConfig.SNIListen = ":18443"
	configMu.Unlock()
	a := bannerBackend(t, "A")
	applyConfigFromPanel(ConfigResponse{Config: Config{DefaultBackend: a}, Rules: []Rule{sniRule(1, "a.example.com", a)}, ConfigVersion: 1})
	configMu.RLock()
	got := globalConfig.SNIListen
	configMu.RUnlock()
	if got != ":18443" {
		t.Errorf("sni_listen after a config without one = %q, want the local :18443", got)
	}
}

// TestListenerMoveKeepsConnections: moving the SNI listener used to cancel the
// context every relayed SNI connection hung off, closing all of them.
func TestListenerMoveKeepsConnections(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	a := bannerBackend(t, "A")
	if err := applyRules([]Rule{sniRule(1, "move.example.com", a)}, 1); err != nil {
		t.Fatal(err)
	}
	first := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	second := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	t.Cleanup(func() {
		sniListenerMu.Lock()
		if sniListenerLn != nil {
			sniListenerLn.Close()
		}
		sniListenerLn, sniListenerAddr = nil, ""
		sniListenerMu.Unlock()
		clearSNIListenFailure()
	})

	restartSNIListener(first)
	conn, banner := dialSNI(t, first, "move.example.com")
	if banner != "A" {
		t.Fatalf("banner = %q", banner)
	}
	restartSNIListener(second)
	if !conn.echoWorks(t) {
		t.Error("an SNI connection was cut by moving the listener")
	}
	if _, banner := dialSNI(t, second, "move.example.com"); banner != "A" {
		t.Errorf("the new address does not serve: %q", banner)
	}
	if _, err := net.DialTimeout("tcp", first, 300*time.Millisecond); err == nil {
		t.Error("the old address still accepts connections")
	}
}

// TestUnbindableListenAddressFallsBackAndIsReported: a bad address stored meant
// the next restart had nothing to fall back to, and the panel never heard.
func TestUnbindableListenAddressFallsBackAndIsReported(t *testing.T) {
	withTestDB(t)
	resetForwarding(t)
	good := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	taken := blocker.Addr().String()
	t.Cleanup(func() {
		sniListenerMu.Lock()
		if sniListenerLn != nil {
			sniListenerLn.Close()
		}
		sniListenerLn, sniListenerAddr = nil, ""
		sniListenerMu.Unlock()
		clearSNIListenFailure()
	})

	restartSNIListener(good)
	restartSNIListener(taken)

	sniListenerMu.Lock()
	serving := sniListenerAddr
	sniListenerMu.Unlock()
	if serving != good {
		t.Errorf("listening on %q, want to have kept %q", serving, good)
	}
	var stored string
	db.QueryRow("SELECT value FROM config WHERE key = 'sni_listen'").Scan(&stored)
	if stored != good {
		t.Errorf("stored sni_listen = %q, want the working %q", stored, good)
	}
	errs := listenErrors()
	if len(errs) == 0 || errs[0].RuleID != 0 || !strings.Contains(errs[0].Error, "SNI") {
		t.Errorf("listen errors = %+v, want the SNI failure reported", errs)
	}
}
