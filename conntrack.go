package xpfw

import (
	"net"
	"sync"
)

const (
	connKindSNI  = "sni"
	connKindPort = "port"
)

// trackedConn is one relayed connection, recorded with what it was routed by and
// where it went. That is enough to re-ask, after a config push, whether the new
// configuration would still send it to the same place, and to close it when it
// would not.
type trackedConn struct {
	kind   string
	sni    string // normalised; kind sni only
	port   int    // kind port only
	ruleID int
	// backend is the address actually dialled, viaFallback whether that was the
	// rule's fallback rather than its own targets.
	backend     string
	viaFallback bool

	client   net.Conn
	upstream net.Conn
	once     sync.Once
}

// close ends both halves, which makes the relay loops return and the handler
// untrack the connection.
func (c *trackedConn) close() {
	c.once.Do(func() {
		c.client.Close()
		c.upstream.Close()
	})
}

var (
	activeConnsMu sync.Mutex
	activeConns   = make(map[*trackedConn]struct{})
)

// trackConn registers c and returns the function that forgets it. The checks
// after registering close the window between dialling and registering: a config
// push or a failover that lands in it has already swept the table without
// seeing c, and would otherwise leave it where it no longer belongs.
func trackConn(c *trackedConn) func() {
	activeConnsMu.Lock()
	activeConns[c] = struct{}{}
	activeConnsMu.Unlock()
	if !connStillRouted(c) || onDownPinnedLanding(c) {
		c.close()
	}
	return func() {
		activeConnsMu.Lock()
		delete(activeConns, c)
		activeConnsMu.Unlock()
	}
}

// activeConnCount is the number of connections being relayed right now. One
// still in its handshake or dialling its backend is not counted yet.
func activeConnCount() int {
	activeConnsMu.Lock()
	defer activeConnsMu.Unlock()
	return len(activeConns)
}

func snapshotConns() []*trackedConn {
	activeConnsMu.Lock()
	defer activeConnsMu.Unlock()
	out := make([]*trackedConn, 0, len(activeConns))
	for c := range activeConns {
		out = append(out, c)
	}
	return out
}

// dropStaleConnections closes every connection whose backend the current
// configuration no longer sends its traffic to, and nothing else. A rule whose
// target changed has its connections moved at once instead of left on the old
// target until they happen to end; a rule that did not change, or changed in a
// way that leaves the address in use, is not touched. Before this, every config
// push closed every port-forwarded connection on the node, changed or not.
func dropStaleConnections() int {
	dropped := 0
	for _, c := range snapshotConns() {
		if !connStillRouted(c) {
			c.close()
			dropped++
		}
	}
	return dropped
}

// currentRoute is the route c would be given if it connected now; nil for an
// SNI connection that matches no rule and for a port no longer listening.
func currentRoute(c *trackedConn) *sniRouteEntry {
	switch c.kind {
	case connKindSNI:
		entry, _ := lookupSNIRoute(c.sni)
		return entry
	case connKindPort:
		portListenersMu.Lock()
		pf := portListeners[c.port]
		portListenersMu.Unlock()
		if pf != nil {
			return pf.route.Load()
		}
	}
	return nil
}

// connStillRouted reports whether the current configuration would still send c
// where it is. A connection that went to the fallback during a failover stays
// valid while the fallback is still the rule's fallback: the landing coming
// back does not move connections that are working.
func connStillRouted(c *trackedConn) bool {
	entry := currentRoute(c)
	if entry == nil {
		if c.kind == connKindSNI {
			// Unmatched traffic belongs to default_backend and nowhere else. A
			// connection that matched a rule which has since gone falls here too.
			return c.ruleID == 0 && c.backend == getMissBackend()
		}
		return false
	}
	return routeAllows(entry, c)
}

// onPinnedLanding reports whether c is on a landing its rule currently pins
// this entry to. Asked of the current route rather than recorded at dial time:
// a connection made before the rule was pinned is on the landing just the same,
// and has to go when the landing does.
func onPinnedLanding(c *trackedConn) bool {
	if c.viaFallback {
		return false
	}
	entry := currentRoute(c)
	if !entry.pinned() {
		return false
	}
	for _, d := range entry.dests {
		if d == c.backend {
			return true
		}
	}
	return false
}

func onDownPinnedLanding(c *trackedConn) bool {
	return failoverIsDown(c.backend) && onPinnedLanding(c)
}

func routeAllows(e *sniRouteEntry, c *trackedConn) bool {
	if e == nil {
		return false
	}
	for _, d := range e.dests {
		if d == c.backend {
			return true
		}
	}
	if c.viaFallback {
		for _, d := range e.fallback {
			if d == c.backend {
				return true
			}
		}
	}
	return false
}

// closePinnedConnsTo closes the connections still on a pinned landing that has
// just been marked down. Left alone they would sit until the idle timeout on a
// landing that stopped answering; closed, their clients reconnect and land on
// the fallback. Connections of rules that merely share the address without
// being pinned to it are not this monitor's business.
func closePinnedConnsTo(addr string) int {
	n := 0
	for _, c := range snapshotConns() {
		if c.backend == addr && onPinnedLanding(c) {
			c.close()
			n++
		}
	}
	return n
}
