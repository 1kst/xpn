package xpfw

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"
)

// Probe capture and the in-program blocklist.
//
// The node records the anomalous connections it already recognises -- an SNI
// listener connection that carried no usable ClientHello, no server name, or a
// name no rule serves -- as compact metadata events, and ships them to the
// panel on the heartbeat. It never records payload: the closest it comes is a
// hash of the bytes it had already read to find the SNI, which is what lets the
// panel spot the same probe replayed from many addresses without keeping any of
// the traffic.
//
// It also holds a blocklist the panel pushes down, and drops a listed source at
// Accept on every listener. That is a program-level drop, not a firewall rule:
// it does not stop a SYN flood, but it needs no privileges and works in a
// container.

// Probe event kinds.
const (
	probeNoTLS  = "no_tls"      // bytes arrived but were not a usable ClientHello
	probeNoSNI  = "no_sni"      // a ClientHello with no server name
	probeNoRule = "no_rule"     // a server name no rule serves
	probePort   = "port_nodata" // a port-rule connection that moved no data
)

// ProbeEvent is one anomalous connection, metadata only. Field names are short
// because a scanned node emits many of these per heartbeat.
type ProbeEvent struct {
	TS        string `json:"ts"`   // RFC3339, when the connection closed
	SrcIP     string `json:"ip"`   // source address, no port
	DstPort   int    `json:"port"` // local port it hit
	Kind      string `json:"kind"`
	SNI       string `json:"sni,omitempty"`
	IsTLS     bool   `json:"tls,omitempty"`
	FirstLen  int    `json:"flen,omitempty"` // bytes read before routing
	CHLen     int    `json:"chlen,omitempty"`
	FP        string `json:"fp,omitempty"`  // sha256 prefix of the first bytes
	JA3       string `json:"ja3,omitempty"` // md5 of the ClientHello's JA3 string
	UA        string `json:"ua,omitempty"`  // User-Agent, plain-HTTP probes only
	DurMS     int64  `json:"dur"`
	Up        uint64 `json:"up"`
	Down      uint64 `json:"down"`
	Responded bool   `json:"resp,omitempty"`
	// SrcHasReal is set when this source group has also completed a real,
	// rule-matched session carrying real bytes recently. A genuine user transfers
	// data; a pure prober does not, so this lets the panel exonerate a source that
	// merely reconnects badly from one that only ever probes. Node-computed.
	SrcHasReal bool `json:"real,omitempty"`
	// SrcRealBytes is the source group's real transferred bytes still remembered
	// in the node's rolling window, shown for context (a productivity signal is a
	// ratio, not this absolute number).
	SrcRealBytes uint64 `json:"realb,omitempty"`
}

const probeBufferMax = 512

var (
	probeMu  sync.Mutex
	probeBuf []ProbeEvent
	// probeDropped counts events shed since the last drain because the buffer was
	// full, so the panel can tell a quiet node from a flooded one.
	probeDropped uint64
)

// recordProbe buffers one event, oldest-dropped when full so a flood cannot grow
// this without bound.
func recordProbe(ev ProbeEvent) {
	probeMu.Lock()
	if len(probeBuf) >= probeBufferMax {
		probeBuf = probeBuf[1:]
		probeDropped++
	}
	probeBuf = append(probeBuf, ev)
	probeMu.Unlock()
}

// drainProbes returns the buffered events and how many were dropped, clearing
// both. Fire and forget: a heartbeat that fails to deliver them loses them, but
// the panel aggregates over time and a lost batch only coarsens that.
func drainProbes() ([]ProbeEvent, uint64) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if len(probeBuf) == 0 && probeDropped == 0 {
		return nil, 0
	}
	out := probeBuf
	dropped := probeDropped
	probeBuf = nil
	probeDropped = 0
	return out, dropped
}

// fingerprintFirstBytes hashes what was read before routing. Identical probes
// replayed from different addresses hash alike, which is the panel's strongest
// signal; the bytes themselves are never kept.
func fingerprintFirstBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func ipOnly(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// srcGroup canonicalises a source IP into the key the panel aggregates by: an
// IPv4 address as-is, an IPv6 address masked to its /64. Kept identical to the
// panel's grouping so a real session and a probe from the same client (or the
// same /64) collapse to one key.
func srcGroup(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		// Normalised like the panel's probeSrcGroup, so an IPv4-mapped address
		// (::ffff:a.b.c.d) and the plain one are the same source.
		return v4.String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// Source-level real-traffic memory. A source that completes a real, rule-matched
// session carrying at least realTrafficMinBytes is remembered for realTrafficTTL,
// so a probe from a source that is also a genuine user can be told apart from a
// pure prober. Bounded: a busy node sees many clients and this must not grow
// without bound. Only the group key, a timestamp and a byte count are kept.
//
// The same memory feeds the panel fleet-wide: a group is queued for the next
// heartbeat when it first transfers real data and then at most once per
// realReportEvery, so the panel can exonerate a source that misbehaves on one
// node while it is a real user of another. A steady user costs one entry an hour.
const (
	realTrafficMinBytes = 4096
	realTrafficMax      = 20000
	realTrafficTTL      = 24 * time.Hour
	realReportEvery     = time.Hour
	realReportMax       = 5000
)

// RealSource is one source group this node has seen transfer real data, as sent
// on the heartbeat. Field names are short because a busy node sends many.
type RealSource struct {
	G string `json:"g"` // source group: IPv4 address, or IPv6 /64
	B uint64 `json:"b"` // real bytes remembered for it
}

type realEntry struct {
	ts         time.Time
	bytes      uint64
	reportedAt time.Time
}

var (
	realMu      sync.Mutex
	realSeen    = map[string]*realEntry{}
	realPending = map[string]struct{}{}
)

// noteRealTraffic records n real bytes for group, queues it for the panel if it
// has not been reported within realReportEvery, and evicts expired then the
// oldest entry when full.
func noteRealTraffic(group string, n uint64) {
	now := time.Now()
	realMu.Lock()
	e := realSeen[group]
	if e != nil {
		e.ts = now
		e.bytes += n
	} else {
		e = &realEntry{ts: now, bytes: n}
		realSeen[group] = e
	}
	if e.reportedAt.IsZero() || now.Sub(e.reportedAt) >= realReportEvery {
		realPending[group] = struct{}{}
	}
	if len(realSeen) > realTrafficMax {
		var oldestK string
		var oldestT time.Time
		for k, x := range realSeen {
			if now.Sub(x.ts) > realTrafficTTL {
				delete(realSeen, k)
				delete(realPending, k)
				continue
			}
			if oldestT.IsZero() || x.ts.Before(oldestT) {
				oldestK, oldestT = k, x.ts
			}
		}
		if len(realSeen) > realTrafficMax && oldestK != "" {
			delete(realSeen, oldestK)
			delete(realPending, oldestK)
		}
	}
	realMu.Unlock()
}

// drainRealSources hands the queued groups to a heartbeat, at most realReportMax
// of them; the rest stay queued for the next one.
func drainRealSources() []RealSource {
	now := time.Now()
	realMu.Lock()
	defer realMu.Unlock()
	if len(realPending) == 0 {
		return nil
	}
	n := len(realPending)
	if n > realReportMax {
		n = realReportMax
	}
	out := make([]RealSource, 0, n)
	for g := range realPending {
		if len(out) >= realReportMax {
			break
		}
		delete(realPending, g)
		e := realSeen[g]
		if e == nil {
			continue
		}
		e.reportedAt = now
		out = append(out, RealSource{G: g, B: e.bytes})
	}
	return out
}

// requeueRealSources puts back groups whose heartbeat never reached the panel,
// so they go out on the next one instead of waiting out realReportEvery.
func requeueRealSources(list []RealSource) {
	realMu.Lock()
	for _, r := range list {
		if e := realSeen[r.G]; e != nil {
			e.reportedAt = time.Time{}
			realPending[r.G] = struct{}{}
		}
	}
	realMu.Unlock()
}

// realTrafficFor reports whether group completed a real session within the TTL
// and how many real bytes are still remembered for it.
func realTrafficFor(group string) (bool, uint64) {
	realMu.Lock()
	e := realSeen[group]
	realMu.Unlock()
	if e == nil || time.Since(e.ts) > realTrafficTTL {
		return false, 0
	}
	return true, e.bytes
}

func localPort(c net.Conn) int {
	if _, p, err := net.SplitHostPort(c.LocalAddr().String()); err == nil {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return 0
			}
			n = n*10 + int(r-'0')
		}
		return n
	}
	return 0
}

// blocklist is the set of sources the panel has banned. Exact addresses are a
// map; CIDRs are scanned. Replaced wholesale when the version changes.
var blocklist struct {
	sync.RWMutex
	version int
	exact   map[string]struct{}
	nets    []*net.IPNet
}

// setBlocklist installs a new list if version is newer than the one held. A
// version of 0 is "none issued yet" and is ignored, so a panel too old to send
// one never clears an existing list by accident.
func setBlocklist(version int, entries []string) {
	if version == 0 {
		return
	}
	blocklist.Lock()
	defer blocklist.Unlock()
	if version == blocklist.version {
		return
	}
	exact := make(map[string]struct{})
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil {
				nets = append(nets, n)
			}
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			exact[ip.String()] = struct{}{}
		}
	}
	blocklist.version = version
	blocklist.exact = exact
	blocklist.nets = nets
}

func blocklistVersion() int {
	blocklist.RLock()
	defer blocklist.RUnlock()
	return blocklist.version
}

// blockedAddr reports whether a source is banned. Cheap enough for the accept
// path: a map hit for the common case, and the CIDR scan only when there are
// CIDRs and the exact test missed.
func blockedAddr(remoteAddr string) bool {
	host := ipOnly(remoteAddr)
	blocklist.RLock()
	defer blocklist.RUnlock()
	if blocklist.exact == nil && blocklist.nets == nil {
		return false
	}
	if _, ok := blocklist.exact[host]; ok {
		return true
	}
	if len(blocklist.nets) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range blocklist.nets {
				if n.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// nowRFC3339 is the event timestamp helper, split out so tests can pin it.
func nowRFC3339() string { return time.Now().Format(time.RFC3339) }
