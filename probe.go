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
	FP        string `json:"fp,omitempty"` // sha256 prefix of the first bytes
	DurMS     int64  `json:"dur"`
	Up        uint64 `json:"up"`
	Down      uint64 `json:"down"`
	Responded bool   `json:"resp,omitempty"`
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
