package xpfw

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

const (
	ModePanel = "panel"
	ModeNode  = "node"
)

type NodeInfo struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Addr              string         `json:"addr"`
	IPv4              string         `json:"ipv4"`
	IPv6              string         `json:"ipv6"`
	Status            string         `json:"status"`
	LastSeen          time.Time      `json:"last_seen"`
	ConfigVersion     int            `json:"config_version"`
	StatusData        map[string]int `json:"status_data"`
	CreatedAt         time.Time      `json:"created_at"`
	NodeVersion       string         `json:"node_version"`
	DesiredVersion    string         `json:"desired_version"`
	IsOutdated        bool           `json:"is_outdated"`
	LastUpdateStatus  string         `json:"last_update_status"`
	LastUpdateMessage string         `json:"last_update_message"`
	LastUpdateAt      time.Time      `json:"last_update_at"`
	CustomSNIListen   string         `json:"custom_sni_listen"`
	CPU               float64        `json:"cpu"`
	MemUsed           uint64         `json:"mem_used"`
	MemTotal          uint64         `json:"mem_total"`
	DiskUsed          uint64         `json:"disk_used"`
	DiskTotal         uint64         `json:"disk_total"`
	NetInSpeed        uint64         `json:"net_in_speed"`
	NetOutSpeed       uint64         `json:"net_out_speed"`
	NetInTransfer     uint64         `json:"net_in_transfer"`
	NetOutTransfer    uint64         `json:"net_out_transfer"`
	UptimeSeconds     uint64         `json:"uptime_seconds"`
	ForceUpdate       bool           `json:"-"`
	ForceBinUpdate    bool           `json:"-"`
}

type SystemMetrics struct {
	CPU            float64 `json:"cpu"`
	MemUsed        uint64  `json:"mem_used"`
	MemTotal       uint64  `json:"mem_total"`
	DiskUsed       uint64  `json:"disk_used"`
	DiskTotal      uint64  `json:"disk_total"`
	NetInSpeed     uint64  `json:"net_in_speed"`
	NetOutSpeed    uint64  `json:"net_out_speed"`
	NetInTransfer  uint64  `json:"net_in_transfer"`
	NetOutTransfer uint64  `json:"net_out_transfer"`
	UptimeSeconds  uint64  `json:"uptime_seconds"`
}

type HeartbeatRequest struct {
	NodeID        string `json:"node_id"`
	IPv4          string `json:"ipv4"`
	IPv6          string `json:"ipv6"`
	ConfigVersion int    `json:"config_version"`
	NodeVersion   string `json:"node_version"`
	// Arch is this build's GOARCH, so the panel can hand out the release asset
	// this machine can actually run. Without it the panel derives one URL from a
	// version tag for the whole fleet, which is how an arm64 node came to be
	// offered the amd64 build. A panel too old to read this field simply keeps
	// sending what it always did.
	Arch          string         `json:"arch,omitempty"`
	StatusData    map[string]int `json:"status_data"`
	System        *SystemMetrics `json:"system,omitempty"`
	UpdateStatus  string         `json:"update_status,omitempty"`
	UpdateMessage string         `json:"update_message,omitempty"`
	UpdateAt      string         `json:"update_at,omitempty"`
	Traffic       *NodeCounters  `json:"traffic,omitempty"`
}

// NodeCounters carries the node's own accounting of proxied traffic. The panel's
// existing net_in_transfer/net_out_transfer come from the host NIC and therefore
// include everything else running on the box; these numbers are what this
// process actually relayed, and they can be attributed to a rule.
//
// Every total is monotonic since process start and is paired with BootID. The
// panel derives deltas itself, so a dropped heartbeat only coarsens the
// resolution instead of losing the bytes: reporting deltas would discard them
// permanently whenever a POST failed, which for geographically spread nodes is
// routine rather than exceptional. A change of BootID tells the panel the
// counters restarted from zero.
type NodeCounters struct {
	BootID string `json:"boot_id"`
	// SNIMisses counts handshakes that matched no rule and fell through to
	// default_backend. A rising rate means either a missing rule or someone
	// probing the listener.
	//
	// It is the sum of the three fields below and stays on the wire in its own
	// right: a panel older than the split reads it and is none the wiser.
	SNIMisses uint64 `json:"sni_misses"`
	// The three kinds of miss, because the total cannot be acted on. A node too
	// old to report the split sends none of them, which reads as zero rather
	// than as a claim, so the panel has to treat "all three zero while SNIMisses
	// is not" as unknown rather than as no misses.
	//
	// MissNoTLS is a connection whose ClientHello could not be read at all: a
	// bare TCP connect that sent nothing, a port probe, a plain HTTP request. A
	// browser's speculative preconnect lands here too, so this is background
	// noise more often than it is hostile.
	MissNoTLS uint64 `json:"miss_no_tls,omitempty"`
	// MissNoSNI is a valid ClientHello with no server name in it, which means a
	// client that dialled this node by address instead of by hostname.
	MissNoSNI uint64 `json:"miss_no_sni,omitempty"`
	// MissNoRule is a client that asked for a specific hostname this node does
	// not serve. This is the actionable one: it means a rule is missing, or was
	// deleted while clients were still using it, or someone has pointed a domain
	// at this node.
	MissNoRule uint64 `json:"miss_no_rule,omitempty"`
	// LogLines and LogSuppressed are how much this process has written to its log
	// and how much it collapsed as repetition. Counted in the process rather than
	// read from journald: reading the journal would mean running journalctl, and
	// giving a root daemon that auto-updates from a public repository the ability
	// to execute processes is a far larger change than this question is worth. It
	// would also measure the whole shared journal rather than this node's share
	// of it, which is the number an operator actually needs.
	//
	// A high LogSuppressed is not a problem in itself -- it is the mechanism
	// working. The pair is what matters: suppressed climbing while emitted stays
	// flat means something is failing repeatedly and quietly.
	LogLines      uint64 `json:"log_lines,omitempty"`
	LogSuppressed uint64 `json:"log_suppressed,omitempty"`
	// Rules omits entries whose counters are all zero, so an idle fleet does not
	// pay for 52 rules of zeroes on every heartbeat.
	Rules []RuleCounter `json:"rules,omitempty"`
}

// RuleCounter is one rule's share of the traffic on this node. Up and Down are
// kept apart because bandwidth is usually billed on egress alone.
type RuleCounter struct {
	RuleID int `json:"rule_id"`
	// BytesUp is client to backend, BytesDown is backend to client. Both count
	// payload bytes as seen by the relay, so they run a few percent below what
	// the NIC reports for the same traffic once TCP/IP overhead is included.
	BytesUp   uint64 `json:"up"`
	BytesDown uint64 `json:"down"`
	// Conns counts accepted connections, which separates a few large transfers
	// from many small requests: the two load a node very differently.
	Conns uint64 `json:"conns"`
	// DialFail counts failures to reach a backend. Destinations that have never
	// once been reachable from this node are excluded, so a rule pointing at a
	// loopback or node-local address does not drown the signal.
	DialFail uint64 `json:"dial_fail"`
}

type probeState struct {
	failCount int
	nextProbe time.Time
	lastMS    int
}

var (
	probeCache   = make(map[string]*probeState)
	probeCacheMu sync.Mutex
	metricsMu    sync.Mutex
	lastNetIn    uint64
	lastNetOut   uint64
	lastNetAt    time.Time
	nodeUpdateMu sync.Mutex
	nodeUpdate   = struct {
		Status  string
		Message string
		At      time.Time
	}{Status: "idle"}
)

const dbTimeLayout = "2006-01-02 15:04:05"

func formatDBTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(dbTimeLayout)
}

// parseDBTime reads a timestamp written by formatDBTime. The stored strings carry
// no zone, so they have to be read back in the zone that wrote them. time.Parse
// assumes UTC, which shifted every value by the local offset and made session
// lifetimes come out wrong by that amount in either direction.
func parseDBTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.ParseInLocation(dbTimeLayout, s, time.Local); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// collectTrafficCounters snapshots the accounting for a heartbeat. Rules with
// nothing to report are omitted so an idle fleet does not carry 52 rules of
// zeroes on every beat.
func collectTrafficCounters() *NodeCounters {
	emitted, suppressed := logCounters()
	out := &NodeCounters{
		BootID:        bootID,
		SNIMisses:     totalSNIMisses(),
		MissNoTLS:     missNoTLS.Load(),
		MissNoSNI:     missNoSNI.Load(),
		MissNoRule:    missNoRule.Load(),
		LogLines:      emitted,
		LogSuppressed: suppressed,
	}

	trafficMu.RLock()
	ids := make([]int, 0, len(trafficByRule))
	for id := range trafficByRule {
		ids = append(ids, id)
	}
	trafficMu.RUnlock()
	sort.Ints(ids)

	for _, id := range ids {
		trafficMu.RLock()
		c := trafficByRule[id]
		trafficMu.RUnlock()
		if c == nil {
			continue
		}
		rc := RuleCounter{
			RuleID:    id,
			BytesUp:   c.bytesUp.Load(),
			BytesDown: c.bytesDown.Load(),
			Conns:     c.conns.Load(),
			DialFail:  c.dialFail.Load(),
		}
		if rc.BytesUp == 0 && rc.BytesDown == 0 && rc.Conns == 0 && rc.DialFail == 0 {
			continue
		}
		out.Rules = append(out.Rules, rc)
	}
	return out
}

func setNodeUpdateState(status, message string) {
	nodeUpdateMu.Lock()
	nodeUpdate.Status = strings.TrimSpace(status)
	msg := strings.TrimSpace(message)
	if len(msg) > 240 {
		msg = msg[:240]
	}
	nodeUpdate.Message = msg
	nodeUpdate.At = time.Now()
	nodeUpdateMu.Unlock()
}

// getNodeUpdateState reports the pending update state without consuming it.
// Terminal states (ok/failed) are only cleared by clearNodeUpdateState once the
// heartbeat carrying them has actually been accepted, otherwise a single failed
// POST loses the result forever and the panel shows "running" indefinitely.
func getNodeUpdateState() (string, string, string) {
	nodeUpdateMu.Lock()
	defer nodeUpdateMu.Unlock()
	if nodeUpdate.Status == "" || nodeUpdate.Status == "idle" {
		return "", "", ""
	}
	return nodeUpdate.Status, nodeUpdate.Message, nodeUpdate.At.Format(time.RFC3339)
}

// clearNodeUpdateState retires a terminal state after it has been delivered.
// reported is the status the successful heartbeat actually carried, so a state
// that changed in the meantime is left for the next heartbeat.
func clearNodeUpdateState(reported string) {
	if reported != "ok" && reported != "failed" {
		return
	}
	nodeUpdateMu.Lock()
	defer nodeUpdateMu.Unlock()
	if nodeUpdate.Status == reported {
		nodeUpdate.Status = "idle"
		nodeUpdate.Message = ""
	}
}

// publicIPCache memoises this node's own public addresses. Resolving them walks
// up to three external endpoints with a 5s timeout each; doing that inline on
// every heartbeat could stall the heartbeat loop for ~30s per address family and
// push the effective interval past the panel's 90s offline threshold, so a node
// with restricted egress would flap offline while perfectly healthy.
var publicIPCache = struct {
	sync.Mutex
	v map[int]publicIPEntry
}{v: make(map[int]publicIPEntry)}

type publicIPEntry struct {
	ip         string
	expiresAt  time.Time
	refreshing bool
}

const publicIPTTL = 10 * time.Minute

// getCachedPublicIP returns the last known address immediately and refreshes it
// in the background once the TTL lapses, so the heartbeat never blocks on it.
func getCachedPublicIP(version int) string {
	now := time.Now()
	publicIPCache.Lock()
	entry, ok := publicIPCache.v[version]
	stale := !ok || now.After(entry.expiresAt)
	if stale && !entry.refreshing {
		entry.refreshing = true
		publicIPCache.v[version] = entry
		go refreshPublicIP(version)
	}
	publicIPCache.Unlock()
	return entry.ip
}

func refreshPublicIP(version int) {
	ip := getPublicIP(version)
	publicIPCache.Lock()
	entry := publicIPCache.v[version]
	entry.refreshing = false
	// A failed probe keeps the previous value but retries sooner.
	if ip != "" {
		entry.ip = ip
		entry.expiresAt = time.Now().Add(publicIPTTL)
	} else {
		entry.expiresAt = time.Now().Add(time.Minute)
	}
	publicIPCache.v[version] = entry
	publicIPCache.Unlock()
}

func getPublicIP(version int) string {
	endpoints := []string{
		"https://api64.ipify.org",
		"https://ident.me",
		"https://ifconfig.me/ip",
	}
	network := "tcp4"
	if version == 6 {
		network = "tcp6"
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
		Timeout: 5 * time.Second,
	}

	for _, url := range endpoints {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ipStr := strings.TrimSpace(string(body))
		if net.ParseIP(ipStr) != nil {
			return ipStr
		}
	}
	return ""
}

type HeartbeatResponse struct {
	Status           string `json:"status"`
	ConfigVersion    int    `json:"config_version"`
	NeedUpdate       bool   `json:"need_update"`
	NeedBinaryUpdate bool   `json:"need_binary_update"`
	LatestVersion    string `json:"latest_version"`
	BinaryURL        string `json:"binary_url"`
}

type ConfigResponse struct {
	Config        Config `json:"config"`
	Rules         []Rule `json:"rules"`
	ConfigVersion int    `json:"config_version"`
}

var (
	panelConfig struct {
		Mode         string `json:"mode"`
		PanelURL     string `json:"panel_url"`
		PanelToken   string `json:"panel_token"`
		NodeID       string `json:"node_id"`
		PullInterval int    `json:"pull_interval"`
	}
	panelConfigMu sync.RWMutex

	managedNodes   = make(map[string]*NodeInfo)
	managedNodesMu sync.RWMutex

	configVersionCounter = 0
	configVersionMu      sync.Mutex
)

func init() {
	panelConfig.PullInterval = 30
}

func startPanel(token string) {
	panelConfigMu.Lock()
	panelConfig.Mode = ModePanel
	panelConfig.PanelToken = token
	panelConfigMu.Unlock()

	http.HandleFunc("/api/node/heartbeat", handleNodeHeartbeat)
	http.HandleFunc("/api/node/config", handleNodeConfigPull)
	http.HandleFunc("/api/panel/nodes", authMiddleware(handlePanelNodes))
	http.HandleFunc("/api/panel/node/rename", authMiddleware(handleNodeRename))
	http.HandleFunc("/api/panel/node/delete", authMiddleware(handleNodeDelete))
	http.HandleFunc("/api/panel/node/set-listen", authMiddleware(handleNodeSetListen))
	http.HandleFunc("/api/panel/node/update", authMiddleware(handleNodeUpdate))

	go cleanupOfflineNodes()

	loadNodesFromDB()

	log.Info("management panel started")
}

func extractNodeCommKey(r *http.Request) string {
	key := strings.TrimSpace(r.Header.Get("X-XPFW-Key"))
	if key != "" {
		return key
	}
	key = strings.TrimSpace(r.Header.Get("X-Panel-Key"))
	if key != "" {
		return key
	}
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return strings.TrimSpace(raw[7:])
	}
	return raw
}

func validateNodeCommKey(r *http.Request) bool {
	received := extractNodeCommKey(r)
	panelConfigMu.RLock()
	expected := strings.TrimSpace(panelConfig.PanelToken)
	panelConfigMu.RUnlock()
	if received == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(received), []byte(expected)) == 1
}

func handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !validateNodeCommKey(r) {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	nodeID := req.NodeID
	if nodeID == "" {
		http.Error(w, `{"error":"Node ID required"}`, http.StatusBadRequest)
		return
	}

	managedNodesMu.Lock()
	node, exists := managedNodes[nodeID]

	remoteIP := getClientIP(r)

	if !exists {
		node = &NodeInfo{
			ID:               nodeID,
			Name:             fmt.Sprintf("节点-%s", nodeID[:8]),
			Addr:             remoteIP,
			IPv4:             req.IPv4,
			IPv6:             req.IPv6,
			Status:           "online",
			LastSeen:         time.Now(),
			ConfigVersion:    req.ConfigVersion,
			NodeVersion:      req.NodeVersion,
			LastUpdateStatus: "idle",
			StatusData:       req.StatusData,
			CreatedAt:        time.Now(),
		}
		if req.System != nil {
			node.CPU = req.System.CPU
			node.MemUsed = req.System.MemUsed
			node.MemTotal = req.System.MemTotal
			node.DiskUsed = req.System.DiskUsed
			node.DiskTotal = req.System.DiskTotal
			node.NetInSpeed = req.System.NetInSpeed
			node.NetOutSpeed = req.System.NetOutSpeed
			node.NetInTransfer = req.System.NetInTransfer
			node.NetOutTransfer = req.System.NetOutTransfer
			node.UptimeSeconds = req.System.UptimeSeconds
		}
		managedNodes[nodeID] = node
		saveNodeToDB(node)
		log.Infof("new node registered: %s (IP: %s)", nodeID, remoteIP)
	} else {
		node.Status = "online"
		node.LastSeen = time.Now()
		node.Addr = remoteIP
		node.IPv4 = req.IPv4
		node.IPv6 = req.IPv6
		node.ConfigVersion = req.ConfigVersion
		node.NodeVersion = req.NodeVersion
		node.StatusData = req.StatusData
		if req.System != nil {
			node.CPU = req.System.CPU
			node.MemUsed = req.System.MemUsed
			node.MemTotal = req.System.MemTotal
			node.DiskUsed = req.System.DiskUsed
			node.DiskTotal = req.System.DiskTotal
			node.NetInSpeed = req.System.NetInSpeed
			node.NetOutSpeed = req.System.NetOutSpeed
			node.NetInTransfer = req.System.NetInTransfer
			node.NetOutTransfer = req.System.NetOutTransfer
			node.UptimeSeconds = req.System.UptimeSeconds
		}
		if req.UpdateStatus != "" {
			node.LastUpdateStatus = req.UpdateStatus
			node.LastUpdateMessage = req.UpdateMessage
			if ts, err := time.Parse(time.RFC3339, req.UpdateAt); err == nil {
				node.LastUpdateAt = ts
			} else {
				node.LastUpdateAt = time.Now()
			}
		}

		if (node.LastUpdateStatus == "pending" || node.LastUpdateStatus == "running") && req.NodeVersion == NodeVersion {
			node.LastUpdateStatus = "ok"
			node.LastUpdateMessage = "binary updated and restarted"
			node.LastUpdateAt = time.Now()
		}
		updateNodeInDB(node)
	}
	managedNodesMu.Unlock()

	configVersionMu.Lock()
	currentVersion := configVersionCounter
	configVersionMu.Unlock()

	managedNodesMu.Lock()
	forceUpdate := false
	forceBinUpdate := false
	if n, ok := managedNodes[nodeID]; ok && n.ForceUpdate {
		forceUpdate = true
		n.ForceUpdate = false
		db.Exec("UPDATE nodes SET force_update = 0 WHERE id = ?", nodeID)
	}
	if n, ok := managedNodes[nodeID]; ok && n.ForceBinUpdate {
		forceBinUpdate = true
		n.ForceBinUpdate = false
		n.LastUpdateStatus = "running"
		n.LastUpdateMessage = "binary update command accepted by node heartbeat"
		n.LastUpdateAt = time.Now()
		db.Exec("UPDATE nodes SET force_binary_update = 0 WHERE id = ?", nodeID)
		updateNodeInDB(n)
	}
	managedNodesMu.Unlock()

	resp := HeartbeatResponse{
		Status:           "ok",
		ConfigVersion:    currentVersion,
		NeedUpdate:       req.ConfigVersion < currentVersion || forceUpdate,
		NeedBinaryUpdate: forceBinUpdate && req.NodeVersion != NodeVersion,
		LatestVersion:    NodeVersion,
		BinaryURL:        binaryURLForVersion(NodeVersion),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleNodeConfigPull(w http.ResponseWriter, r *http.Request) {
	if !validateNodeCommKey(r) {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	configMu.RLock()
	cfg := globalConfig
	configMu.RUnlock()

	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
	} else {
		managedNodesMu.RLock()
		if n, ok := managedNodes[nodeID]; ok && n.CustomSNIListen != "" {
			cfg.SNIListen = n.CustomSNIListen
		}
		managedNodesMu.RUnlock()
	}

	rules, err := getAllRules()
	if err != nil {
		http.Error(w, `{"error":"Failed to get rules"}`, http.StatusInternalServerError)
		return
	}

	configVersionMu.Lock()
	version := configVersionCounter
	configVersionMu.Unlock()

	resp := ConfigResponse{
		Config:        cfg,
		Rules:         rules,
		ConfigVersion: version,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handlePanelNodes(w http.ResponseWriter, r *http.Request) {
	managedNodesMu.RLock()
	defer managedNodesMu.RUnlock()

	nodeList := make([]*NodeInfo, 0, len(managedNodes))
	for _, node := range managedNodes {
		isOutdated := strings.TrimSpace(node.NodeVersion) != strings.TrimSpace(NodeVersion)
		status := node.LastUpdateStatus
		if status == "" {
			status = "idle"
		}
		nodeList = append(nodeList, &NodeInfo{
			ID:                node.ID,
			Name:              node.Name,
			Addr:              node.Addr,
			IPv4:              node.IPv4,
			IPv6:              node.IPv6,
			Status:            node.Status,
			LastSeen:          node.LastSeen,
			ConfigVersion:     node.ConfigVersion,
			StatusData:        node.StatusData,
			CreatedAt:         node.CreatedAt,
			NodeVersion:       node.NodeVersion,
			DesiredVersion:    NodeVersion,
			IsOutdated:        isOutdated,
			LastUpdateStatus:  status,
			LastUpdateMessage: node.LastUpdateMessage,
			LastUpdateAt:      node.LastUpdateAt,
			CustomSNIListen:   node.CustomSNIListen,
			CPU:               node.CPU,
			MemUsed:           node.MemUsed,
			MemTotal:          node.MemTotal,
			DiskUsed:          node.DiskUsed,
			DiskTotal:         node.DiskTotal,
			NetInSpeed:        node.NetInSpeed,
			NetOutSpeed:       node.NetOutSpeed,
			NetInTransfer:     node.NetInTransfer,
			NetOutTransfer:    node.NetOutTransfer,
			UptimeSeconds:     node.UptimeSeconds,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodeList)
}

func handleNodeRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID  string `json:"node_id"`
		NewName string `json:"new_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	managedNodesMu.Lock()
	node, exists := managedNodes[req.NodeID]
	if !exists {
		managedNodesMu.Unlock()
		http.Error(w, `{"error":"Node not found"}`, http.StatusNotFound)
		return
	}

	node.Name = req.NewName
	updateNodeInDB(node)
	managedNodesMu.Unlock()

	log.Infof("node renamed: %s -> %s", req.NodeID, req.NewName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleNodeSetListen(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID    string `json:"node_id"`
		SNIListen string `json:"sni_listen"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	managedNodesMu.Lock()
	node, exists := managedNodes[req.NodeID]
	if !exists {
		managedNodesMu.Unlock()
		http.Error(w, `{"error":"Node not found"}`, http.StatusNotFound)
		return
	}

	node.CustomSNIListen = req.SNIListen
	node.ForceUpdate = true
	updateNodeInDB(node)
	managedNodesMu.Unlock()

	log.Infof("node %s custom_sni_listen set to %q", req.NodeID, req.SNIListen)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleNodeUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	managedNodesMu.Lock()
	node, exists := managedNodes[req.NodeID]
	if !exists {
		managedNodesMu.Unlock()
		http.Error(w, `{"error":"Node not found"}`, http.StatusNotFound)
		return
	}
	node.ForceBinUpdate = true
	node.LastUpdateStatus = "pending"
	node.LastUpdateMessage = "update command queued, waiting for next heartbeat"
	node.LastUpdateAt = time.Now()
	updateNodeInDB(node)
	managedNodesMu.Unlock()

	log.Infof("node %s binary update requested", req.NodeID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID string `json:"node_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	managedNodesMu.Lock()
	if _, exists := managedNodes[req.NodeID]; !exists {
		managedNodesMu.Unlock()
		http.Error(w, `{"error":"Node not found"}`, http.StatusNotFound)
		return
	}
	delete(managedNodes, req.NodeID)
	managedNodesMu.Unlock()

	db.Exec("DELETE FROM nodes WHERE id = ?", req.NodeID)

	log.Infof("node deleted: %s", req.NodeID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func cleanupOfflineNodes() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		managedNodesMu.Lock()
		for _, node := range managedNodes {
			if time.Since(node.LastSeen) > 90*time.Second {
				if node.Status == "online" {
					node.Status = "offline"
					updateNodeInDB(node)
					log.Warnf("node offline: %s (%s)", node.Name, node.ID)
				}
			}
		}
		managedNodesMu.Unlock()
	}
}

func incrementConfigVersion() int {
	configVersionMu.Lock()
	configVersionCounter++
	version := configVersionCounter
	configVersionMu.Unlock()

	log.Infof("config version updated to %d", version)
	db.Exec("UPDATE panel_config SET value = ? WHERE key = 'config_version'", version)
	return version
}

func startNode(panelURL, token, nodeID string, pullInterval int) {
	panelConfigMu.Lock()
	panelConfig.Mode = ModeNode
	panelConfig.PanelURL = panelURL
	panelConfig.PanelToken = token
	panelConfig.NodeID = nodeID
	panelConfig.PullInterval = pullInterval
	panelConfigMu.Unlock()

	// A fresh id each start tells the panel the counters below restarted at zero.
	if b, err := generateCommKey(); err == nil {
		bootID = b
	} else {
		bootID = fmt.Sprintf("boot-%d", time.Now().UnixNano())
	}

	log.Infof("node mode initialized, panel: %s, node_id: %s, boot: %s", panelURL, nodeID, bootID)

	if !panelChannelIsSecure() {
		// Worth stating plainly at startup: over plain HTTP the shared token
		// travels in clear text on every heartbeat and the responses can be
		// rewritten in transit, so binary updates are refused (see sendHeartbeat).
		log.Warnf("SECURITY: panel url %q is not https — the node token is sent in clear text, "+
			"responses can be tampered with, and binary self-update will be refused. Put the panel behind TLS.", panelURL)
	}

	go pullConfigFromPanel()

	go heartbeatLoop()
}

func heartbeatLoop() {
	panelConfigMu.RLock()
	interval := panelConfig.PullInterval
	if interval <= 0 {
		interval = 10
	}
	panelConfigMu.RUnlock()

	go sendHeartbeat()

	go startProbingLoop()

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sendHeartbeat()
	}
}

func startProbingLoop() {
	go runProbing()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		runProbing()
	}
}

func runProbing() {
	rules, err := getAllRules()
	if err != nil {
		return
	}

	active := make(map[string]struct{})
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, dest := range rule.Dest {
			active[dest] = struct{}{}
			go probeTarget(dest)
		}
	}
	pruneProbeCache(active)
}

// pruneProbeCache drops entries for targets no longer referenced by an enabled
// rule. Without it the cache only ever grows, and every heartbeat keeps
// reporting latency for destinations that were deleted long ago — on a
// long-running node that inflates the heartbeat payload indefinitely.
func pruneProbeCache(active map[string]struct{}) {
	probeCacheMu.Lock()
	defer probeCacheMu.Unlock()
	for target := range probeCache {
		if _, ok := active[target]; !ok {
			delete(probeCache, target)
		}
	}
}

func collectSystemMetrics() *SystemMetrics {
	m := &SystemMetrics{}

	if cp, err := cpu.Percent(0, false); err == nil && len(cp) > 0 {
		m.CPU = cp[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		m.MemUsed = vm.Total - vm.Available
		m.MemTotal = vm.Total
	}
	if du, err := disk.Usage("/"); err == nil {
		m.DiskUsed = du.Used
		m.DiskTotal = du.Total
	}
	if io, err := psnet.IOCounters(false); err == nil && len(io) > 0 {
		m.NetInTransfer = io[0].BytesRecv
		m.NetOutTransfer = io[0].BytesSent

		now := time.Now()
		metricsMu.Lock()
		if !lastNetAt.IsZero() {
			sec := now.Sub(lastNetAt).Seconds()
			if sec > 0 {
				if m.NetInTransfer >= lastNetIn {
					m.NetInSpeed = uint64(float64(m.NetInTransfer-lastNetIn) / sec)
				}
				if m.NetOutTransfer >= lastNetOut {
					m.NetOutSpeed = uint64(float64(m.NetOutTransfer-lastNetOut) / sec)
				}
			}
		}
		lastNetIn = m.NetInTransfer
		lastNetOut = m.NetOutTransfer
		lastNetAt = now
		metricsMu.Unlock()
	}
	if up, err := host.Uptime(); err == nil {
		m.UptimeSeconds = up
	}

	return m
}

func probeTarget(target string) {
	probeCacheMu.Lock()
	state, exists := probeCache[target]
	if !exists {
		state = &probeState{}
		probeCache[target] = state
	}

	if time.Now().Before(state.nextProbe) {
		probeCacheMu.Unlock()
		log.Debugf("[Probe] %s skipping due to cooldown", target)
		return
	}
	probeCacheMu.Unlock()

	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	latency := int(time.Since(start).Milliseconds())

	probeCacheMu.Lock()
	defer probeCacheMu.Unlock()

	if err != nil {
		state.failCount++
		state.lastMS = -1
		if conn != nil {
			conn.Close()
		}
		log.Warnf("[Probe] %s failed (%d/3): %v", target, state.failCount, err)
		if state.failCount >= 3 {
			state.nextProbe = time.Now().Add(30 * time.Second)
			log.Errorf("[Probe] %s triggered circuit breaker, 30s cooldown", target)
		}
	} else {
		conn.Close()
		state.failCount = 0
		state.lastMS = latency
		state.nextProbe = time.Time{}
		log.Infof("[Probe] %s success: %dms", target, latency)
	}
}

func sendHeartbeat() {
	panelConfigMu.RLock()
	panelURL := panelConfig.PanelURL
	token := panelConfig.PanelToken
	nodeID := panelConfig.NodeID
	panelConfigMu.RUnlock()

	configVersionMu.Lock()
	currentVersion := configVersionCounter
	configVersionMu.Unlock()

	statusData := make(map[string]int)
	probeCacheMu.Lock()
	for target, state := range probeCache {
		statusData[target] = state.lastMS
	}
	probeCacheMu.Unlock()

	req := HeartbeatRequest{
		NodeID:        nodeID,
		IPv4:          getCachedPublicIP(4),
		IPv6:          getCachedPublicIP(6),
		ConfigVersion: currentVersion,
		NodeVersion:   NodeVersion,
		Arch:          runtime.GOARCH,
		StatusData:    statusData,
		System:        collectSystemMetrics(),
		Traffic:       collectTrafficCounters(),
	}
	reportedStatus, message, at := getNodeUpdateState()
	if reportedStatus != "" {
		req.UpdateStatus = reportedStatus
		req.UpdateMessage = message
		req.UpdateAt = at
	}

	log.Infof("[Heartbeat] sending... (version: %d, targets: %d)", currentVersion, len(statusData))

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequest("POST", panelURL+"/api/node/heartbeat", bytes.NewReader(body))
	if err != nil {
		log.Errorf("create heartbeat request failed: %v", err)
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-XPFW-Key", token)
	httpReq.Header.Set("Authorization", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Errorf("send heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("heartbeat failed with status: %d", resp.StatusCode)
		return
	}

	var heartbeatResp HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&heartbeatResp); err != nil {
		log.Errorf("decode heartbeat response failed: %v", err)
		return
	}

	// The panel has the result now, so the terminal state can be retired. Doing
	// this any earlier loses the outcome whenever the POST itself fails.
	clearNodeUpdateState(reportedStatus)

	if heartbeatResp.NeedUpdate {
		log.Infof("[Heartbeat] remote version %d is newer than local %d, pulling update...", heartbeatResp.ConfigVersion, currentVersion)
		pullConfigFromPanel()
	}
	if heartbeatResp.NeedBinaryUpdate {
		log.Infof("[Heartbeat] binary update requested: local=%s latest=%s", NodeVersion, heartbeatResp.LatestVersion)
		if !panelChannelIsSecure() {
			// Not fatal, because plenty of panels are reachable only over HTTP and
			// blocking updates outright would strand them. The protection that
			// actually matters is validateBinaryURL's host allowlist: with it, a
			// tampered response can at worst point this node at a genuine release
			// of this project, not at attacker-supplied code.
			log.Warnf("panel url is not https: this update instruction cannot be authenticated, " +
				"and only the download host allowlist is preventing arbitrary code from being installed. Put the panel behind TLS.")
		}
		setNodeUpdateState("running", "binary update started")
		if err := updateBinaryAndExit(heartbeatResp.BinaryURL); err != nil {
			setNodeUpdateState("failed", fmt.Sprintf("binary update failed: %v", err))
			log.Errorf("binary update failed: %v", err)
		}
	}
}

func pullConfigFromPanel() {
	panelConfigMu.RLock()
	panelURL := panelConfig.PanelURL
	token := panelConfig.PanelToken
	nodeID := panelConfig.NodeID
	panelConfigMu.RUnlock()

	log.Infof("[Sync] pulling configuration from %s...", panelURL)
	httpReq, err := http.NewRequest("GET", panelURL+"/api/node/config?node_id="+nodeID, nil)
	if err != nil {
		log.Errorf("create config pull request failed: %v", err)
		return
	}

	httpReq.Header.Set("X-XPFW-Key", token)
	httpReq.Header.Set("Authorization", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Errorf("pull config failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("pull config failed with status: %d", resp.StatusCode)
		return
	}

	var configResp ConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&configResp); err != nil {
		log.Errorf("decode config response failed: %v", err)
		return
	}

	applyConfigFromPanel(configResp)
}

func applyConfigFromPanel(configResp ConfigResponse) {
	configMu.RLock()
	oldSNIListen := globalConfig.SNIListen
	oldLogLevel := globalConfig.LogLevel
	localWebPanel := globalConfig.WebPanel
	localWebAuth := globalConfig.WebAuth
	localWebTitle := globalConfig.WebTitle
	configMu.RUnlock()

	// The panel's own web credentials are none of this node's business, and this
	// node's are none of the panel's. Taking them from the pulled config used to
	// overwrite the local panel password with whatever the control panel used —
	// and once the panel stopped sending it, with an empty string, which would
	// leave this node's own web panel with no password at all.
	incoming := configResp.Config
	incoming.WebPanel = localWebPanel
	incoming.WebAuth = localWebAuth
	if strings.TrimSpace(incoming.WebTitle) == "" {
		incoming.WebTitle = localWebTitle
	}

	if err := saveConfig(incoming); err != nil {
		log.Errorf("save pulled config failed: %v", err)
		return
	}

	// setLogLevel as well as saveConfig: the level was reaching the database and
	// stopping there, so changing it from the panel appeared to do nothing until
	// the process happened to restart. It is the one setting an operator changes
	// specifically to watch what is happening right now, which makes a silent
	// delay of unbounded length the worst possible behaviour for it.
	if strings.TrimSpace(incoming.LogLevel) != "" && incoming.LogLevel != oldLogLevel {
		log.Infof("[Sync] log level changed: %q -> %q", oldLogLevel, incoming.LogLevel)
		setLogLevel(incoming.LogLevel)
	}

	if err := applyRules(configResp.Rules, configResp.ConfigVersion); err != nil {
		log.Errorf("apply pulled rules failed: %v", err)
		return
	}

	configVersionMu.Lock()
	configVersionCounter = configResp.ConfigVersion
	configVersionMu.Unlock()

	log.Infof("config applied successfully (version: %d, rules: %d, sni_listen: %s)", configResp.ConfigVersion, len(configResp.Rules), incoming.SNIListen)

	if incoming.SNIListen != "" && incoming.SNIListen != oldSNIListen {
		log.Infof("[Sync] SNI listen address changed: %q -> %q, restarting listener...", oldSNIListen, configResp.Config.SNIListen)
		go restartSNIListener(configResp.Config.SNIListen)
	}

	go runProbing()
}

func applyRules(rules []Rule, configVersion int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM rules"); err != nil {
		return err
	}

	type portStart struct {
		id       int
		name     string
		port     int
		dest     []string
		strategy string
	}
	var portStarts []portStart

	for _, rule := range rules {
		rule.SNI = normalizeSNI(rule.SNI)
		destJSON, _ := json.Marshal(rule.Dest)
		enabled := 0
		if rule.Enabled {
			enabled = 1
		}

		// The panel's id is stored, not left to AUTOINCREMENT. These ids are what
		// the traffic counters report back, and the panel resolves them against its
		// own rules table: a local id means nothing there. Because this function
		// deletes and reinserts every rule on each config push, the local sequence
		// climbed by the whole rule count every time, so the reported ids were not
		// merely wrong but different on every push -- the panel labelled all of
		// them "(deleted #id)" and per-rule traffic could never be attributed.
		ruleID := rule.ID
		if ruleID <= 0 {
			// A panel too old to send ids leaves attribution impossible either way;
			// let SQLite assign one so the rule itself still works.
			result, err := tx.Exec(`
				INSERT INTO rules (name, type, sni, listen_port, dest, lb_strategy, enabled, version)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`, rule.Name, rule.Type, rule.SNI, rule.ListenPort, string(destJSON), rule.LBStrategy, enabled, configVersion)
			if err != nil {
				return err
			}
			id, _ := result.LastInsertId()
			ruleID = int(id)
		} else if _, err := tx.Exec(`
			INSERT INTO rules (id, name, type, sni, listen_port, dest, lb_strategy, enabled, version)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, ruleID, rule.Name, rule.Type, rule.SNI, rule.ListenPort, string(destJSON), rule.LBStrategy, enabled, configVersion); err != nil {
			return err
		}

		if rule.Type == RuleTypePort && rule.Enabled {
			portStarts = append(portStarts, portStart{
				id:       ruleID,
				name:     rule.Name,
				port:     rule.ListenPort,
				dest:     rule.Dest,
				strategy: rule.LBStrategy,
			})
		}
	}

	if _, err := tx.Exec("UPDATE panel_config SET value = ? WHERE key = 'config_version'", configVersion); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	portListenersMu.Lock()
	for port, pf := range portListeners {
		log.Infof("stopping port forwarder on :%d for config update", port)
		pf.cancel()
		if pf.ln != nil {
			_ = pf.ln.Close()
		}
	}
	portListeners = make(map[int]*portForwarder)
	portListenersMu.Unlock()

	for _, ps := range portStarts {
		ctx := context.Background()
		go startPortForwarder(ctx, ps.id, ps.name, ps.port, ps.dest, ps.strategy)
	}

	if err := rebuildSniRouteCacheFromDB(); err != nil {
		return err
	}
	return nil
}

func loadNodesFromDB() {
	rows, err := db.Query("SELECT id, name, addr, COALESCE(ipv4,''), COALESCE(ipv6,''), status, last_seen, config_version, COALESCE(status_data,''), created_at, COALESCE(node_version,''), COALESCE(custom_sni_listen,''), COALESCE(force_update,0), COALESCE(force_binary_update,0), COALESCE(last_update_status,''), COALESCE(last_update_message,''), COALESCE(last_update_at,'') FROM nodes")
	if err != nil {
		log.Warnf("load nodes from db failed: %v", err)
		return
	}
	defer rows.Close()

	managedNodesMu.Lock()
	defer managedNodesMu.Unlock()

	for rows.Next() {
		var node NodeInfo
		var lastSeenStr, createdAtStr, statusJSON, lastUpdateAtStr string
		var forceUpdateInt, forceBinaryUpdateInt int
		if err := rows.Scan(&node.ID, &node.Name, &node.Addr, &node.IPv4, &node.IPv6, &node.Status, &lastSeenStr, &node.ConfigVersion, &statusJSON, &createdAtStr, &node.NodeVersion, &node.CustomSNIListen, &forceUpdateInt, &forceBinaryUpdateInt, &node.LastUpdateStatus, &node.LastUpdateMessage, &lastUpdateAtStr); err != nil {
			continue
		}

		node.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeenStr)
		node.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		if strings.TrimSpace(lastUpdateAtStr) != "" {
			node.LastUpdateAt, _ = time.Parse("2006-01-02 15:04:05", lastUpdateAtStr)
		}
		node.ForceUpdate = forceUpdateInt == 1
		node.ForceBinUpdate = forceBinaryUpdateInt == 1
		json.Unmarshal([]byte(statusJSON), &node.StatusData)
		managedNodes[node.ID] = &node
	}

	log.Infof("loaded %d nodes from database", len(managedNodes))
}

func saveNodeToDB(node *NodeInfo) {
	statusJSON, _ := json.Marshal(node.StatusData)
	forceUpdateInt := 0
	forceBinaryUpdateInt := 0
	if node.ForceUpdate {
		forceUpdateInt = 1
	}
	if node.ForceBinUpdate {
		forceBinaryUpdateInt = 1
	}
	db.Exec(`
		INSERT OR REPLACE INTO nodes (id, name, addr, ipv4, ipv6, status, last_seen, config_version, status_data, created_at, node_version, custom_sni_listen, force_update, force_binary_update, last_update_status, last_update_message, last_update_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, node.ID, node.Name, node.Addr, node.IPv4, node.IPv6, node.Status,
		node.LastSeen.Format("2006-01-02 15:04:05"),
		node.ConfigVersion,
		string(statusJSON),
		node.CreatedAt.Format("2006-01-02 15:04:05"),
		node.NodeVersion,
		node.CustomSNIListen,
		forceUpdateInt,
		forceBinaryUpdateInt,
		node.LastUpdateStatus,
		node.LastUpdateMessage,
		node.LastUpdateAt.Format("2006-01-02 15:04:05"))
}

func updateNodeInDB(node *NodeInfo) {
	statusJSON, _ := json.Marshal(node.StatusData)
	forceUpdateInt := 0
	forceBinaryUpdateInt := 0
	if node.ForceUpdate {
		forceUpdateInt = 1
	}
	if node.ForceBinUpdate {
		forceBinaryUpdateInt = 1
	}
	db.Exec(`
		UPDATE nodes SET name = ?, addr = ?, ipv4 = ?, ipv6 = ?, status = ?, last_seen = ?, config_version = ?, status_data = ?, node_version = ?, custom_sni_listen = ?, force_update = ?, force_binary_update = ?, last_update_status = ?, last_update_message = ?, last_update_at = ?
		WHERE id = ?
	`, node.Name, node.Addr, node.IPv4, node.IPv6, node.Status,
		node.LastSeen.Format("2006-01-02 15:04:05"),
		node.ConfigVersion,
		string(statusJSON),
		node.NodeVersion,
		node.CustomSNIListen,
		forceUpdateInt,
		forceBinaryUpdateInt,
		node.LastUpdateStatus,
		node.LastUpdateMessage,
		node.LastUpdateAt.Format("2006-01-02 15:04:05"),
		node.ID)
}

const (
	// maxBinaryArchiveSize bounds the download. The URL is supplied by the
	// panel, so an unbounded io.ReadAll would let a wrong or hostile URL exhaust
	// this node's memory.
	maxBinaryArchiveSize = 128 << 20 // 128 MiB
	// maxBinaryPayloadSize bounds the decompressed binary, so a small archive
	// cannot expand into gigabytes (a decompression bomb).
	maxBinaryPayloadSize = 256 << 20 // 256 MiB
	// minBinaryPayloadSize rejects an obviously truncated build before it
	// replaces a working one.
	minBinaryPayloadSize = 1 << 20 // 1 MiB
)

// allowedBinaryHostsEnv lets an operator opt into extra download hosts, as a
// comma-separated list. Anything not listed is refused rather than warned about:
// the URL arrives in an unauthenticated heartbeat response, so treating an
// unexpected host as merely noteworthy is what turns a hijacked response into
// arbitrary root code execution on this node.
const allowedBinaryHostsEnv = "XPN_ALLOWED_BINARY_HOSTS"

func binaryHostAllowed(host string) bool {
	host = strings.ToLower(host)
	if host == "github.com" || strings.HasSuffix(host, ".github.com") {
		return true
	}
	for _, extra := range strings.Split(os.Getenv(allowedBinaryHostsEnv), ",") {
		extra = strings.ToLower(strings.TrimSpace(extra))
		if extra != "" && extra == host {
			return true
		}
	}
	return false
}

// validateBinaryURL decides whether a URL handed to us by the panel may be used
// to replace this node's own executable.
//
// The sha256 companion file is fetched from the same origin as the archive, so
// it can only prove the download was not corrupted in transit — it proves
// nothing about who produced the binary. There is also no authentication on the
// heartbeat *response*: the node signs its requests with the shared token, but
// anything coming back is taken on faith. So the transport and the origin are
// the only things standing between a hijacked response and root code execution,
// and both are enforced here rather than merely logged.
func validateBinaryURL(raw string) error {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid binary url: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("refusing to update over %q: binary url must use https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid binary url: missing host")
	}
	if !binaryHostAllowed(u.Host) {
		return fmt.Errorf("refusing to fetch node binary from unapproved host %q (set %s to allow it)", u.Host, allowedBinaryHostsEnv)
	}
	return nil
}

// panelChannelIsSecure reports whether the control channel itself is protected.
// A plain-HTTP panel URL means the heartbeat response can be rewritten by anyone
// on the path, so a "replace your executable" instruction arriving over it
// cannot be trusted at all — config sync over HTTP is merely an information
// leak, but honouring a binary swap would be handing over the machine.
func panelChannelIsSecure() bool {
	panelConfigMu.RLock()
	raw := strings.TrimSpace(panelConfig.PanelURL)
	panelConfigMu.RUnlock()

	u, err := neturl.Parse(raw)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}

// looksLikeLinuxExecutable checks the ELF magic. A matching sha256 only proves
// the archive arrived intact, not that it contains a runnable build; without
// this check a bad release would be swapped in, fail to exec, and leave systemd
// restart-looping with no working binary to fall back to.
func looksLikeLinuxExecutable(payload []byte) bool {
	return len(payload) >= 4 && payload[0] == 0x7f && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'F'
}

// expectedELFMachine is the ELF machine type a binary must declare to be
// runnable on this build's architecture. An architecture missing from this table
// is not judged, so an exotic platform is never blocked by a check that cannot
// speak for it.
var expectedELFMachine = map[string]elf.Machine{
	"amd64":    elf.EM_X86_64,
	"arm64":    elf.EM_AARCH64,
	"386":      elf.EM_386,
	"arm":      elf.EM_ARM,
	"riscv64":  elf.EM_RISCV,
	"ppc64le":  elf.EM_PPC64,
	"s390x":    elf.EM_S390,
	"mips64le": elf.EM_MIPS,
}

// checkExecutableMatchesHost refuses a binary built for another architecture.
//
// The ELF magic alone does not distinguish an amd64 build from an arm64 one, and
// the panel derives the download URL from a version tag without knowing what a
// given node runs — so an arm64 node could be handed the amd64 asset, pass every
// other check, install it, and then fail to exec. With Restart=always that is
// not a failed update but a bricked machine: systemd restart-loops a binary the
// kernel refuses to run, and the only way back is SSH. The node is the one party
// that knows its own architecture for certain, so it is the right place to say no.
//
// Refusing here leaves the working binary untouched and reports "failed" to the
// panel on the next heartbeat, which is a recoverable outcome.
func checkExecutableMatchesHost(payload []byte) error {
	want, known := expectedELFMachine[runtime.GOARCH]
	if !known {
		return nil
	}
	f, err := elf.NewFile(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("cannot read ELF header: %w", err)
	}
	if f.Machine != want {
		return fmt.Errorf("binary is built for %s but this node is %s (%s); refusing to install it",
			f.Machine, runtime.GOARCH, want)
	}
	return nil
}

func updateBinaryAndExit(url string) error {
	if strings.TrimSpace(url) == "" {
		url = binaryURLForVersion(NodeVersion)
	}
	if err := validateBinaryURL(url); err != nil {
		return err
	}

	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download binary failed: status %d", resp.StatusCode)
	}
	archiveBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBinaryArchiveSize+1))
	if err != nil {
		return err
	}
	if len(archiveBytes) > maxBinaryArchiveSize {
		return fmt.Errorf("binary package exceeds %d bytes", maxBinaryArchiveSize)
	}

	expectedSHA, err := fetchExpectedSHA256(url)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(archiveBytes)
	actualSHA := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(actualSHA)), []byte(strings.ToLower(expectedSHA))) != 1 {
		return fmt.Errorf("binary package sha256 mismatch")
	}

	gzr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var payload []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Only a regular file is a candidate. Matching on the base name alone
		// would otherwise happily accept a directory or symlink entry.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(filepath.Clean(hdr.Name)) == "xpn-node" {
			payload, err = io.ReadAll(io.LimitReader(tr, maxBinaryPayloadSize+1))
			if err != nil {
				return err
			}
			if len(payload) > maxBinaryPayloadSize {
				return fmt.Errorf("extracted binary exceeds %d bytes", maxBinaryPayloadSize)
			}
			break
		}
	}
	if len(payload) == 0 {
		return fmt.Errorf("binary xpn-node not found in package")
	}
	if len(payload) < minBinaryPayloadSize {
		return fmt.Errorf("extracted binary is only %d bytes, refusing to install it", len(payload))
	}
	if !looksLikeLinuxExecutable(payload) {
		return fmt.Errorf("extracted binary is not an ELF executable, refusing to install it")
	}
	if err := checkExecutableMatchesHost(payload); err != nil {
		return err
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	dir := filepath.Dir(exePath)
	newPath := filepath.Join(dir, "xpn-node.new")
	backupPath := filepath.Join(dir, "xpn-node.bak")

	if err := os.WriteFile(newPath, payload, 0o755); err != nil {
		return err
	}
	// Any failure from here on must not leave the staged file behind.
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(newPath)
		}
	}()

	_ = os.Remove(backupPath)
	if err := os.Rename(exePath, backupPath); err != nil {
		return err
	}
	if err := os.Rename(newPath, exePath); err != nil {
		// Put the working binary back before giving up, otherwise the service
		// has no executable at all.
		if rbErr := os.Rename(backupPath, exePath); rbErr != nil {
			log.Errorf("CRITICAL: failed to restore previous binary from %s: %v", backupPath, rbErr)
		}
		return err
	}
	installed = true

	log.Infof("binary updated successfully (%d bytes), exiting for service restart", len(payload))
	// os.Exit skips deferred cleanup, so close the database explicitly to let
	// SQLite checkpoint its WAL before the process disappears.
	if db != nil {
		_ = db.Close()
	}
	os.Exit(0)
	return nil
}

func fetchExpectedSHA256(binaryURL string) (string, error) {
	shaURL := binaryURL + ".sha256"
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(shaURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download sha256 failed: status %d", resp.StatusCode)
	}
	// A checksum file is a few dozen bytes; cap the read so a wrong URL serving
	// something huge cannot be slurped into memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return "", fmt.Errorf("invalid sha256 file content")
	}
	expected := strings.TrimSpace(fields[0])
	if len(expected) != 64 {
		return "", fmt.Errorf("invalid sha256 length")
	}
	for _, c := range expected {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", fmt.Errorf("invalid sha256 format")
		}
	}
	return strings.ToLower(expected), nil
}

func getAllRules() ([]Rule, error) {
	rows, err := db.Query(`
		SELECT id, name, type, COALESCE(sni, ''), COALESCE(listen_port, 0), dest, lb_strategy, enabled
		FROM rules ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var rule Rule
		var destJSON string
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Type, &rule.SNI, &rule.ListenPort, &destJSON, &rule.LBStrategy, &enabled); err != nil {
			continue
		}
		json.Unmarshal([]byte(destJSON), &rule.Dest)
		rule.Enabled = enabled == 1
		rules = append(rules, rule)
	}

	return rules, nil
}
