package xpfw

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	NodeID        string         `json:"node_id"`
	IPv4          string         `json:"ipv4"`
	IPv6          string         `json:"ipv6"`
	ConfigVersion int            `json:"config_version"`
	NodeVersion   string         `json:"node_version"`
	StatusData    map[string]int `json:"status_data"`
	System        *SystemMetrics `json:"system,omitempty"`
	UpdateStatus  string         `json:"update_status,omitempty"`
	UpdateMessage string         `json:"update_message,omitempty"`
	UpdateAt      string         `json:"update_at,omitempty"`
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

func getNodeUpdateState() (string, string, string) {
	nodeUpdateMu.Lock()
	defer nodeUpdateMu.Unlock()
	if nodeUpdate.Status == "" || nodeUpdate.Status == "idle" {
		return "", "", ""
	}
	status := nodeUpdate.Status
	message := nodeUpdate.Message
	at := nodeUpdate.At.Format(time.RFC3339)
	if status == "ok" || status == "failed" {
		nodeUpdate.Status = "idle"
		nodeUpdate.Message = ""
	}
	return status, message, at
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

	log.Infof("node mode initialized, panel: %s, node_id: %s", panelURL, nodeID)

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

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, dest := range rule.Dest {
			go probeTarget(dest)
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
		IPv4:          getPublicIP(4),
		IPv6:          getPublicIP(6),
		ConfigVersion: currentVersion,
		NodeVersion:   NodeVersion,
		StatusData:    statusData,
		System:        collectSystemMetrics(),
	}
	if status, message, at := getNodeUpdateState(); status != "" {
		req.UpdateStatus = status
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

	if heartbeatResp.NeedUpdate {
		log.Infof("[Heartbeat] remote version %d is newer than local %d, pulling update...", heartbeatResp.ConfigVersion, currentVersion)
		pullConfigFromPanel()
	}
	if heartbeatResp.NeedBinaryUpdate {
		log.Infof("[Heartbeat] binary update requested: local=%s latest=%s", NodeVersion, heartbeatResp.LatestVersion)
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
	configMu.Lock()
	oldSNIListen := globalConfig.SNIListen
	globalConfig.SNIListen = configResp.Config.SNIListen
	globalConfig.DefaultBackend = configResp.Config.DefaultBackend
	globalConfig.LogLevel = configResp.Config.LogLevel
	configMu.Unlock()

	applyRules(configResp.Rules)

	configVersionMu.Lock()
	configVersionCounter = configResp.ConfigVersion
	configVersionMu.Unlock()

	log.Infof("config applied successfully (version: %d, rules: %d, sni_listen: %s)", configResp.ConfigVersion, len(configResp.Rules), configResp.Config.SNIListen)

	if configResp.Config.SNIListen != "" && configResp.Config.SNIListen != oldSNIListen {
		log.Infof("[Sync] SNI listen address changed: %q -> %q, restarting listener...", oldSNIListen, configResp.Config.SNIListen)
		go restartSNIListener(configResp.Config.SNIListen)
	}

	go runProbing()
}

func applyRules(rules []Rule) {
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

	db.Exec("DELETE FROM rules")

	for _, rule := range rules {
		rule.SNI = normalizeSNI(rule.SNI)
		destJSON, _ := json.Marshal(rule.Dest)
		enabled := 0
		if rule.Enabled {
			enabled = 1
		}

		result, err := db.Exec(`
			INSERT INTO rules (name, type, sni, listen_port, dest, lb_strategy, enabled)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, rule.Name, rule.Type, rule.SNI, rule.ListenPort, string(destJSON), rule.LBStrategy, enabled)

		if err != nil {
			log.Errorf("insert rule failed: %v", err)
			continue
		}

		if rule.Type == RuleTypePort && rule.Enabled {
			id, _ := result.LastInsertId()
			ctx := context.Background()
			go startPortForwarder(ctx, int(id), rule.Name, rule.ListenPort, rule.Dest, rule.LBStrategy)
		}
	}
	if err := rebuildSniRouteCacheFromDB(); err != nil {
		log.Errorf("rebuild sni route cache failed: %v", err)
	}
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

func updateBinaryAndExit(url string) error {
	if strings.TrimSpace(url) == "" {
		url = binaryURLForVersion(NodeVersion)
	}

	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download binary failed: status %d", resp.StatusCode)
	}
	archiveBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
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
		if filepath.Base(hdr.Name) == "sni-proxy" {
			payload, err = io.ReadAll(tr)
			if err != nil {
				return err
			}
			break
		}
	}
	if len(payload) == 0 {
		return fmt.Errorf("binary sni-proxy not found in package")
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exePath)
	newPath := filepath.Join(dir, "sni-proxy.new")
	backupPath := filepath.Join(dir, "sni-proxy.bak")

	if err := os.WriteFile(newPath, payload, 0755); err != nil {
		return err
	}
	_ = os.Remove(backupPath)
	if err := os.Rename(exePath, backupPath); err != nil {
		return err
	}
	if err := os.Rename(newPath, exePath); err != nil {
		_ = os.Rename(backupPath, exePath)
		return err
	}

	log.Infof("binary updated successfully, exiting for service restart")
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
	body, err := io.ReadAll(resp.Body)
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
