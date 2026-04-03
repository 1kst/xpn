package xpfw

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
)

var (
	log = logrus.New()
	db  *sql.DB
)

const (
	handshakeTimeout = 8 * time.Second
	idleTimeout      = 3 * time.Minute
	transferTimeout  = 2 * time.Hour
	dnsCacheTTL      = 60 * time.Second
	dnsNegativeTTL   = 5 * time.Second
	dnsLookupTimeout = 2 * time.Second
	DefaultBinaryURL = "https://github.com/1kst/xpn/releases/latest/download/xpn-node-linux-amd64.tar.gz"
)

var (
	PanelVersion = "v1.0"
	NodeVersion  = "v1.1.10"
)

func binaryURLForVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return DefaultBinaryURL
	}
	return fmt.Sprintf("https://github.com/1kst/xpn/releases/download/%s/xpn-node-linux-amd64.tar.gz", v)
}

const (
	RuleTypeSNI  = "sni"
	RuleTypePort = "port"
)

const (
	LBRoundRobin  = "round_robin"
	LBRandom      = "random"
	LBFirstOnly   = "first_only"
	LBHealthCheck = "health_check"
)

type Rule struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	SNI        string   `json:"sni"`
	ListenPort int      `json:"listen_port"`
	Dest       []string `json:"dest"`
	LBStrategy string   `json:"lb_strategy"`
	Enabled    bool     `json:"enabled"`
	Version    int      `json:"version"`
	Counter    uint64   `json:"-"`
}

type Config struct {
	SNIListen      string `json:"sni_listen"`
	DefaultBackend string `json:"default_backend"`
	WebPanel       string `json:"web_panel"`
	WebAuth        string `json:"web_auth"`
	LogLevel       string `json:"log_level"`
	WebTitle       string `json:"web_title"`
}

type sniRouteEntry struct {
	dests    []string
	strategy string
	counter  uint64
}

type portForwarder struct {
	cancel context.CancelFunc
	ln     net.Listener
}

type dnsCacheEntry struct {
	ips       []string
	expiresAt time.Time
	nextIdx   int
	negative  bool
}

var (
	globalConfig    Config
	configMu        sync.RWMutex
	portListeners   = make(map[int]*portForwarder)
	portListenersMu sync.Mutex
	sniRouteCache   = make(map[string]*sniRouteEntry)
	sniRouteMu      sync.RWMutex
	sniRouteLogN    uint64
	dnsCache        = make(map[string]*dnsCacheEntry)
	dnsCacheMu      sync.Mutex

	sniListenerCancel context.CancelFunc
	sniListenerLn     net.Listener
	sniListenerMu     sync.Mutex
	mainCtx           context.Context
)

func Run(forcedMode string) {
	var err error
	db, err = initDB("sni-proxy.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "init database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	if err := loadPanelConfigFromDB(); err != nil {
		fmt.Fprintf(os.Stderr, "load panel config: %v\n", err)
		os.Exit(1)
	}
	if err := rebuildSniRouteCacheFromDB(); err != nil {
		fmt.Fprintf(os.Stderr, "build sni route cache: %v\n", err)
		os.Exit(1)
	}

	var modeArg string
	var panelURLArg string
	var tokenArg string
	var nodeIDArg string
	var urlAliasArg string
	var keyAliasArg string

	flag.StringVar(&modeArg, "mode", "", "Run mode: 'panel' or 'node'")
	flag.StringVar(&panelURLArg, "panel", "", "Panel URL (required for node mode)")
	flag.StringVar(&urlAliasArg, "url", "", "Panel URL (alias of -panel)")
	flag.StringVar(&tokenArg, "token", "", "Panel communication token (required for node mode)")
	flag.StringVar(&keyAliasArg, "key", "", "Panel communication token (alias of -token)")
	flag.StringVar(&nodeIDArg, "id", "", "Node ID (optional)")
	flag.Parse()

	if strings.TrimSpace(urlAliasArg) != "" {
		panelURLArg = strings.TrimSpace(urlAliasArg)
	}
	if strings.TrimSpace(keyAliasArg) != "" {
		tokenArg = strings.TrimSpace(keyAliasArg)
	}

	if forcedMode != "" {
		forcedMode = strings.TrimSpace(forcedMode)
		if modeArg != "" && strings.TrimSpace(modeArg) != forcedMode {
			log.Warnf("ignoring -mode=%s because this binary is fixed to mode=%s", strings.TrimSpace(modeArg), forcedMode)
		}
		modeArg = forcedMode
	}

	if modeArg != "" || panelURLArg != "" || tokenArg != "" || nodeIDArg != "" {
		panelConfigMu.Lock()
		if modeArg != "" {
			panelConfig.Mode = modeArg
		}
		if panelURLArg != "" {
			panelConfig.PanelURL = panelURLArg
		}
		if tokenArg != "" {
			panelConfig.PanelToken = tokenArg
		}
		if nodeIDArg != "" {
			panelConfig.NodeID = nodeIDArg
		}

		if panelConfig.Mode == ModeNode && panelConfig.PanelURL == "" {
			fmt.Fprintln(os.Stderr, "Error: node mode requires panel address, use -panel")
			os.Exit(1)
		}
		if panelConfig.Mode == ModeNode && strings.TrimSpace(panelConfig.PanelToken) == "" {
			fmt.Fprintln(os.Stderr, "Error: node mode requires panel token, use -token")
			os.Exit(1)
		}

		panelConfigMu.Unlock()

		if err := savePanelConfigToDB(); err != nil {
			fmt.Fprintf(os.Stderr, "save config from flags: %v\n", err)
			os.Exit(1)
		}
	}

	setLogLevel(globalConfig.LogLevel)

	panelConfigMu.RLock()
	mode := panelConfig.Mode
	panelConfigMu.RUnlock()

	log.WithFields(logrus.Fields{
		"sni_listen":      globalConfig.SNIListen,
		"default_backend": globalConfig.DefaultBackend,
		"web_panel":       globalConfig.WebPanel,
		"mode":            mode,
		"panel_version":   PanelVersion,
		"node_version":    NodeVersion,
	}).Info("starting sni-proxy")

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mainCtx = ctx

	panelConfigMu.RLock()
	currentMode := panelConfig.Mode
	panelURL := panelConfig.PanelURL
	token := panelConfig.PanelToken
	nodeID := panelConfig.NodeID
	pullInterval := panelConfig.PullInterval
	panelConfigMu.RUnlock()

	if currentMode == ModePanel {
		if err := ensurePanelCommKey(); err != nil {
			log.Fatalf("initialize panel communication key failed: %v", err)
		}
		panelConfigMu.RLock()
		token = panelConfig.PanelToken
		panelConfigMu.RUnlock()

		log.Info("running in PANEL mode (Control Panel Only)")
		if globalConfig.WebPanel != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				startWebPanel(globalConfig.WebPanel, globalConfig.WebAuth)
			}()
		}
		go startPanel(token)
	} else if currentMode == ModeNode {
		log.Info("running in NODE mode (Proxy Worker)")
		if nodeID == "" {
			nodeID = fmt.Sprintf("%d", time.Now().UnixNano())
			panelConfigMu.Lock()
			panelConfig.NodeID = nodeID
			panelConfigMu.Unlock()
			db.Exec("UPDATE panel_config SET value = ? WHERE key = 'node_id'", nodeID)
			log.Infof("generated new node id: %s", nodeID)
		}

		log.WithFields(logrus.Fields{
			"panel":   panelURL,
			"node_id": nodeID,
		}).Info("node mode started")

		if globalConfig.SNIListen != "" {
			go restartSNIListener(globalConfig.SNIListen)
		}

		if err := startAllPortForwarders(ctx); err != nil {
			log.Errorf("start port forwarders: %v", err)
		}

		go startNode(panelURL, token, nodeID, pullInterval)

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Info("shutting down gracefully...")
		cancel()
		stopAllPortForwarders()
	}()

	wg.Wait()
	log.Info("shutdown complete")
}

func ensurePanelCommKey() error {
	panelConfigMu.RLock()
	existing := strings.TrimSpace(panelConfig.PanelToken)
	panelConfigMu.RUnlock()

	if existing != "" && existing != "your-secret-token" {
		return nil
	}

	key, err := generateCommKey()
	if err != nil {
		return err
	}

	panelConfigMu.Lock()
	panelConfig.PanelToken = key
	panelConfigMu.Unlock()

	if err := savePanelConfigToDB(); err != nil {
		return err
	}

	log.Warnf("panel communication token was initialized automatically, update node side with -token %s", key)
	return nil
}

func generateCommKey() (string, error) {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func loadPanelConfigFromDB() error {
	rows, err := db.Query("SELECT key, value FROM panel_config")
	if err != nil {
		return err
	}
	defer rows.Close()

	configMap := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return err
		}
		configMap[key] = value
	}

	panelConfigMu.Lock()
	panelConfig.Mode = configMap["mode"]
	panelConfig.PanelURL = configMap["panel_url"]
	panelConfig.PanelToken = configMap["panel_token"]
	panelConfig.NodeID = configMap["node_id"]

	pullInterval := 10
	if v, ok := configMap["pull_interval"]; ok && v != "" {
		fmt.Sscanf(v, "%d", &pullInterval)
	}
	panelConfig.PullInterval = pullInterval

	configVersionMu.Lock()
	if v, ok := configMap["config_version"]; ok && v != "" {
		fmt.Sscanf(v, "%d", &configVersionCounter)
	}
	configVersionMu.Unlock()
	panelConfigMu.Unlock()

	return nil
}

func savePanelConfigToDB() error {
	panelConfigMu.RLock()
	mode := panelConfig.Mode
	url := panelConfig.PanelURL
	token := panelConfig.PanelToken
	id := panelConfig.NodeID
	interval := panelConfig.PullInterval
	panelConfigMu.RUnlock()

	configVersionMu.Lock()
	version := configVersionCounter
	configVersionMu.Unlock()

	updates := map[string]string{
		"mode":           mode,
		"panel_url":      url,
		"panel_token":    token,
		"node_id":        id,
		"pull_interval":  fmt.Sprintf("%d", interval),
		"config_version": fmt.Sprintf("%d", version),
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range updates {
		if _, err := tx.Exec("UPDATE panel_config SET value = ? WHERE key = ?", v, k); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func initDB(dbPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_busy_timeout=5000", dbPath)
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	database.SetMaxOpenConns(1)

	schema := `
	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT
	);

	CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		sni TEXT,
		listen_port INTEGER,
		dest TEXT NOT NULL,
		lb_strategy TEXT DEFAULT 'round_robin',
		enabled INTEGER DEFAULT 1,
		version INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS panel_config (
		key TEXT PRIMARY KEY,
		value TEXT
	);

	CREATE TABLE IF NOT EXISTS nodes (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		addr TEXT,
		ipv4 TEXT,
		ipv6 TEXT,
		status TEXT DEFAULT 'offline',
		last_seen DATETIME,
		config_version INTEGER DEFAULT 0,
		status_data TEXT,
		node_version TEXT DEFAULT '',
		last_update_status TEXT DEFAULT 'idle',
		last_update_message TEXT DEFAULT '',
		last_update_at DATETIME,
		custom_sni_listen TEXT DEFAULT '',
		force_update INTEGER DEFAULT 0,
		force_binary_update INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(type);
	CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
	`

	if _, err := database.Exec(schema); err != nil {
		return nil, err
	}

	database.Exec("ALTER TABLE rules ADD COLUMN version INTEGER DEFAULT 0")
	database.Exec("ALTER TABLE nodes ADD COLUMN status_data TEXT")
	database.Exec("ALTER TABLE nodes ADD COLUMN ipv4 TEXT")
	database.Exec("ALTER TABLE nodes ADD COLUMN ipv6 TEXT")
	database.Exec("ALTER TABLE nodes ADD COLUMN custom_sni_listen TEXT DEFAULT ''")
	database.Exec("ALTER TABLE nodes ADD COLUMN force_update INTEGER DEFAULT 0")
	database.Exec("ALTER TABLE nodes ADD COLUMN node_version TEXT DEFAULT ''")
	database.Exec("ALTER TABLE nodes ADD COLUMN force_binary_update INTEGER DEFAULT 0")
	database.Exec("ALTER TABLE nodes ADD COLUMN last_update_status TEXT DEFAULT 'idle'")
	database.Exec("ALTER TABLE nodes ADD COLUMN last_update_message TEXT DEFAULT ''")
	database.Exec("ALTER TABLE nodes ADD COLUMN last_update_at DATETIME")

	defaultConfig := map[string]string{
		"sni_listen":      ":443",
		"default_backend": "127.0.0.1:8080",
		"web_panel":       ":8888",
		"web_auth":        "",
		"log_level":       "info",
		"web_title":       "SNI Proxy Pro",
	}

	for k, v := range defaultConfig {
		database.Exec("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)", k, v)
	}

	defaultPanelConfig := map[string]string{
		"mode":           "panel",
		"panel_url":      "",
		"panel_token":    "your-secret-token",
		"node_id":        "",
		"pull_interval":  "10",
		"config_version": "0",
	}

	for k, v := range defaultPanelConfig {
		database.Exec("INSERT OR IGNORE INTO panel_config (key, value) VALUES (?, ?)", k, v)
	}

	return database, nil
}

func loadConfig() error {
	rows, err := db.Query("SELECT key, value FROM config")
	if err != nil {
		return err
	}
	defer rows.Close()

	configMap := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return err
		}
		configMap[key] = value
	}

	configMu.Lock()
	globalConfig = Config{
		SNIListen:      configMap["sni_listen"],
		DefaultBackend: configMap["default_backend"],
		WebPanel:       configMap["web_panel"],
		WebAuth:        configMap["web_auth"],
		LogLevel:       configMap["log_level"],
		WebTitle:       configMap["web_title"],
	}
	configMu.Unlock()

	return nil
}

func saveConfig(cfg Config) error {
	configMu.Lock()
	defer configMu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	updates := map[string]string{
		"sni_listen":      cfg.SNIListen,
		"default_backend": cfg.DefaultBackend,
		"web_panel":       cfg.WebPanel,
		"web_auth":        cfg.WebAuth,
		"log_level":       cfg.LogLevel,
		"web_title":       cfg.WebTitle,
	}

	for k, v := range updates {
		if _, err := tx.Exec("UPDATE config SET value = ? WHERE key = ?", v, k); err != nil {
			return err
		}
	}

	globalConfig = cfg
	return tx.Commit()
}

func setLogLevel(lvl string) {
	switch strings.ToLower(strings.TrimSpace(lvl)) {
	case "trace":
		log.SetLevel(logrus.TraceLevel)
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info", "":
		log.SetLevel(logrus.InfoLevel)
	case "warn", "warning":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	}
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
}

func restartSNIListener(addr string) {
	if addr != "" && !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	sniListenerMu.Lock()
	if sniListenerLn != nil {
		sniListenerLn.Close()
		sniListenerLn = nil
	}
	if sniListenerCancel != nil {
		sniListenerCancel()
	}
	sniCtx, cancel := context.WithCancel(mainCtx)
	sniListenerCancel = cancel
	sniListenerMu.Unlock()

	time.Sleep(200 * time.Millisecond)
	startSNIListener(sniCtx, addr)
}

func startSNIListener(ctx context.Context, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("SNI listen %s: %v", addr, err)
		return
	}

	select {
	case <-ctx.Done():
		ln.Close()
		return
	default:
	}

	sniListenerMu.Lock()
	sniListenerLn = ln
	sniListenerMu.Unlock()
	defer func() {
		sniListenerMu.Lock()
		if sniListenerLn == ln {
			sniListenerLn = nil
		}
		sniListenerMu.Unlock()
		ln.Close()
	}()

	log.Infof("SNI listener started on %s", addr)

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			log.Info("SNI listener shutting down...")
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				break
			}
			log.Errorf("SNI accept: %v", err)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleSNIConn(c, ctx)
		}(conn)
	}
}

func handleSNIConn(client net.Conn, ctx context.Context) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()

	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(client, 64*1024)

	sni, peeked, err := peekClientHelloSNI(br)
	if err != nil {
		log.WithFields(logrus.Fields{"client": clientAddr, "err": err}).Warn("SNI peek failed")
	}

	backend := routeSNIBackend(sni)
	fields := logrus.Fields{
		"client":  clientAddr,
		"sni":     sni,
		"backend": backend,
	}
	if log.IsLevelEnabled(logrus.DebugLevel) {
		log.WithFields(fields).Debug("SNI route")
	} else if atomic.AddUint64(&sniRouteLogN, 1)%200 == 0 {
		log.WithFields(fields).Info("SNI route sample")
	}

	backendConn, err := dialBackendWithDNSCache("tcp", backend, 6*time.Second)
	if err != nil {
		log.WithFields(logrus.Fields{"client": clientAddr, "backend": backend, "err": err}).Error("dial backend failed")
		return
	}
	defer backendConn.Close()

	deadline := time.Now().Add(transferTimeout)
	_ = client.SetDeadline(deadline)
	_ = backendConn.SetDeadline(deadline)

	if len(peeked) > 0 {
		backendConn.Write(peeked)
	}
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		io.ReadFull(br, buf)
		backendConn.Write(buf)
	}

	done := make(chan struct{}, 2)
	go proxyWithIdleTimeout(backendConn, client, done, idleTimeout, clientAddr, "c->b")
	go proxyWithIdleTimeout(client, backendConn, done, idleTimeout, clientAddr, "b->c")

	select {
	case <-done:
		<-done
	case <-ctx.Done():
		client.Close()
		backendConn.Close()
		<-done
		<-done
	}
}

func routeSNIBackend(sni string) string {
	sniRouteMu.RLock()
	entry := sniRouteCache[normalizeSNI(sni)]
	sniRouteMu.RUnlock()
	if entry != nil && len(entry.dests) > 0 {
		return selectBackend(entry.dests, entry.strategy, &entry.counter)
	}
	return getDefaultBackend()
}

func normalizeSNI(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

func normalizeHost(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

func rebuildSniRouteCacheFromDB() error {
	rows, err := db.Query(`
		SELECT COALESCE(sni, ''), dest, lb_strategy
		FROM rules
		WHERE type = ? AND enabled = 1
	`, RuleTypeSNI)
	if err != nil {
		return err
	}
	defer rows.Close()

	next := make(map[string]*sniRouteEntry)
	for rows.Next() {
		var sni, destJSON, lbStrategy string
		if err := rows.Scan(&sni, &destJSON, &lbStrategy); err != nil {
			return err
		}
		var dests []string
		if err := json.Unmarshal([]byte(destJSON), &dests); err != nil {
			continue
		}
		normSNI := normalizeSNI(sni)
		if normSNI == "" || len(dests) == 0 {
			continue
		}
		next[normSNI] = &sniRouteEntry{
			dests:    dests,
			strategy: lbStrategy,
		}
	}

	sniRouteMu.Lock()
	sniRouteCache = next
	sniRouteMu.Unlock()
	return nil
}

func resolveHostCached(host string) ([]string, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}

	now := time.Now()
	dnsCacheMu.Lock()
	if entry, ok := dnsCache[host]; ok && now.Before(entry.expiresAt) {
		if entry.negative || len(entry.ips) == 0 {
			dnsCacheMu.Unlock()
			return nil, fmt.Errorf("cached dns miss for %s", host)
		}
		ordered := rotateIPs(entry.ips, entry.nextIdx)
		entry.nextIdx = (entry.nextIdx + 1) % len(entry.ips)
		dnsCacheMu.Unlock()
		return ordered, nil
	}
	dnsCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		dnsCacheMu.Lock()
		dnsCache[host] = &dnsCacheEntry{negative: true, expiresAt: time.Now().Add(dnsNegativeTTL)}
		dnsCacheMu.Unlock()
		return nil, err
	}
	if len(ipAddrs) == 0 {
		dnsCacheMu.Lock()
		dnsCache[host] = &dnsCacheEntry{negative: true, expiresAt: time.Now().Add(dnsNegativeTTL)}
		dnsCacheMu.Unlock()
		return nil, fmt.Errorf("no dns answer for %s", host)
	}

	seen := make(map[string]struct{}, len(ipAddrs))
	ips := make([]string, 0, len(ipAddrs))
	for _, item := range ipAddrs {
		ip := item.IP.String()
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		dnsCacheMu.Lock()
		dnsCache[host] = &dnsCacheEntry{negative: true, expiresAt: time.Now().Add(dnsNegativeTTL)}
		dnsCacheMu.Unlock()
		return nil, fmt.Errorf("no usable dns answer for %s", host)
	}

	dnsCacheMu.Lock()
	dnsCache[host] = &dnsCacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(dnsCacheTTL),
	}
	dnsCacheMu.Unlock()
	return ips, nil
}

func rotateIPs(ips []string, start int) []string {
	if len(ips) <= 1 {
		return append([]string(nil), ips...)
	}
	start = start % len(ips)
	if start < 0 {
		start = 0
	}
	out := make([]string, 0, len(ips))
	out = append(out, ips[start:]...)
	out = append(out, ips[:start]...)
	return out
}

func dialBackendWithDNSCache(network, target string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return net.DialTimeout(network, target, timeout)
	}
	ips, err := resolveHostCached(host)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	var lastErr error
	for i, ip := range ips {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		tryTimeout := remaining
		left := len(ips) - i
		if left > 1 && remaining > time.Second {
			tryTimeout = remaining / time.Duration(left)
		}
		conn, dialErr := net.DialTimeout(network, net.JoinHostPort(ip, port), tryTimeout)
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dial backend failed: %s", target)
	}
	return nil, lastErr
}

func getDefaultBackend() string {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig.DefaultBackend
}

func startAllPortForwarders(ctx context.Context) error {
	rows, err := db.Query("SELECT id, name, listen_port, dest, lb_strategy FROM rules WHERE type = ? AND enabled = 1", RuleTypePort)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, port int
		var name, destJSON, lbStrategy string
		if err := rows.Scan(&id, &name, &port, &destJSON, &lbStrategy); err != nil {
			continue
		}

		var dests []string
		json.Unmarshal([]byte(destJSON), &dests)

		if err := startPortForwarder(ctx, id, name, port, dests, lbStrategy); err != nil {
			log.Errorf("start port forwarder %s:%d failed: %v", name, port, err)
		}
	}

	return nil
}

func startPortForwarder(ctx context.Context, ruleID int, name string, port int, dests []string, lbStrategy string) error {
	portListenersMu.Lock()
	defer portListenersMu.Unlock()

	if pf, exists := portListeners[port]; exists {
		pf.cancel()
		if pf.ln != nil {
			_ = pf.ln.Close()
		}
		delete(portListeners, port)
		time.Sleep(100 * time.Millisecond)
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	portCtx, cancel := context.WithCancel(ctx)
	portListeners[port] = &portForwarder{
		cancel: cancel,
		ln:     ln,
	}

	log.WithFields(logrus.Fields{
		"name": name,
		"port": port,
		"dest": dests,
		"lb":   lbStrategy,
	}).Info("port forwarder started")

	go func() {
		defer ln.Close()
		var counter uint64
		var wg sync.WaitGroup

		for {
			select {
			case <-portCtx.Done():
				wg.Wait()
				return
			default:
			}

			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed") {
					return
				}
				continue
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handlePortForward(c, dests, lbStrategy, &counter, portCtx)
			}(conn)
		}
	}()

	return nil
}

func stopAllPortForwarders() {
	portListenersMu.Lock()
	defer portListenersMu.Unlock()

	for port, pf := range portListeners {
		log.Infof("stopping port forwarder on :%d", port)
		pf.cancel()
		if pf.ln != nil {
			_ = pf.ln.Close()
		}
	}
	portListeners = make(map[int]*portForwarder)
}

func handlePortForward(client net.Conn, dests []string, lbStrategy string, counter *uint64, ctx context.Context) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()

	backend := selectBackend(dests, lbStrategy, counter)

	backendConn, err := dialBackendWithDNSCache("tcp", backend, 6*time.Second)
	if err != nil {
		log.WithFields(logrus.Fields{"client": clientAddr, "backend": backend, "err": err}).Error("dial backend failed")
		return
	}
	defer backendConn.Close()

	deadline := time.Now().Add(transferTimeout)
	_ = client.SetDeadline(deadline)
	_ = backendConn.SetDeadline(deadline)

	log.WithFields(logrus.Fields{
		"client":  clientAddr,
		"backend": backend,
	}).Debug("port forward")

	done := make(chan struct{}, 2)
	go proxyWithIdleTimeout(backendConn, client, done, idleTimeout, clientAddr, "c->b")
	go proxyWithIdleTimeout(client, backendConn, done, idleTimeout, clientAddr, "b->c")

	select {
	case <-done:
		<-done
	case <-ctx.Done():
		client.Close()
		backendConn.Close()
		<-done
		<-done
	}
}

func selectBackend(dests []string, strategy string, counter *uint64) string {
	if len(dests) == 0 {
		return ""
	}

	switch strategy {
	case LBRoundRobin:
		if counter != nil {
			idx := atomic.AddUint64(counter, 1) % uint64(len(dests))
			return dests[idx]
		}
		return dests[rand.Intn(len(dests))]

	case LBRandom:
		return dests[rand.Intn(len(dests))]

	case LBFirstOnly:
		return dests[0]

	case LBHealthCheck:
		probeCacheMu.Lock()
		best := ""
		bestMS := -1
		for _, dest := range dests {
			state, ok := probeCache[dest]
			if ok && state.lastMS >= 0 {
				if best == "" || state.lastMS < bestMS {
					best = dest
					bestMS = state.lastMS
				}
			}
		}
		probeCacheMu.Unlock()
		if best != "" {
			return best
		}
		return dests[0]

	default:
		return dests[0]
	}
}

func proxyWithIdleTimeout(dst, src net.Conn, done chan<- struct{}, timeout time.Duration, clientAddr, direction string) {
	defer func() {
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	buf := make([]byte, 64*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, err := src.Read(buf)

		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(timeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}

		if err != nil {
			return
		}
	}
}

func peekClientHelloSNI(br *bufio.Reader) (string, []byte, error) {
	const maxRecord = 64 * 1024

	readBuffered := func(n int) []byte {
		if n <= 0 {
			n = br.Buffered()
		}
		buf := make([]byte, n)
		io.ReadFull(br, buf)
		return buf
	}

	hdr, err := br.Peek(5)
	if err != nil || len(hdr) < 5 {
		return "", nil, fmt.Errorf("peek header: %v", err)
	}

	if hdr[0] != 0x16 {
		peeked := readBuffered(0)
		return "", peeked, errors.New("not a TLS handshake record")
	}

	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > maxRecord-5 {
		peeked := readBuffered(0)
		return "", peeked, fmt.Errorf("invalid TLS record length: %d", recLen)
	}

	total := 5 + recLen
	rec, err := br.Peek(total)
	if err != nil || len(rec) < total {
		peeked := readBuffered(0)
		return "", peeked, fmt.Errorf("incomplete TLS record: %v", err)
	}

	payload := rec[5:total]
	if len(payload) < 4 || payload[0] != 0x01 {
		peeked := readBuffered(total)
		return "", peeked, errors.New("not ClientHello")
	}

	hlen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if hlen+4 > len(payload) {
		peeked := readBuffered(total)
		return "", peeked, errors.New("truncated ClientHello")
	}

	ch := payload[4 : 4+hlen]
	if len(ch) < 34 {
		peeked := readBuffered(total)
		return "", peeked, errors.New("short ClientHello")
	}

	off := 34
	if off+1 > len(ch) {
		peeked := readBuffered(total)
		return "", peeked, errors.New("no session_id")
	}

	sidLen := int(ch[off])
	off += 1 + sidLen

	if off+2 > len(ch) {
		peeked := readBuffered(total)
		return "", peeked, errors.New("no cipher_suites")
	}

	csLen := int(ch[off])<<8 | int(ch[off+1])
	off += 2 + csLen

	if off+1 > len(ch) {
		peeked := readBuffered(total)
		return "", peeked, errors.New("no compression")
	}

	cmLen := int(ch[off])
	off += 1 + cmLen

	if off+2 > len(ch) {
		peeked := readBuffered(total)
		return "", peeked, errors.New("no extensions")
	}

	extLen := int(ch[off])<<8 | int(ch[off+1])
	off += 2

	if off+extLen > len(ch) {
		peeked := readBuffered(total)
		return "", peeked, errors.New("extensions truncated")
	}

	exts := ch[off : off+extLen]
	for i := 0; i+4 <= len(exts); {
		eType := int(exts[i])<<8 | int(exts[i+1])
		eLen := int(exts[i+2])<<8 | int(exts[i+3])
		i += 4

		if i+eLen > len(exts) {
			break
		}

		if eType == 0 {
			block := exts[i : i+eLen]
			if len(block) < 2 {
				break
			}

			listLen := int(block[0])<<8 | int(block[1])
			p := 2

			for p+3 <= len(block) && p < 2+listLen {
				nameType := block[p]
				hnLen := int(block[p+1])<<8 | int(block[p+2])
				p += 3

				if p+hnLen > len(block) {
					break
				}

				if nameType == 0 {
					serverName := string(block[p : p+hnLen])
					peeked := readBuffered(total)
					return strings.ToLower(serverName), peeked, nil
				}
				p += hnLen
			}
		}
		i += eLen
	}

	peeked := readBuffered(total)
	return "", peeked, errors.New("no SNI found")
}
