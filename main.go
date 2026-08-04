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
	NodeVersion  = "v1.1.13"
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
	// ruleID attributes the traffic this route carries. Port rules already know
	// their id from startPortForwarder; SNI rules had no way to report it.
	ruleID   int
	dests    []string
	strategy string
	counter  uint64
}

// ruleCounters is one rule's accounting. Updated from the relay loops, so every
// field is atomic and nothing here may take a lock.
type ruleCounters struct {
	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64
	conns     atomic.Uint64
	dialFail  atomic.Uint64
}

var (
	trafficMu     sync.RWMutex
	trafficByRule = make(map[int]*ruleCounters)
	sniMissCount  atomic.Uint64
	// bootID lets the panel tell a counter reset apart from a decrease it should
	// never otherwise see.
	bootID string
	// reachableDest records, per destination, whether this node has ever managed
	// to connect. A rule pointing at 127.0.0.1 or another node-local address is
	// unreachable here by design, and counting those attempts as failures would
	// make the dial failure rate useless.
	reachableMu  sync.RWMutex
	reachedDest  = make(map[string]bool)
	attemptedDst = make(map[string]bool)
)

// counterFor returns the accounting slot for a rule, creating it on first use.
func counterFor(ruleID int) *ruleCounters {
	if ruleID <= 0 {
		return nil
	}
	trafficMu.RLock()
	c := trafficByRule[ruleID]
	trafficMu.RUnlock()
	if c != nil {
		return c
	}
	trafficMu.Lock()
	defer trafficMu.Unlock()
	if c = trafficByRule[ruleID]; c == nil {
		c = &ruleCounters{}
		trafficByRule[ruleID] = c
	}
	return c
}

// isLoopback reports whether a destination is a loopback address, which is
// never probed and never counted: whether it answers depends entirely on which
// host the rule happens to be applied to.
func isLoopback(dest string) bool {
	host := strings.TrimSpace(dest)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// "localhost" has exactly the same problem as 127.0.0.1: it resolves to
	// whichever host the rule happens to run on.
	return strings.EqualFold(host, "localhost")
}

// noteDialResult records reachability so a destination this node has never
// reached is reported as not applicable rather than as a failure.
func noteDialResult(dest string, ok bool) {
	if isLoopback(dest) {
		return
	}
	reachableMu.Lock()
	attemptedDst[dest] = true
	if ok {
		reachedDest[dest] = true
	}
	reachableMu.Unlock()
}

// destEverReachable reports whether counting a failure against dest is
// meaningful on this node.
func destEverReachable(dest string) bool {
	if isLoopback(dest) {
		return false
	}
	reachableMu.RLock()
	defer reachableMu.RUnlock()
	return reachedDest[dest]
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
	sniListenerAddr   string
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

// sniRestartMu serialises listener restarts. Two concurrent restarts used to
// race on the same address: each cancelled the other's context and both could
// then fail to bind or immediately shut down again, leaving nothing listening.
var sniRestartMu sync.Mutex

func restartSNIListener(addr string) {
	if addr != "" && !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	sniRestartMu.Lock()
	defer sniRestartMu.Unlock()

	sniListenerMu.Lock()
	previousAddr := sniListenerAddr
	if sniListenerLn != nil {
		sniListenerLn.Close()
		sniListenerLn = nil
	}
	if sniListenerCancel != nil {
		sniListenerCancel()
	}
	sniCtx, cancel := context.WithCancel(mainCtx)
	sniListenerCancel = cancel
	sniListenerAddr = addr
	sniListenerMu.Unlock()

	// Give the old listener a moment to release the port before rebinding.
	time.Sleep(200 * time.Millisecond)

	if bindSNIListener(sniCtx, addr) {
		return
	}

	// The new address is unusable. Falling back to the previous one keeps this
	// node forwarding traffic instead of going dark until someone changes the
	// configuration again — on a node, no listener means a full outage.
	if previousAddr != "" && previousAddr != addr {
		log.Warnf("SNI listen %s failed, falling back to previous address %s", addr, previousAddr)
		sniListenerMu.Lock()
		sniListenerAddr = previousAddr
		sniListenerMu.Unlock()
		if bindSNIListener(sniCtx, previousAddr) {
			return
		}
	}
	log.Errorf("SNI listener is down: neither %s nor %s could be bound", addr, previousAddr)
}

// bindSNIListener tries to bind addr, retrying briefly because the previous
// listener's socket may still be in TIME_WAIT or a peer process may be exiting.
// It reports whether the accept loop was handed a live listener.
func bindSNIListener(ctx context.Context, addr string) bool {
	const attempts = 5
	delay := 200 * time.Millisecond
	for attempt := 1; attempt <= attempts; attempt++ {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		ln, err := net.Listen("tcp", addr)
		if err == nil {
			go serveSNIListener(ctx, addr, ln)
			return true
		}
		log.Errorf("SNI listen %s (attempt %d/%d): %v", addr, attempt, attempts, err)
		if attempt < attempts {
			time.Sleep(delay)
			if delay < 2*time.Second {
				delay *= 2
			}
		}
	}
	return false
}

func startSNIListener(ctx context.Context, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("SNI listen %s: %v", addr, err)
		return
	}
	serveSNIListener(ctx, addr, ln)
}

func serveSNIListener(ctx context.Context, addr string, ln net.Listener) {
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
	acceptDelay := time.Duration(0)
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
			// Back off on transient errors. Without this, a condition that
			// persists — file descriptor exhaustion being the classic one on a
			// busy node — turns this into a hot loop that pins a core and
			// floods the log.
			if acceptDelay == 0 {
				acceptDelay = 5 * time.Millisecond
			} else if acceptDelay < time.Second {
				acceptDelay *= 2
			}
			log.Errorf("SNI accept (retry in %v): %v", acceptDelay, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(acceptDelay):
			}
			continue
		}
		acceptDelay = 0

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

	// A ClientHello is normally well under 2 KiB; 20 KiB covers a full-length
	// record while costing a third of the previous fixed 64 KiB per connection.
	// The reader is pooled because it is only needed for the handshake, not for
	// the lifetime of the connection.
	br := handshakeReaderPool.Get().(*bufio.Reader)
	br.Reset(client)
	defer func() {
		br.Reset(nil)
		handshakeReaderPool.Put(br)
	}()

	sni, peeked, err := peekClientHelloSNI(br)
	if err != nil {
		log.WithFields(logrus.Fields{"client": clientAddr, "err": err}).Warn("SNI peek failed")
	}

	backend, ruleID := routeSNIBackend(sni)
	counters := counterFor(ruleID)
	if counters != nil {
		counters.conns.Add(1)
	}
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
		// Only counted once this node has proved it can reach the destination at
		// all, so a rule aimed at a loopback or node-local address does not make
		// the failure rate meaningless.
		if counters != nil && destEverReachable(backend) {
			counters.dialFail.Add(1)
		}
		noteDialResult(backend, false)
		log.WithFields(logrus.Fields{"client": clientAddr, "backend": backend, "err": err}).Error("dial backend failed")
		return
	}
	noteDialResult(backend, true)
	defer backendConn.Close()

	// The absolute cap now lives in sessionActivity. Setting it on the conns
	// here had no effect: proxyWithIdleTimeout resets the read/write deadlines
	// on every pass, so this deadline was always overwritten before it fired.
	_ = client.SetDeadline(time.Time{})
	_ = backendConn.SetDeadline(time.Time{})

	if len(peeked) > 0 {
		backendConn.Write(peeked)
	}
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		io.ReadFull(br, buf)
		backendConn.Write(buf)
	}

	activity := newSessionActivity(transferTimeout)
	done := make(chan struct{}, 2)
	// c->b is what the client uploads, b->c what it downloads. Kept apart because
	// egress is usually the side that gets billed.
	var up, down *atomic.Uint64
	if counters != nil {
		up, down = &counters.bytesUp, &counters.bytesDown
	}
	go proxyWithIdleTimeout(backendConn, client, done, idleTimeout, activity, "c->b", up)
	go proxyWithIdleTimeout(client, backendConn, done, idleTimeout, activity, "b->c", down)

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

// routeSNIBackend also reports which rule matched, so the traffic can be
// attributed. A zero rule id means nothing matched and the connection is about
// to fall through to default_backend.
func routeSNIBackend(sni string) (string, int) {
	sniRouteMu.RLock()
	entry := sniRouteCache[normalizeSNI(sni)]
	sniRouteMu.RUnlock()
	if entry != nil && len(entry.dests) > 0 {
		return selectBackend(entry.dests, entry.strategy, &entry.counter), entry.ruleID
	}
	sniMissCount.Add(1)
	return getDefaultBackend(), 0
}


func normalizeSNI(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

func normalizeHost(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

func rebuildSniRouteCacheFromDB() error {
	rows, err := db.Query(`
		SELECT id, COALESCE(sni, ''), dest, lb_strategy
		FROM rules
		WHERE type = ? AND enabled = 1
	`, RuleTypeSNI)
	if err != nil {
		return err
	}
	defer rows.Close()

	next := make(map[string]*sniRouteEntry)
	for rows.Next() {
		var ruleID int
		var sni, destJSON, lbStrategy string
		if err := rows.Scan(&ruleID, &sni, &destJSON, &lbStrategy); err != nil {
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
			ruleID:   ruleID,
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
		acceptDelay := time.Duration(0)

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
				// Same backoff as the SNI listener. This loop used to spin
				// silently on a persistent error, with no log line at all to
				// explain the CPU burn.
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else if acceptDelay < time.Second {
					acceptDelay *= 2
				}
				log.Errorf("port %d accept (retry in %v): %v", port, acceptDelay, err)
				select {
				case <-portCtx.Done():
					wg.Wait()
					return
				case <-time.After(acceptDelay):
				}
				continue
			}
			acceptDelay = 0

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handlePortForward(c, ruleID, dests, lbStrategy, &counter, portCtx)
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

func handlePortForward(client net.Conn, ruleID int, dests []string, lbStrategy string, counter *uint64, ctx context.Context) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()

	counters := counterFor(ruleID)
	if counters != nil {
		counters.conns.Add(1)
	}

	backend := selectBackend(dests, lbStrategy, counter)

	backendConn, err := dialBackendWithDNSCache("tcp", backend, 6*time.Second)
	if err != nil {
		if counters != nil && destEverReachable(backend) {
			counters.dialFail.Add(1)
		}
		noteDialResult(backend, false)
		log.WithFields(logrus.Fields{"client": clientAddr, "backend": backend, "err": err}).Error("dial backend failed")
		return
	}
	noteDialResult(backend, true)
	defer backendConn.Close()

	_ = client.SetDeadline(time.Time{})
	_ = backendConn.SetDeadline(time.Time{})

	log.WithFields(logrus.Fields{
		"client":  clientAddr,
		"backend": backend,
	}).Debug("port forward")

	activity := newSessionActivity(transferTimeout)
	done := make(chan struct{}, 2)
	var up, down *atomic.Uint64
	if counters != nil {
		up, down = &counters.bytesUp, &counters.bytesDown
	}
	go proxyWithIdleTimeout(backendConn, client, done, idleTimeout, activity, "c->b", up)
	go proxyWithIdleTimeout(client, backendConn, done, idleTimeout, activity, "b->c", down)

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

// handshakeReaderPool recycles the buffered readers used to peek a ClientHello.
// The size has to exceed maxTLSRecord so a full-length record can still be
// peeked whole, with slack left for reassembling a fragmented handshake.
const handshakeBufSize = 20 * 1024

var handshakeReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, handshakeBufSize)
	},
}

// copyBufPool recycles the 32 KiB relay buffers. Each connection needs two of
// them (one per direction); allocating them per connection made buffer memory
// scale linearly with concurrency and handed the GC a large short-lived object
// for every new connection.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// sessionActivity is shared by both directions of one proxied connection so the
// idle timer reflects the connection as a whole.
type sessionActivity struct {
	lastActive atomic.Int64 // unix nanoseconds
	deadline   time.Time    // absolute cap for the whole session
}

func newSessionActivity(total time.Duration) *sessionActivity {
	s := &sessionActivity{deadline: time.Now().Add(total)}
	s.touch()
	return s
}

func (s *sessionActivity) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *sessionActivity) idleFor() time.Duration {
	return time.Since(time.Unix(0, s.lastActive.Load()))
}

// proxyWithIdleTimeout relays src into dst until the connection as a whole goes
// idle or exceeds its total lifetime.
//
// Idleness is tracked per connection, not per direction. Judging each direction
// on its own meant a long download — where the client sends nothing but ACKs for
// minutes — looked idle from the client side, and the resulting CloseWrite sent
// the backend an EOF that aborted the transfer mid-flight.
//
// The read deadline is a short polling tick rather than the full idle timeout so
// that the shared timestamp and the absolute deadline are re-checked regularly.
// That absolute deadline is what makes transferTimeout real: previously every
// read reset the connection deadline set by the caller, so the intended 2 hour
// cap could never fire.
// bytesTo accumulates relayed payload into a counter when one is supplied. A nil
// counter means the connection could not be attributed to a rule (an SNI miss
// routed to default_backend), and the bytes are simply not attributed.
func bytesTo(c *atomic.Uint64, n int) {
	if c != nil && n > 0 {
		c.Add(uint64(n))
	}
}

func proxyWithIdleTimeout(dst, src net.Conn, done chan<- struct{}, timeout time.Duration, activity *sessionActivity, direction string, relayed *atomic.Uint64) {
	defer func() {
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)
	buf := *bufPtr

	const pollInterval = 5 * time.Second

	for {
		now := time.Now()
		if !activity.deadline.IsZero() && now.After(activity.deadline) {
			log.Debugf("proxy %s closed: exceeded total transfer timeout", direction)
			return
		}
		if activity.idleFor() >= timeout {
			log.Debugf("proxy %s closed: idle for %v", direction, activity.idleFor())
			return
		}

		wake := now.Add(pollInterval)
		if !activity.deadline.IsZero() && activity.deadline.Before(wake) {
			wake = activity.deadline
		}
		_ = src.SetReadDeadline(wake)

		n, err := src.Read(buf)
		if n > 0 {
			activity.touch()
			_ = dst.SetWriteDeadline(time.Now().Add(timeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				// Counted on the read: the bytes did cross this node even if the
				// far side went away before they could be handed on.
				bytesTo(relayed, n)
				return
			}
			bytesTo(relayed, n)
			activity.touch()
		}

		if err != nil {
			// A read deadline hit is just our polling tick: loop round and let
			// the checks above decide whether the connection is really done.
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			return
		}
	}
}

// maxTLSRecord is the largest a single TLS record can be: a 5 byte header plus
// the 2^14 byte maximum payload.
const maxTLSRecord = 5 + 16384

func peekClientHelloSNI(br *bufio.Reader) (string, []byte, error) {
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

	// RFC 8446 §5.1 allows a handshake message to span several records, and some
	// clients deliberately fragment their ClientHello. Walk records until the
	// whole message is in hand instead of giving up on the first one, which used
	// to send every fragmented handshake to the default backend.
	var (
		handshake []byte
		// owned records whether handshake has its own backing array. The first
		// fragment aliases the reader's buffer to avoid a copy in the common
		// single-record case; anything appended after that must go into a buffer
		// we own, or append would write straight into the reader's buffer and
		// corrupt the very bytes we still have to relay to the backend.
		owned bool
		total int
	)
	for {
		if total+5 > handshakeBufSize {
			break
		}
		framed, err := br.Peek(total + 5)
		if err != nil || len(framed) < total+5 {
			break
		}
		recHdr := framed[total : total+5]
		if recHdr[0] != 0x16 {
			break
		}
		recLen := int(recHdr[3])<<8 | int(recHdr[4])
		if recLen <= 0 || recLen > maxTLSRecord-5 {
			if total == 0 {
				peeked := readBuffered(0)
				return "", peeked, fmt.Errorf("invalid TLS record length: %d", recLen)
			}
			break
		}
		end := total + 5 + recLen
		if end > handshakeBufSize {
			break
		}
		full, err := br.Peek(end)
		if err != nil || len(full) < end {
			if total == 0 {
				peeked := readBuffered(0)
				return "", peeked, fmt.Errorf("incomplete TLS record: %v", err)
			}
			break
		}

		fragment := full[total+5 : end]
		if handshake == nil {
			// Common case: one record holds the entire ClientHello, so alias the
			// peek buffer rather than copying it.
			handshake = fragment
		} else {
			if !owned {
				merged := make([]byte, len(handshake), len(handshake)+len(fragment)+512)
				copy(merged, handshake)
				handshake = merged
				owned = true
			}
			handshake = append(handshake, fragment...)
		}
		total = end

		if len(handshake) >= 4 {
			want := 4 + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
			if len(handshake) >= want {
				break
			}
		}
	}

	if len(handshake) < 4 || handshake[0] != 0x01 {
		peeked := readBuffered(total)
		return "", peeked, errors.New("not ClientHello")
	}

	hlen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if hlen+4 > len(handshake) {
		peeked := readBuffered(total)
		return "", peeked, errors.New("truncated ClientHello")
	}

	ch := handshake[4 : 4+hlen]
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
