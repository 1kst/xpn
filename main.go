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
	"runtime"
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
	handshakeTimeout   = 8 * time.Second
	backendDialTimeout = 6 * time.Second
	idleTimeout        = 3 * time.Minute
	transferTimeout    = 2 * time.Hour
	// dnsStaleTTL is how long a name keeps its last good addresses when a refresh
	// fails, before the next attempt.
	dnsStaleTTL      = 30 * time.Second
	dnsCacheTTL      = 60 * time.Second
	dnsNegativeTTL   = 5 * time.Second
	dnsLookupTimeout = 2 * time.Second
)

// DefaultBinaryURL is the fallback download for this node's own architecture.
//
// It used to be a constant naming amd64, so an arm64 node fell back to
// downloading the amd64 build of itself. runtime.GOARCH is the same value the
// CI uses in the asset name and the installer derives from `uname -m`, so the
// three agree; an architecture with no published asset now 404s, which is a
// clearer failure than fetching a binary this machine cannot run.
//
// It and binaryURLForVersion both derive from NodeReleaseOrigin, the constant
// validateBinaryURL pins downloads to, so a URL this node builds for itself can
// never fall outside what it is willing to accept.
func DefaultBinaryURL() string {
	return NodeReleaseOrigin + fmt.Sprintf("latest/download/xpn-node-linux-%s.tar.gz", runtime.GOARCH)
}

var (
	PanelVersion = "v1.0"
	NodeVersion  = "v1.1.19"
)

func binaryURLForVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return DefaultBinaryURL()
	}
	return NodeReleaseOrigin + fmt.Sprintf("download/%s/xpn-node-linux-%s.tar.gz", v, runtime.GOARCH)
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
	// Fallback is where the rule's traffic goes once every address in Dest has
	// been found unreachable. The panel fills it in when the operator pinned this
	// entry node to a landing of its own for the rule: Dest is then that landing
	// and Fallback the rule's shared default. Empty means no failover, which is
	// also what a panel too old to know about pinning sends.
	Fallback []string `json:"fallback,omitempty"`
	Counter  uint64   `json:"-"`
}

type Config struct {
	SNIListen      string `json:"sni_listen"`
	DefaultBackend string `json:"default_backend"`
	WebPanel       string `json:"web_panel"`
	WebAuth        string `json:"web_auth"`
	LogLevel       string `json:"log_level"`
	WebTitle       string `json:"web_title"`
}

// sniRouteEntry is where one rule sends new connections. Port forwarders hold one
// too, swapped in place when the rule's targets change, so a listener no longer
// has to be torn down (and its connections with it) just to point it elsewhere.
type sniRouteEntry struct {
	// ruleID attributes the traffic this route carries. Port rules already know
	// their id from startPortForwarder; SNI rules had no way to report it.
	ruleID   int
	dests    []string
	fallback []string
	strategy string
	counter  uint64
}

// pinned reports whether dests is a landing this entry node was pinned to, with
// fallback to use while it is down.
func (e *sniRouteEntry) pinned() bool {
	return e != nil && len(e.fallback) > 0
}

// pick chooses the backend for a new connection, and whether it is the
// fallback. Without a fallback this is the rule's load balancing exactly as it
// always was.
func (e *sniRouteEntry) pick() (string, bool) {
	if !e.pinned() {
		return selectBackend(e.dests, e.strategy, &e.counter), false
	}
	if len(e.dests) == 1 {
		if !failoverIsDown(e.dests[0]) {
			return e.dests[0], false
		}
	} else {
		live := make([]string, 0, len(e.dests))
		for _, d := range e.dests {
			if !failoverIsDown(d) {
				live = append(live, d)
			}
		}
		if len(live) > 0 {
			return selectBackend(live, e.strategy, &e.counter), false
		}
	}
	return selectBackend(e.fallback, e.strategy, &e.counter), true
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
	// The three ways a connection can fail to reach a rule, counted apart because
	// the single total they used to share cannot be acted on. They mean different
	// things and call for different responses:
	//
	//	missNoTLS  the bytes were not a usable ClientHello at all -- a bare TCP
	//	           connect that sent nothing, a port probe, a plain HTTP request.
	//	           Browsers also land here through speculative preconnect, so this
	//	           is not by itself evidence of hostility.
	//	missNoSNI  a valid ClientHello carrying no server name. A client that
	//	           dialled by IP address rather than by hostname.
	//	missNoRule a client asked for a specific hostname this node does not
	//	           serve. The only one of the three that points at a missing or
	//	           deleted rule, and therefore the only one worth an alert.
	//
	// Their sum is reported as SNIMisses so a panel that predates the split still
	// sees the same total it always did.
	missNoTLS  atomic.Uint64
	missNoSNI  atomic.Uint64
	missNoRule atomic.Uint64
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
	name   string
	// route is read once per accepted connection, so replacing it redirects new
	// connections without closing the listener.
	route atomic.Pointer[sniRouteEntry]
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
	// desiredPorts is what the current configuration wants listening, which can
	// differ from portListeners while a bind is failing and being retried. The
	// retry loop stops as soon as its route is no longer the wanted one.
	desiredPorts  = make(map[int]*sniRouteEntry)
	sniRouteCache = make(map[string]*sniRouteEntry)
	sniRouteMu    sync.RWMutex
	dnsCache      = make(map[string]*dnsCacheEntry)
	dnsCacheMu    sync.Mutex

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

		// From the local table, so a node that restarts while the panel is
		// unreachable still fails over.
		if rules, err := getAllRules(); err == nil {
			setPinnedTargets(rules)
		}
		go failoverLoop(ctx)

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
	// busy_timeout as a pragma: this driver ignores a bare _busy_timeout=, so the
	// timeout was never applied and a write contended by a backup or the sqlite3
	// shell failed at once.
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
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
		fallback TEXT DEFAULT '',
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
	// The database holds the panel token; it has no business being readable by
	// every account on the machine.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Chmod(dbPath+suffix, 0o600)
	}

	database.Exec("ALTER TABLE rules ADD COLUMN version INTEGER DEFAULT 0")
	// Stored so failover survives a restart while the panel is unreachable: the
	// node runs from this table until it can pull again.
	database.Exec("ALTER TABLE rules ADD COLUMN fallback TEXT DEFAULT ''")
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

// restartSNIListener moves the SNI listener to addr.
//
// The new address is bound while the old listener still serves, so moving to
// another port has no gap and a bad address costs nothing; only when the old
// listener holds the very port needed is it released first. Connections already
// relayed are left alone: only the listener moves, where it used to take every
// SNI connection on the node down with it. If the new address cannot be bound
// the node keeps, or goes back to, the previous one, and that address is what
// gets stored: the bad one stored meant the next restart had nothing to fall
// back to. Either way the failure is reported to the panel.
func restartSNIListener(addr string) {
	if addr != "" && !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	sniRestartMu.Lock()
	defer sniRestartMu.Unlock()

	sniListenerMu.Lock()
	previousAddr := sniListenerAddr
	oldLn := sniListenerLn
	sniListenerMu.Unlock()

	parent := mainCtx
	if parent == nil {
		parent = context.Background()
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil && oldLn != nil && samePort(addr, previousAddr) {
		// The old listener is what holds the port. Release it and try again.
		oldLn.Close()
		oldLn = nil
		ln, err = listenWithRetry(addr)
	}
	if err != nil {
		setSNIListenFailure(addr, err)
		if previousAddr == "" || previousAddr == addr {
			log.Errorf("SNI listener is down: %s could not be bound: %v", addr, err)
			return
		}
		if oldLn != nil {
			// Still serving on the previous address; nothing moved.
			log.Warnf("SNI listen %s failed (%v), still listening on %s", addr, err, previousAddr)
			persistSNIListen(previousAddr)
			return
		}
		log.Warnf("SNI listen %s failed (%v), going back to %s", addr, err, previousAddr)
		ln, err = listenWithRetry(previousAddr)
		if err != nil {
			log.Errorf("SNI listener is down: neither %s nor %s could be bound", addr, previousAddr)
			return
		}
		addr = previousAddr
		persistSNIListen(addr)
	} else {
		clearSNIListenFailure()
	}

	ctx, cancel := context.WithCancel(parent)
	sniListenerMu.Lock()
	// The previous context is deliberately not cancelled: that is what closes the
	// connections the old listener accepted. It is a child of mainCtx and goes
	// with it at shutdown.
	sniListenerCancel = cancel
	sniListenerAddr = addr
	// Recorded here, not only by the accept loop once it starts: a restart that
	// follows quickly must see this listener, or it takes the address for free
	// and fails to bind it.
	sniListenerLn = ln
	sniListenerMu.Unlock()
	if oldLn != nil {
		oldLn.Close()
	}
	go serveSNIListener(ctx, addr, ln)
}

func samePort(a, b string) bool {
	_, pa, errA := net.SplitHostPort(a)
	_, pb, errB := net.SplitHostPort(b)
	return errA == nil && errB == nil && pa == pb
}

// listenWithRetry binds addr, retrying briefly for a socket that is still being
// released.
func listenWithRetry(addr string) (net.Listener, error) {
	const attempts = 5
	delay := 200 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		lastErr = err
		if attempt < attempts {
			time.Sleep(delay)
			if delay < 2*time.Second {
				delay *= 2
			}
		}
	}
	return nil, lastErr
}

// persistSNIListen records the address actually in use, so a restart binds what
// works rather than what failed.
func persistSNIListen(addr string) {
	configMu.Lock()
	globalConfig.SNIListen = addr
	configMu.Unlock()
	if db != nil {
		if _, err := db.Exec("UPDATE config SET value = ? WHERE key = 'sni_listen'", addr); err != nil {
			log.Errorf("store SNI listen address %s failed: %v", addr, err)
		}
	}
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
	// Returned to the pool as soon as the handshake bytes are handed on, not when
	// the connection ends: held for the whole relay it made every live connection
	// pin 20 KiB it no longer used.
	releaseReader := func() {
		if br != nil {
			br.Reset(nil)
			handshakeReaderPool.Put(br)
			br = nil
		}
	}
	defer releaseReader()

	sni, peeked, err := peekClientHelloSNI(br)
	if err != nil && len(peeked) == 0 && br.Buffered() == 0 {
		// Nothing arrived at all: a port probe, a bare connect, a health check.
		// Dialling default_backend for it used to cost a backend connection and up
		// to the idle timeout of relaying nothing, per probe.
		noteSNIMiss(sni, err)
		return
	}
	if err != nil {
		// The highest-volume line on the node: every port probe and every browser
		// preconnect that opens a connection without sending a ClientHello lands
		// here. Keyed on the message alone -- the reason a handshake was unreadable
		// is nearly always the same one, and the client address is a sample rather
		// than something worth a key per value.
		if n, ok := throttledLog("peek"); ok {
			log.WithFields(throttledFields(logrus.Fields{"client": clientAddr, "err": err}, n)).Warn("SNI peek failed")
		}
	}

	entry, matched := lookupSNIRoute(sni)
	if !matched {
		noteSNIMiss(sni, err)
	}
	ruleID := 0
	var backend string
	viaFallback := false
	if entry != nil {
		ruleID = entry.ruleID
		backend, viaFallback = entry.pick()
	} else {
		backend = getDefaultBackend()
	}
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
	} else if routeSampleDue() {
		log.WithFields(fields).Info("SNI route sample")
	}
	// A miss that carried a hostname is logged in full, unsampled: it means a
	// client asked for something this node does not serve, which is either a
	// rule that was deleted by mistake or somebody pointing a domain here. The
	// other two kinds are dominated by port probes and browser preconnects and
	// would bury it, so they stay on the sample path above.
	if !matched && err == nil && sni != "" {
		// Deliberately NOT keyed by the hostname: a scanner chooses it, so a key per
		// value would let a client grow this map without bound. One key, with the
		// hostname of the emitted occurrence as a sample and the count of the rest.
		if n, ok := throttledLog("norule"); ok {
			log.WithFields(throttledFields(logrus.Fields{"client": clientAddr, "sni": sni}, n)).Warn("no rule for requested hostname")
		}
	}

	backendConn, backend, viaFallback, err := dialPicked(entry, backend, viaFallback)
	if err != nil {
		// Only counted once this node has proved it can reach the destination at
		// all, so a rule aimed at a loopback or node-local address does not make
		// the failure rate meaningless.
		if counters != nil && destEverReachable(backend) {
			counters.dialFail.Add(1)
		}
		noteDialResult(backend, false)
		// Keyed by backend so one broken destination does not hide another, and so a
		// node whose default_backend refuses every unmatched connection reports it
		// once a minute with a count instead of once per connection.
		if n, ok := throttledLog("dial:" + backend); ok {
			log.WithFields(throttledFields(logrus.Fields{"client": clientAddr, "backend": backend, "err": err}, n)).Error("dial backend failed")
		}
		return
	}
	noteDialResult(backend, true)
	defer backendConn.Close()

	// Registered so a config push or a failover can close this connection when
	// the backend it is on is no longer where its traffic belongs.
	untrack := trackConn(&trackedConn{
		kind:        connKindSNI,
		sni:         normalizeSNI(sni),
		ruleID:      ruleID,
		backend:     backend,
		viaFallback: viaFallback,
		client:      client,
		upstream:    backendConn,
	})
	defer untrack()

	// The absolute cap now lives in sessionActivity. Setting it on the conns
	// here had no effect: proxyWithIdleTimeout resets the read/write deadlines
	// on every pass, so this deadline was always overwritten before it fired.
	_ = client.SetDeadline(time.Time{})
	_ = backendConn.SetDeadline(time.Time{})

	// c->b is what the client uploads, b->c what it downloads. Kept apart because
	// egress is usually the side that gets billed.
	var up, down *atomic.Uint64
	if counters != nil {
		up, down = &counters.bytesUp, &counters.bytesDown
	}

	// The handshake and anything that arrived with it go first. They are client
	// upload like the rest and are counted as such; they used to be written
	// uncounted and with the error ignored.
	first := peeked
	if n := br.Buffered(); n > 0 {
		rest := make([]byte, n)
		io.ReadFull(br, rest)
		first = append(first, rest...)
	}
	releaseReader()
	if len(first) > 0 {
		_ = backendConn.SetWriteDeadline(time.Now().Add(idleTimeout))
		n, werr := backendConn.Write(first)
		bytesTo(up, n)
		if werr != nil {
			return
		}
	}

	relayPair(client, backendConn, up, down, ctx)
}

// relayPair relays both directions of one connection until both are done, or
// ctx ends. When one direction finishes first, the other is put on the shorter
// halfCloseIdle limit and woken so it applies it at once.
func relayPair(client, backendConn net.Conn, up, down *atomic.Uint64, ctx context.Context) {
	activity := newSessionActivity(transferTimeout)
	done := make(chan struct{}, 2)
	go proxyWithIdleTimeout(backendConn, client, done, idleTimeout, activity, "c->b", up)
	go proxyWithIdleTimeout(client, backendConn, done, idleTimeout, activity, "b->c", down)

	select {
	case <-done:
		activity.halfClosed.Store(true)
		wake := time.Now().Add(halfCloseIdle)
		_ = client.SetReadDeadline(wake)
		_ = backendConn.SetReadDeadline(wake)
		select {
		case <-done:
		case <-ctx.Done():
			client.Close()
			backendConn.Close()
			<-done
		}
	case <-ctx.Done():
		client.Close()
		backendConn.Close()
		<-done
		<-done
	}
}

// routeSampleAt is when the last routing sample was logged. Sampling by time
// rather than by count: one in 200 connections was 25 lines a second at 5,000
// connections a second, the flood the throttle elsewhere exists to prevent.
var routeSampleAt atomic.Int64

func routeSampleDue() bool {
	now := time.Now().UnixNano()
	last := routeSampleAt.Load()
	if now-last < int64(logThrottleInterval) {
		return false
	}
	return routeSampleAt.CompareAndSwap(last, now)
}

// lookupSNIRoute returns the route for a hostname and whether anything matched.
// The match is returned explicitly rather than inferred from a nil entry: the
// caller classifies the miss, and it should not have to know which sentinel
// means "none". A miss goes to default_backend.
func lookupSNIRoute(sni string) (*sniRouteEntry, bool) {
	sniRouteMu.RLock()
	entry := sniRouteCache[normalizeSNI(sni)]
	sniRouteMu.RUnlock()
	if entry != nil && len(entry.dests) > 0 {
		return entry, true
	}
	return nil, false
}

// dialPicked connects to the backend pick chose. When that is the landing this
// entry was pinned to and it does not answer within failoverDialTimeout, the
// connection goes to the rule's fallback instead: the first users to hit a
// landing that has just died see a short delay rather than a failure. The failed
// attempt prompts an immediate probe but does not itself count toward marking
// the landing down, since that closes every connection on it and a burst of
// user dials can fail for reasons that say nothing about the landing.
func dialPicked(entry *sniRouteEntry, backend string, viaFallback bool) (net.Conn, string, bool, error) {
	onPinned := entry.pinned() && !viaFallback
	timeout := backendDialTimeout
	if onPinned {
		timeout = failoverDialTimeout
	}
	conn, err := dialBackendWithDNSCache("tcp", backend, timeout)
	if !onPinned {
		if err == nil || entry == nil || viaFallback || len(entry.dests) < 2 {
			return conn, backend, viaFallback, err
		}
		// One more target before giving up: with several targets a dead one used
		// to fail its whole share of connections until something noticed, and
		// health_check kept choosing it for up to a probe interval.
		markProbeFailed(backend)
		alt := alternativeDest(entry.dests, backend)
		if alt == "" {
			return conn, backend, viaFallback, err
		}
		noteDialResult(backend, false)
		if n, ok := throttledLog("retry:" + backend); ok {
			log.WithFields(throttledFields(logrus.Fields{"backend": backend, "retry": alt, "err": err}, n)).Warn("backend unreachable, trying another target of the rule")
		}
		conn, err = dialBackendWithDNSCache("tcp", alt, backendDialTimeout)
		return conn, alt, false, err
	}
	if err == nil {
		// Only probes move a landing between up and down, in both directions: a
		// landing that fails half its connections must still be caught by the
		// probes, which user successes resetting the count would prevent.
		return conn, backend, false, nil
	}
	noteDialResult(backend, false)
	failoverSuspect(backend)
	fallback := selectBackend(entry.fallback, entry.strategy, &entry.counter)
	if n, ok := throttledLog("pinfail:" + backend); ok {
		log.WithFields(throttledFields(logrus.Fields{"landing": backend, "fallback": fallback, "err": err}, n)).Warn("pinned landing unreachable, using fallback")
	}
	conn, err = dialBackendWithDNSCache("tcp", fallback, backendDialTimeout)
	return conn, fallback, true, err
}

// alternativeDest is the target after failed in dests, wrapping round.
func alternativeDest(dests []string, failed string) string {
	for i, d := range dests {
		if d == failed {
			for j := 1; j < len(dests); j++ {
				if alt := dests[(i+j)%len(dests)]; alt != failed {
					return alt
				}
			}
			return ""
		}
	}
	return ""
}

// noteSNIMiss books a connection that reached no rule against the reason it did
// not. Counting happens here rather than inside routeSNIBackend because only the
// caller knows whether the ClientHello parsed, and that distinction is the whole
// point of splitting the counter.
func noteSNIMiss(sni string, peekErr error) {
	switch {
	case peekErr != nil:
		missNoTLS.Add(1)
	case sni == "":
		missNoSNI.Add(1)
	default:
		missNoRule.Add(1)
	}
}

// totalSNIMisses is what the wire protocol has always called SNIMisses.
func totalSNIMisses() uint64 {
	return missNoTLS.Load() + missNoSNI.Load() + missNoRule.Load()
}

func normalizeSNI(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

func normalizeHost(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
}

func rebuildSniRouteCacheFromDB() error {
	rows, err := db.Query(`
		SELECT id, COALESCE(sni, ''), dest, lb_strategy, COALESCE(fallback, '')
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
		var sni, destJSON, lbStrategy, fallbackJSON string
		if err := rows.Scan(&ruleID, &sni, &destJSON, &lbStrategy, &fallbackJSON); err != nil {
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
			fallback: decodeDestList(fallbackJSON),
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
		if old, ok := dnsCache[host]; ok && !old.negative && len(old.ips) > 0 {
			// Serve the last good answer rather than none: a resolver hiccup at
			// the moment the entry expired used to fail every connection to the
			// name, and failover probes with it, which could mark a pinned
			// landing down that had never stopped answering.
			old.expiresAt = time.Now().Add(dnsStaleTTL)
			ordered := rotateIPs(old.ips, old.nextIdx)
			old.nextIdx = (old.nextIdx + 1) % len(old.ips)
			dnsCacheMu.Unlock()
			if n, ok := throttledLog("dnsstale:" + host); ok {
				log.WithFields(throttledFields(logrus.Fields{"host": host, "err": err}, n)).Warn("dns refresh failed, still using the previous addresses")
			}
			return ordered, nil
		}
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
	rules, err := getAllRules()
	if err != nil {
		return err
	}
	reconcilePortForwarders(ctx, rules)
	return nil
}

// portSpec is one enabled port rule as the listeners need it.
type portSpec struct {
	port  int
	name  string
	route *sniRouteEntry
}

func portSpecsFromRules(rules []Rule) map[int]portSpec {
	want := make(map[int]portSpec)
	for _, rule := range rules {
		if rule.Type != RuleTypePort || !rule.Enabled {
			continue
		}
		if rule.ListenPort < 1 || rule.ListenPort > 65535 {
			log.Warnf("port rule %q has unusable listen port %d, skipped", rule.Name, rule.ListenPort)
			continue
		}
		want[rule.ListenPort] = portSpec{
			port: rule.ListenPort,
			name: rule.Name,
			route: &sniRouteEntry{
				ruleID:   rule.ID,
				dests:    rule.Dest,
				fallback: rule.Fallback,
				strategy: rule.LBStrategy,
			},
		}
	}
	return want
}

// reconcilePortForwarders brings the listeners in line with rules. A port that
// stays configured keeps its listener and has only its route swapped, so its
// connections survive; which of them still belong where they are is decided
// afterwards by dropStaleConnections. Only a port that is no longer wanted is
// closed, and only a new one is bound.
func reconcilePortForwarders(ctx context.Context, rules []Rule) {
	if ctx == nil {
		ctx = context.Background()
	}
	want := portSpecsFromRules(rules)

	var toStart []portSpec
	portListenersMu.Lock()
	for port, pf := range portListeners {
		if _, ok := want[port]; ok {
			continue
		}
		log.Infof("stopping port forwarder on :%d, no longer configured", port)
		pf.cancel()
		if pf.ln != nil {
			_ = pf.ln.Close()
		}
		delete(portListeners, port)
	}
	desiredPorts = make(map[int]*sniRouteEntry, len(want))
	for port, spec := range want {
		desiredPorts[port] = spec.route
		if pf, ok := portListeners[port]; ok {
			pf.route.Store(spec.route)
			pf.name = spec.name
			continue
		}
		toStart = append(toStart, spec)
	}
	portListenersMu.Unlock()

	for _, spec := range toStart {
		go ensurePortListener(ctx, spec)
	}
}

// ensurePortListener binds a port and keeps retrying while the bind fails, which
// it can when another process holds the port or the previous socket has not
// been released yet. It used to be a single attempt whose error was discarded,
// so the rule stopped working with nothing in the log to say so. The failure is
// also reported to the panel on each heartbeat until the bind succeeds.
func ensurePortListener(ctx context.Context, spec portSpec) {
	delay := 2 * time.Second
	for {
		err := upsertPortForwarder(ctx, spec.port, spec.name, spec.route, true)
		if err == nil {
			return
		}
		if errors.Is(err, errPortNotWanted) {
			// A newer configuration took the port over or dropped it; whichever it
			// was, it is now responsible for the port and for its failure record.
			return
		}
		if n, ok := throttledLog(fmt.Sprintf("listen:%d", spec.port)); ok {
			log.WithFields(throttledFields(logrus.Fields{"port": spec.port, "rule": spec.name, "err": err, "retry_in": delay}, n)).Error("port forwarder cannot listen")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

var errPortNotWanted = errors.New("port is no longer wanted by the configuration")

// startPortForwarder serves one port rule. Kept for the local web panel, which
// manages rules one at a time; config pushed from the panel goes through
// reconcilePortForwarders instead.
func startPortForwarder(ctx context.Context, ruleID int, name string, port int, dests []string, lbStrategy string) error {
	route := &sniRouteEntry{ruleID: ruleID, dests: dests, strategy: lbStrategy}
	portListenersMu.Lock()
	desiredPorts[port] = route
	portListenersMu.Unlock()
	return upsertPortForwarder(ctx, port, name, route, false)
}

// upsertPortForwarder points port at route, binding a listener only if there is
// none yet. An existing listener is never closed here: replacing its route is
// enough to redirect new connections, and closing it used to cut every
// connection it carried.
//
// onlyIfWanted makes the check against desiredPorts part of the same critical
// section as the bind, so a retry that raced a newer configuration cannot
// install the route that configuration just replaced.
func upsertPortForwarder(ctx context.Context, port int, name string, route *sniRouteEntry, onlyIfWanted bool) error {
	portListenersMu.Lock()
	defer portListenersMu.Unlock()

	if onlyIfWanted && desiredPorts[port] != route {
		return errPortNotWanted
	}

	if pf, exists := portListeners[port]; exists {
		pf.route.Store(route)
		pf.name = name
		clearListenFailure(port)
		return nil
	}

	// The failure record is written and cleared here, under the same lock as the
	// bind, so a retry that failed cannot record its failure after a newer
	// attempt has bound the port and cleared it.
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		recordListenFailure(port, route.ruleID, err)
		return err
	}
	clearListenFailure(port)

	portCtx, cancel := context.WithCancel(ctx)
	pf := &portForwarder{
		cancel: cancel,
		ln:     ln,
		name:   name,
	}
	pf.route.Store(route)
	portListeners[port] = pf

	log.WithFields(logrus.Fields{
		"name": name,
		"port": port,
		"dest": route.dests,
		"lb":   route.strategy,
	}).Info("port forwarder started")

	go func() {
		defer ln.Close()
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
				handlePortForward(c, port, pf.route.Load(), portCtx)
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
	desiredPorts = make(map[int]*sniRouteEntry)
}

// handlePortForward relays one connection accepted on port. route is the
// listener's route at the moment the connection was accepted; a later config
// push that moves the rule elsewhere closes this connection through
// dropStaleConnections rather than by tearing the listener down.
func handlePortForward(client net.Conn, port int, route *sniRouteEntry, ctx context.Context) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()
	if route == nil {
		return
	}
	ruleID := route.ruleID

	counters := counterFor(ruleID)
	if counters != nil {
		counters.conns.Add(1)
	}

	backend, viaFallback := route.pick()

	backendConn, backend, viaFallback, err := dialPicked(route, backend, viaFallback)
	if err != nil {
		if counters != nil && destEverReachable(backend) {
			counters.dialFail.Add(1)
		}
		noteDialResult(backend, false)
		if n, ok := throttledLog("dialport:" + backend); ok {
			log.WithFields(throttledFields(logrus.Fields{"client": clientAddr, "backend": backend, "err": err}, n)).Error("dial backend failed")
		}
		return
	}
	noteDialResult(backend, true)
	defer backendConn.Close()

	untrack := trackConn(&trackedConn{
		kind:        connKindPort,
		port:        port,
		ruleID:      ruleID,
		backend:     backend,
		viaFallback: viaFallback,
		client:      client,
		upstream:    backendConn,
	})
	defer untrack()

	_ = client.SetDeadline(time.Time{})
	_ = backendConn.SetDeadline(time.Time{})

	log.WithFields(logrus.Fields{
		"client":  clientAddr,
		"backend": backend,
	}).Debug("port forward")

	var up, down *atomic.Uint64
	if counters != nil {
		up, down = &counters.bytesUp, &counters.bytesDown
	}
	relayPair(client, backendConn, up, down, ctx)
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
			// A target not probed yet has no latency, not a latency of zero; it
			// used to win outright until its first probe finished.
			if ok && state.probed && state.lastMS >= 0 {
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

// halfCloseIdle is the idle limit once one direction has finished. A peer that
// closed its side and a backend that accepted and then went silent used to hold
// both sockets for the full idleTimeout; the direction still open is given this
// much silence instead. A transfer still moving is not cut. A variable only so
// tests need not wait half a minute.
var halfCloseIdle = 30 * time.Second

// sessionActivity is shared by both directions of one proxied connection so the
// idle timer reflects the connection as a whole.
type sessionActivity struct {
	lastActive atomic.Int64 // unix nanoseconds
	deadline   time.Time    // absolute cap for the whole session
	// halfClosed is set once one direction has finished; the other then goes by
	// halfCloseIdle instead of the full idle timeout.
	halfClosed atomic.Bool
}

func newSessionActivity(total time.Duration) *sessionActivity {
	now := time.Now()
	s := &sessionActivity{deadline: now.Add(total)}
	s.touchAt(now)
	return s
}

func (s *sessionActivity) touchAt(now time.Time) {
	s.lastActive.Store(now.UnixNano())
}

func (s *sessionActivity) last() time.Time {
	return time.Unix(0, s.lastActive.Load())
}

func (s *sessionActivity) idleLimit(timeout time.Duration) time.Duration {
	if s.halfClosed.Load() && halfCloseIdle < timeout {
		return halfCloseIdle
	}
	return timeout
}

// proxyWithIdleTimeout relays src into dst until the connection as a whole goes
// idle or exceeds its total lifetime.
//
// Idleness is tracked per connection, not per direction. Judging each direction
// on its own meant a long download — where the client sends nothing but ACKs for
// minutes — looked idle from the client side, and the resulting CloseWrite sent
// the backend an EOF that aborted the transfer mid-flight.
//
// The read deadline is the moment the connection would go idle, not a fixed
// tick: an idle connection wakes once per idle period, where a five second tick
// woke every idle connection twelve times a minute for nothing. A direction
// woken early because the other one was busy finds the shared timestamp moved on
// and sleeps again. Deadlines are only moved when they would change by more than
// a second, and the clock is read twice per chunk; resetting both deadlines and
// reading the clock five times per chunk used to cost more than the copy on
// virtual machines with a slow clock source.
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

	var readDL, writeDL time.Time
	now := time.Now()
	for {
		if !activity.deadline.IsZero() && !now.Before(activity.deadline) {
			log.Debugf("proxy %s closed: exceeded total transfer timeout", direction)
			return
		}
		last := activity.last()
		limit := activity.idleLimit(timeout)
		if now.Sub(last) >= limit {
			log.Debugf("proxy %s closed: idle for %v", direction, now.Sub(last))
			return
		}

		wake := last.Add(limit)
		if !activity.deadline.IsZero() && activity.deadline.Before(wake) {
			wake = activity.deadline
		}
		if readDL.IsZero() || wake.Before(readDL) || wake.Sub(readDL) > time.Second {
			readDL = wake
			_ = src.SetReadDeadline(wake)
		}

		n, err := src.Read(buf)
		now = time.Now()
		if n > 0 {
			activity.touchAt(now)
			if wd := now.Add(timeout); wd.Sub(writeDL) > time.Second {
				writeDL = wd
				_ = dst.SetWriteDeadline(wd)
			}
			_, werr := dst.Write(buf[:n])
			// Counted on the read: the bytes did cross this node even if the far
			// side went away before they could be handed on.
			bytesTo(relayed, n)
			if werr != nil {
				return
			}
			// A write can block for a long time on a slow receiver; that is
			// activity too.
			now = time.Now()
			activity.touchAt(now)
		}

		if err != nil {
			// A read deadline hit means "check again": loop round and let the
			// checks above decide whether the connection is really done. The
			// deadline this goroutine last set may have been replaced from outside
			// (see relayPair), so it is recomputed rather than trusted.
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				readDL = time.Time{}
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
