package xpfw

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	loginAttempts   = make(map[string]*attemptInfo)
	loginAttemptsMu sync.Mutex
	sessionCache    = make(map[string]*sessionInfo) // active web sessions in memory
	sessionCacheMu  sync.RWMutex
)

type attemptInfo struct {
	count       int
	lastAttempt time.Time
}

type sessionInfo struct {
	token     string
	createdAt time.Time
	expiresAt time.Time
}

const (
	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
	sessionDuration  = 24 * time.Hour
)

func startWebPanel(addr, _ string) {
	loadSessionsFromDB()

	go cleanupRoutine()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/config", authMiddleware(handleConfig))
	http.HandleFunc("/api/panel/config", authMiddleware(handlePanelConfigAPI))
	http.HandleFunc("/api/rules", authMiddleware(handleRules))
	http.HandleFunc("/api/rule", authMiddleware(handleRule))
	http.HandleFunc("/api/rule/import", authMiddleware(handleImport))
	http.HandleFunc("/api/rule/export", authMiddleware(handleExport))

	server := &http.Server{
		Addr:              addr,
		Handler:           nil,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Infof("web panel started on %s", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("web panel failed: %v", err)
	}
}

func loadSessionsFromDB() {
	rows, err := db.Query("SELECT token, created_at, expires_at FROM sessions WHERE expires_at > datetime('now')")
	if err != nil {
		log.Warnf("load sessions from db: %v", err)
		return
	}
	defer rows.Close()

	count := 0
	sessionCacheMu.Lock()
	for rows.Next() {
		var token, createdAt, expiresAt string
		if err := rows.Scan(&token, &createdAt, &expiresAt); err != nil {
			continue
		}

		created, _ := time.Parse("2006-01-02 15:04:05", createdAt)
		expires, _ := time.Parse("2006-01-02 15:04:05", expiresAt)

		sessionCache[token] = &sessionInfo{
			token:     token,
			createdAt: created,
			expiresAt: expires,
		}
		count++
	}
	sessionCacheMu.Unlock()
	log.Infof("loaded %d valid sessions from database", count)
}

func cleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		result, err := db.Exec("DELETE FROM sessions WHERE expires_at <= datetime('now')")
		if err == nil {
			if affected, _ := result.RowsAffected(); affected > 0 {
				log.Infof("cleaned %d expired sessions from database", affected)
			}
		}

		now := time.Now()
		sessionCacheMu.Lock()
		for token, session := range sessionCache {
			if now.After(session.expiresAt) {
				delete(sessionCache, token)
			}
		}
		sessionCacheMu.Unlock()

		loginAttemptsMu.Lock()
		for ip, info := range loginAttempts {
			if now.Sub(info.lastAttempt) > lockoutDuration {
				delete(loginAttempts, ip)
			}
		}
		loginAttemptsMu.Unlock()
	}
}

func getClientIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// fallback should never happen, but avoid silent failure
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	configMu.RLock()
	password := globalConfig.WebAuth
	configMu.RUnlock()

	if password == "" {
		http.Error(w, `{"error":"No password configured"}`, http.StatusForbidden)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getClientIP(r)

	loginAttemptsMu.Lock()
	info, exists := loginAttempts[ip]
	if exists {
		if info.count >= maxLoginAttempts {
			if time.Since(info.lastAttempt) < lockoutDuration {
				loginAttemptsMu.Unlock()
				remainingTime := lockoutDuration - time.Since(info.lastAttempt)
				http.Error(w, fmt.Sprintf(`{"error":"Too many attempts. Please try again in %d minutes"}`, int(remainingTime.Minutes())+1), http.StatusTooManyRequests)
				return
			}
			delete(loginAttempts, ip)
		}
	}
	loginAttemptsMu.Unlock()

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(password)) != 1 {
		loginAttemptsMu.Lock()
		if info, exists := loginAttempts[ip]; exists {
			info.count++
			info.lastAttempt = time.Now()
		} else {
			loginAttempts[ip] = &attemptInfo{
				count:       1,
				lastAttempt: time.Now(),
			}
		}
		attempts := loginAttempts[ip].count
		loginAttemptsMu.Unlock()

		log.Warnf("failed login attempt from %s (attempt %d/%d)", ip, attempts, maxLoginAttempts)

		http.Error(w, fmt.Sprintf(`{"error":"Invalid password","remaining":%d}`, maxLoginAttempts-attempts), http.StatusUnauthorized)
		return
	}

	loginAttemptsMu.Lock()
	delete(loginAttempts, ip)
	loginAttemptsMu.Unlock()

	token := generateSessionToken()
	now := time.Now()
	expiresAt := now.Add(sessionDuration)

	_, err := db.Exec("INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)",
		token, now.Format("2006-01-02 15:04:05"), expiresAt.Format("2006-01-02 15:04:05"))

	if err != nil {
		log.Errorf("failed to save session to db: %v", err)
		http.Error(w, `{"error":"创建会话失败"}`, http.StatusInternalServerError)
		return
	}

	sessionCacheMu.Lock()
	sessionCache[token] = &sessionInfo{
		token:     token,
		createdAt: now,
		expiresAt: expiresAt,
	}
	sessionCacheMu.Unlock()

	log.Infof("successful login from %s, session will expire in 24h", ip)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"token":   token,
		"expires": sessionDuration.Seconds(),
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	if token != "" {
		db.Exec("DELETE FROM sessions WHERE token = ?", token)

		sessionCacheMu.Lock()
		delete(sessionCache, token)
		sessionCacheMu.Unlock()

		log.Info("user logged out successfully")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configMu.RLock()
		password := globalConfig.WebAuth
		configMu.RUnlock()

		if password == "" {
			next(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var token string
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			token = authHeader
		}

		sessionCacheMu.RLock()
		session, exists := sessionCache[token]
		sessionCacheMu.RUnlock()

		if exists && time.Now().Before(session.expiresAt) {
			newExpiresAt := time.Now().Add(sessionDuration)

			db.Exec("UPDATE sessions SET expires_at = ? WHERE token = ?",
				newExpiresAt.Format("2006-01-02 15:04:05"), token)

			sessionCacheMu.Lock()
			session.expiresAt = newExpiresAt
			sessionCacheMu.Unlock()

			next(w, r)
			return
		}

		if !exists {
			var expiresAtStr string
			err := db.QueryRow("SELECT expires_at FROM sessions WHERE token = ?", token).Scan(&expiresAtStr)
			if err == nil {
				expiresAt, _ := time.Parse("2006-01-02 15:04:05", expiresAtStr)
				if time.Now().Before(expiresAt) {
					newExpiresAt := time.Now().Add(sessionDuration)

					db.Exec("UPDATE sessions SET expires_at = ? WHERE token = ?",
						newExpiresAt.Format("2006-01-02 15:04:05"), token)

					sessionCacheMu.Lock()
					sessionCache[token] = &sessionInfo{
						token:     token,
						createdAt: time.Now(),
						expiresAt: newExpiresAt,
					}
					sessionCacheMu.Unlock()

					next(w, r)
					return
				}
			}
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(password)) == 1 {
			next(w, r)
			return
		}

		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
	}
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		configMu.RLock()
		defer configMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(globalConfig)
	} else if r.Method == "POST" {
		var cfg Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := saveConfig(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		incrementConfigVersion()

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func handleRules(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, name, type, COALESCE(sni, ''), COALESCE(listen_port, 0), dest, lb_strategy, enabled, version
		FROM rules ORDER BY id DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var rule Rule
		var destJSON string
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Type, &rule.SNI, &rule.ListenPort, &destJSON, &rule.LBStrategy, &enabled, &rule.Version); err != nil {
			continue
		}
		json.Unmarshal([]byte(destJSON), &rule.Dest)
		rule.Enabled = enabled == 1
		rules = append(rules, rule)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func handleRule(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		addRuleHandler(w, r)
	case "PUT":
		updateRuleHandler(w, r)
	case "DELETE":
		deleteRuleHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func addRuleHandler(w http.ResponseWriter, r *http.Request) {
	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rule.SNI = normalizeSNI(rule.SNI)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM rules WHERE name = ?", rule.Name).Scan(&count)
	if count > 0 {
		http.Error(w, `{"error":"规则名称宸插瓨鍦?}`, http.StatusConflict)
		return
	}

	if rule.Type == RuleTypeSNI {
		db.QueryRow("SELECT COUNT(*) FROM rules WHERE type = ? AND sni = ?", RuleTypeSNI, rule.SNI).Scan(&count)
		if count > 0 {
			http.Error(w, `{"error":"SNI 规则宸插瓨鍦?}`, http.StatusConflict)
			return
		}
	} else if rule.Type == RuleTypePort {
		db.QueryRow("SELECT COUNT(*) FROM rules WHERE type = ? AND listen_port = ?", RuleTypePort, rule.ListenPort).Scan(&count)
		if count > 0 {
			http.Error(w, `{"error":"閻╂垵鎯夌粩顖氬經瀹告彃鐡ㄩ崷?}`, http.StatusConflict)
			return
		}
	}

	destJSON, _ := json.Marshal(rule.Dest)
	enabled := 1
	if !rule.Enabled {
		enabled = 0
	}

	ruleVersion := incrementConfigVersion()

	result, err := db.Exec(`
		INSERT INTO rules (name, type, sni, listen_port, dest, lb_strategy, enabled, version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.Name, rule.Type, rule.SNI, rule.ListenPort, string(destJSON), rule.LBStrategy, enabled, ruleVersion)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rule.Type == RuleTypePort && rule.Enabled {
		id, _ := result.LastInsertId()
		ctx := context.Background()
		go startPortForwarder(ctx, int(id), rule.Name, rule.ListenPort, rule.Dest, rule.LBStrategy)
	}
	if err := rebuildSniRouteCacheFromDB(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("rule added: %s (%s)", rule.Name, rule.Type)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func updateRuleHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var rule Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rule.SNI = normalizeSNI(rule.SNI)

	destJSON, _ := json.Marshal(rule.Dest)
	enabled := 1
	if !rule.Enabled {
		enabled = 0
	}

	var oldType string
	var oldPort int
	db.QueryRow("SELECT type, listen_port FROM rules WHERE id = ?", id).Scan(&oldType, &oldPort)

	ruleVersion := incrementConfigVersion()

	_, err = db.Exec(`
		UPDATE rules SET name = ?, type = ?, sni = ?, listen_port = ?, dest = ?, lb_strategy = ?, enabled = ?, version = ?
		WHERE id = ?
	`, rule.Name, rule.Type, rule.SNI, rule.ListenPort, string(destJSON), rule.LBStrategy, enabled, ruleVersion, id)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rule.Type == RuleTypePort {
		if oldPort != 0 && oldPort != rule.ListenPort {
			portListenersMu.Lock()
			if pf, ok := portListeners[oldPort]; ok {
				pf.cancel()
				if pf.ln != nil {
					_ = pf.ln.Close()
				}
				delete(portListeners, oldPort)
			}
			portListenersMu.Unlock()
		}

		if rule.Enabled {
			ctx := context.Background()
			go startPortForwarder(ctx, id, rule.Name, rule.ListenPort, rule.Dest, rule.LBStrategy)
		}
	}
	if err := rebuildSniRouteCacheFromDB(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("rule updated: %s (ID=%d)", rule.Name, id)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func deleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var ruleType string
	var port int
	db.QueryRow("SELECT type, listen_port FROM rules WHERE id = ?", id).Scan(&ruleType, &port)

	_, err = db.Exec("DELETE FROM rules WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ruleType == RuleTypePort && port != 0 {
		portListenersMu.Lock()
		if pf, ok := portListeners[port]; ok {
			pf.cancel()
			if pf.ln != nil {
				_ = pf.ln.Close()
			}
			delete(portListeners, port)
		}
		portListenersMu.Unlock()
	}

	log.Infof("rule deleted: ID=%d", id)

	incrementConfigVersion()
	if err := rebuildSniRouteCacheFromDB(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lines := strings.Split(req.Data, "\n")
	imported := 0
	failed := 0
	skipped := 0
	var importedIDs []int64

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var item struct {
			Name       string   `json:"name"`
			Type       string   `json:"type"`
			SNI        string   `json:"sni"`
			ListenPort int      `json:"listen_port"`
			Dest       []string `json:"dest"`
			LBStrategy string   `json:"lb_strategy"`
			Enabled    bool     `json:"enabled"`
		}

		if err := json.Unmarshal([]byte(line), &item); err != nil {
			failed++
			continue
		}

		if item.Type == "" {
			item.Type = RuleTypePort
		}
		item.SNI = normalizeSNI(item.SNI)

		var existCount int
		if item.Type == RuleTypeSNI {
			db.QueryRow("SELECT COUNT(*) FROM rules WHERE name = ? OR (type = ? AND sni = ?)", item.Name, RuleTypeSNI, item.SNI).Scan(&existCount)
		} else {
			db.QueryRow("SELECT COUNT(*) FROM rules WHERE name = ? OR (type = ? AND listen_port = ?)", item.Name, RuleTypePort, item.ListenPort).Scan(&existCount)
		}

		if existCount > 0 {
			skipped++
			continue
		}

		if item.LBStrategy == "" {
			item.LBStrategy = LBRoundRobin
		}

		destJSON, _ := json.Marshal(item.Dest)
		enabled := 1
		if !item.Enabled {
			enabled = 0
		}

		result, err := db.Exec(`
			INSERT INTO rules (name, type, sni, listen_port, dest, lb_strategy, enabled, version)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, item.Name, item.Type, item.SNI, item.ListenPort, string(destJSON), item.LBStrategy, enabled, 0)

		if err != nil {
			failed++
			continue
		}

		newID, _ := result.LastInsertId()
		importedIDs = append(importedIDs, newID)

		if item.Type == RuleTypePort && item.Enabled {
			ctx := context.Background()
			go startPortForwarder(ctx, int(newID), item.Name, item.ListenPort, item.Dest, item.LBStrategy)
		}
		imported++
	}

	log.Infof("batch import: %d succeeded, %d failed", imported, failed)

	if imported > 0 {
		batchVersion := incrementConfigVersion()
		for _, id := range importedIDs {
			db.Exec("UPDATE rules SET version = ? WHERE id = ?", batchVersion, id)
		}
	}
	if err := rebuildSniRouteCacheFromDB(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"imported": imported,
		"failed":   failed,
		"skipped":  skipped,
	})
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, name, type, COALESCE(sni, ''), COALESCE(listen_port, 0), dest, lb_strategy, enabled
		FROM rules ORDER BY id ASC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	for _, rule := range rules {
		exportRule := map[string]interface{}{
			"name":        rule.Name,
			"type":        rule.Type,
			"listen_port": rule.ListenPort,
			"dest":        rule.Dest,
			"lb_strategy": rule.LBStrategy,
			"enabled":     rule.Enabled,
		}
		if rule.Type == RuleTypeSNI {
			exportRule["sni"] = rule.SNI
		}
		json.NewEncoder(w).Encode(exportRule)
	}

	log.Infof("exported %d rules", len(rules))
}

func handlePanelConfigAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		panelConfigMu.RLock()
		cfg := map[string]interface{}{
			"mode":          panelConfig.Mode,
			"panel_url":     panelConfig.PanelURL,
			"panel_token":   panelConfig.PanelToken,
			"node_id":       panelConfig.NodeID,
			"pull_interval": panelConfig.PullInterval,
		}
		panelConfigMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	} else if r.Method == "POST" {
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		panelConfigMu.Lock()
		if mode, ok := req["mode"].(string); ok {
			panelConfig.Mode = mode
		}
		if url, ok := req["panel_url"].(string); ok {
			panelConfig.PanelURL = url
		}
		if token, ok := req["panel_token"].(string); ok {
			panelConfig.PanelToken = token
		}
		if interval, ok := req["pull_interval"].(float64); ok {
			panelConfig.PullInterval = int(interval)
		}
		panelConfigMu.Unlock()

		if err := savePanelConfigToDB(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "面板配置已保存",
		})
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, getHTML())
}

func getHTML() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SNI Proxy Pro</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px}
.container{max-width:1400px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;padding:30px;text-align:center;border-radius:12px 12px 0 0;position:relative}
.header h1{font-size:2.5em;margin-bottom:10px}
.logout-btn{position:absolute;top:30px;right:30px;background:rgba(255,255,255,.2);border:2px solid #fff;color:#fff;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600;transition:.3s}
.logout-btn:hover{background:rgba(255,255,255,.3);transform:translateY(-2px)}
.tabs{display:flex;background:#f8f9fa;border-bottom:2px solid #dee2e6}
.tab{flex:1;padding:15px;text-align:center;cursor:pointer;transition:.3s;font-weight:600;color:#6c757d}
.tab:hover{background:#e9ecef}
.tab.active{background:#fff;color:#667eea;border-bottom:3px solid #667eea}
.content{padding:30px}
.tab-content{display:none}
.tab-content.active{display:block}
.toolbar{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
.btn{padding:10px 20px;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;transition:.3s}
.btn-primary{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff}
.btn-secondary{background:#6c757d;color:#fff}
.btn-success{background:#198754;color:#fff}
.btn-danger{background:#dc3545;color:#fff}
.btn-warning{background:#fd7e14;color:#fff}
.btn-info{background:#6c757d;color:#fff}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}
thead{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff}
th,td{padding:12px;text-align:left}
tbody tr:hover{background:#f8f9fa}
tbody tr{border-bottom:1px solid #dee2e6}
.badge{display:inline-block;padding:4px 8px;border-radius:4px;font-size:12px;font-weight:600}
.badge-sni{background:#e3f2fd;color:#1976d2}
.badge-port{background:#f3e5f5;color:#7b1fa2}
.badge-success{background:#d1e7dd;color:#0f5132}
.badge-warning{background:#fff3cd;color:#664d03}
.badge-danger{background:#f8d7da;color:#842029}
.badge-muted{background:#e2e3e5;color:#495057}
.badge-enabled{background:#d1e7dd;color:#0f5132}
.badge-disabled{background:#f8d7da;color:#842029}
.toast-wrap{position:fixed;top:16px;right:16px;z-index:3000;display:flex;flex-direction:column;gap:8px}
.toast{min-width:280px;max-width:420px;padding:10px 12px;border-radius:8px;color:#fff;font-size:13px;box-shadow:0 8px 30px rgba(0,0,0,.25)}
.toast-info{background:#0d6efd}
.toast-success{background:#198754}
.toast-warning{background:#fd7e14}
.toast-error{background:#dc3545}
.row-status{margin-top:8px;padding:6px 8px;border-radius:6px;font-size:12px}
.row-status-success{background:#d1e7dd;color:#0f5132}
.row-status-warning{background:#fff3cd;color:#664d03}
.row-status-danger{background:#f8d7da;color:#842029}
.row-status-muted{background:#e2e3e5;color:#495057}
.node-modal{justify-content:flex-end;align-items:stretch}
.node-modal .modal-content{max-width:none;width:min(520px,95vw);height:100vh;max-height:100vh;border-radius:0;padding:24px;transform:translateX(100%);transition:transform .25s ease}
.node-modal.active .modal-content{transform:translateX(0)}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.6);justify-content:center;align-items:center;z-index:1000}
.modal.active{display:flex}
.modal-content{background:#fff;padding:30px;border-radius:12px;width:90%;max-width:600px;max-height:90vh;overflow-y:auto}
.form-group{margin-bottom:20px}
.form-group label{display:block;margin-bottom:8px;font-weight:600;color:#495057}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:10px;border:2px solid #ced4da;border-radius:6px;font-size:14px}
.form-group textarea{font-family:monospace;resize:vertical;min-height:100px}
.form-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}
.auth-panel{position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);display:flex;justify-content:center;align-items:center;z-index:2000}
.auth-box{background:#fff;padding:40px;border-radius:12px;width:90%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.auth-box h2{margin-bottom:20px;text-align:center;color:#333}
.error-msg{color:#dc3545;font-size:14px;margin-top:10px;text-align:center}
.dest-item{background:#e9ecef;padding:4px 8px;border-radius:4px;font-size:12px;font-family:monospace;display:inline-block;margin:2px}
</style>
</head>
<body>
<div id="authPanel" class="auth-panel" style="display:none">
  <div class="auth-box">
    <h2>用户登录</h2>
    <form onsubmit="event.preventDefault();authenticate()">
      <input type="text" id="authUser" name="username" autocomplete="username" style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0" tabindex="-1" aria-hidden="true">
      <div class="form-group">
        <label for="authPassword">密码</label>
        <input type="password" id="authPassword" name="password" autocomplete="current-password" placeholder="Please enter password" autocapitalize="off" autocorrect="off" spellcheck="false" onkeydown="if(event.key==='Enter'){authenticate()}">
      </div>
      <div id="errorMsg" class="error-msg"></div>
      <button class="btn btn-primary" type="submit" style="width:100%">登录</button>
    </form>
  </div>
</div>

<div class="container" id="mainContainer" style="display:none">
  <div class="header">
    <h1>SNI Proxy Pro</h1>
    <p>规则转发与节点管理</p>
    <button class="logout-btn" onclick="logout()">退出登录</button>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('rules')">规则</div>
    <div class="tab" onclick="switchTab('config')">系统</div>
    <div class="tab" onclick="switchTab('panel')">节点</div>
  </div>

  <div class="content">
    <div id="tab-rules" class="tab-content active">
      <div class="toolbar">
        <button class="btn btn-primary" onclick="showAddModal('sni')">+ 新增 SNI 规则</button>
        <button class="btn btn-primary" onclick="showAddModal('port')">+ 新增端口规则</button>
        <button class="btn btn-secondary" onclick="showImportModal()">导入</button>
        <button class="btn btn-success" onclick="exportRules()">导出</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>名称</th>
            <th>类型</th>
            <th>入口</th>
            <th>目标</th>
            <th>同步</th>
            <th>延迟</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="rulesBody"></tbody>
      </table>
    </div>

    <div id="tab-config" class="tab-content">
      <h3 style="margin-bottom:20px">系统设置</h3>
      <div class="form-group">
        <label for="cfgSNIListen">SNI 监听地址</label>
        <input type="text" id="cfgSNIListen" placeholder=":443">
      </div>
      <div class="form-group">
        <label for="cfgDefaultBackend">默认后端</label>
        <input type="text" id="cfgDefaultBackend" placeholder="example.com:443">
      </div>
      <div class="form-group">
        <label for="cfgWebPanel">Web 管理地址</label>
        <input type="text" id="cfgWebPanel" placeholder="0.0.0.0:8080">
      </div>
      <div class="form-group">
        <label for="cfgWebAuth">Web 密码</label>
        <input type="password" id="cfgWebAuth" name="web_auth_password" autocomplete="new-password" placeholder="Leave empty to keep unchanged">
      </div>
      <div class="form-group">
        <label for="cfgWebTitle">站点名称</label>
        <input type="text" id="cfgWebTitle" placeholder="SNI Proxy Pro">
      </div>
      <div class="form-group">
        <label for="cfgLogLevel">日志级别</label>
        <select id="cfgLogLevel">
          <option value="debug">debug</option>
          <option value="info">info</option>
          <option value="warn">warn</option>
          <option value="error">error</option>
        </select>
      </div>
      <button class="btn btn-primary" onclick="saveConfigSettings()">保存</button>
    </div>

    <div id="tab-panel" class="tab-content">
      <h3 style="margin-bottom:20px">节点面板设置</h3>
      <div class="form-group">
        <label for="panelToken">面板 Token</label>
        <input type="password" id="panelToken" name="token" autocomplete="current-password" placeholder="your-secret-token">
        <small style="color:#6c757d">节点使用同一个 Token 上报状态并接收更新指令。</small>
      </div>
      <button class="btn btn-primary" onclick="savePanelConfig()">保存面板设置</button>

      <div id="nodesSection" style="margin-top:40px">
        <h3 style="margin-bottom:20px">节点
          <button class="btn btn-secondary" onclick="refreshNodes()" style="margin-left:10px">刷新</button>
        </h3>
        <table>
          <thead>
            <tr>
              <th width="16%">名称</th>
              <th width="16%">IP</th>
              <th width="10%">在线状态</th>
              <th width="10%">当前版本</th>
              <th width="10%">目标版本</th>
              <th width="12%">最后心跳</th>
              <th width="16%">操作</th>
            </tr>
          </thead>
          <tbody id="nodesBody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div id="toastWrap" class="toast-wrap"></div>

<div id="nodeModal" class="modal node-modal">
  <div class="modal-content">
    <h3 style="margin-bottom:14px">编辑节点</h3>
    <div class="form-group">
      <label for="nodeEditName">节点名称</label>
      <input type="text" id="nodeEditName" onkeydown="if(event.key==='Escape'){hideNodeModal()} if(event.key==='Enter'){saveNodeSettings()}">
    </div>
    <div class="form-group">
      <label for="nodeEditListen">监听地址</label>
      <input type="text" id="nodeEditListen" placeholder=":8443" onkeydown="if(event.key==='Escape'){hideNodeModal()} if(event.key==='Enter'){saveNodeSettings()}">
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="hideNodeModal()">取消</button>
      <button class="btn btn-primary" onclick="saveNodeSettings()">保存</button>
    </div>
  </div>
</div>

<div id="ruleModal" class="modal">
  <div class="modal-content" id="ruleModalContent">
    <h3 id="modalTitle">新增规则</h3>
    <div class="form-group">
      <label for="inputName">规则名称</label>
      <input type="text" id="inputName">
    </div>
    <div class="form-group">
      <label for="inputType">规则类型</label>
      <select id="inputType" onchange="toggleRuleFields()">
        <option value="sni">SNI 规则</option>
        <option value="port">端口规则</option>
      </select>
    </div>
    <div class="form-group" id="fieldSNI">
      <label for="inputSNI">SNI 主机名</label>
      <input type="text" id="inputSNI">
    </div>
    <div class="form-group" id="fieldPort" style="display:none">
      <label for="inputPort">监听端口</label>
      <input type="number" id="inputPort">
    </div>
    <div class="form-group">
      <label for="inputDest">目标地址（每行一个，IP:PORT）</label>
      <textarea id="inputDest"></textarea>
    </div>
    <div class="form-group">
      <label for="inputLBStrategy">负载策略</label>
      <select id="inputLBStrategy">
        <option value="round_robin">轮询</option>
        <option value="random">随机</option>
        <option value="first_only">仅首个</option>
        <option value="health_check">健康优先</option>
      </select>
    </div>
    <div class="form-group">
      <label><input type="checkbox" id="inputEnabled" checked> 启用规则</label>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="hideModal()">取消</button>
      <button class="btn btn-primary" onclick="saveRule()">保存</button>
    </div>
  </div>
</div>

<div id="importModal" class="modal">
  <div class="modal-content">
    <h3>导入规则（JSONL）</h3>
    <p style="color:#6c757d;margin-bottom:15px">每行一个 JSON，示例：</p>
    <pre style="background:#f8f9fa;padding:10px;border-radius:4px;font-size:12px">{"dest":["IP:PORT"],"listen_port":12345,"name":"NAME"}</pre>
    <div class="form-group">
      <textarea id="importData" rows="10"></textarea>
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" onclick="hideImportModal()">取消</button>
      <button class="btn btn-primary" onclick="doImport()">导入</button>
    </div>
  </div>
</div>
<div id="latencyModal" class="modal">
  <div class="modal-content" id="latencyContent"></div>
</div>
<script>
let authToken = localStorage.getItem('authToken') || '';
let currentEditId = null;
let nodeCache = new Map();
let currentNodeEditId = '';
let actionGuards = new Map();
let rowActionState = new Map();
let nodeActionLocks = new Map();
let nodesRefreshInFlight = false;
let nodesRefreshQueued = false;
let nodesRefreshSeq = 0;
const NODE_SORT_FIELD_KEY = 'panel.nodes.sort.field';
const NODE_SORT_DIR_KEY = 'panel.nodes.sort.dir';

function applyBranding(title){ const t = title || 'SNI Proxy Pro'; document.title = t; const h = document.querySelector('.header h1'); if (h) h.textContent = t; }
function showLoginPanel(){ document.getElementById('authPanel').style.display = 'flex'; document.getElementById('mainContainer').style.display = 'none'; }
function showMainPanel(){ document.getElementById('authPanel').style.display = 'none'; document.getElementById('mainContainer').style.display = 'block'; }
function showToast(msg, type){ const wrap = document.getElementById('toastWrap'); if (!wrap) return; const el = document.createElement('div'); el.className = 'toast toast-' + (type || 'info'); el.textContent = msg; wrap.appendChild(el); setTimeout(() => el.remove(), 2600); }
function esc(v){ return (v || '').toString().replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s])); }
function fmtTime(v){ if (!v) return '--'; const d = new Date(v); return isNaN(d.getTime()) ? '--' : d.toLocaleString('zh-CN'); }
function updateBadgeClass(s){ if (s === 'pending' || s === 'running') return 'badge-warning'; if (s === 'ok') return 'badge-success'; if (s === 'failed') return 'badge-danger'; return 'badge-muted'; }
function updateBadgeText(s){ if (s === 'pending') return 'Queued'; if (s === 'running') return 'Running'; if (s === 'ok') return 'Success'; if (s === 'failed') return 'Failed'; return 'Idle'; }
function updateToneByStatus(s){ if (s === 'ok') return 'success'; if (s === 'pending' || s === 'running') return 'warning'; if (s === 'failed') return 'danger'; return 'muted'; }
function setRowActionState(id, text, tone){ rowActionState.set(id, { text: text || '', tone: tone || 'muted' }); }
function setNodeActionLock(id, locked){ if(locked) nodeActionLocks.set(id,true); else nodeActionLocks.delete(id); updateNodeActionButtons(id); }
function updateNodeActionButtons(id){
  const locked = nodeActionLocks.has(id);
  document.querySelectorAll('[data-node-action="'+id+'"]').forEach(btn=>{ btn.disabled = locked; });
}
function requestRefreshNodes(){ if(nodesRefreshInFlight){ nodesRefreshQueued = true; return; } refreshNodes(); }

function parseVersion(v){ const s = String(v || '').replace(/^v/i, ''); if (!s) return [0,0,0]; const m = s.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/); if (!m) return [0,0,0]; return [parseInt(m[1]||'0',10),parseInt(m[2]||'0',10),parseInt(m[3]||'0',10)]; }
function versionGap(current,target){ const a=parseVersion(current), b=parseVersion(target); const da=a[0]*10000+a[1]*100+a[2]; const db=b[0]*10000+b[1]*100+b[2]; return Math.max(0, db-da); }
function calcAvgLatency(statusData){ if(!statusData||typeof statusData!=='object') return Number.POSITIVE_INFINITY; const vals=Object.values(statusData); if(!vals.length) return Number.POSITIVE_INFINITY; let sum=0,count=0; vals.forEach(v=>{ if(typeof v!=='number') return; sum += (v>=0?v:10000); count++; }); return count?sum/count:Number.POSITIVE_INFINITY; }
function getNodeSortState(){ const rawField = localStorage.getItem(NODE_SORT_FIELD_KEY) || 'last_seen'; const field = ['last_seen','version_gap','latency'].includes(rawField) ? rawField : 'last_seen'; const dir = localStorage.getItem(NODE_SORT_DIR_KEY) || 'desc'; return { field, dir: dir === 'asc' ? 'asc' : 'desc' }; }
function setNodeSortState(field,dir){ localStorage.setItem(NODE_SORT_FIELD_KEY, field); localStorage.setItem(NODE_SORT_DIR_KEY, dir); }

function ensureNodeSortControls(){
  if (document.getElementById('nodeSortField')) return;
  const section = document.getElementById('nodesSection'); if(!section) return;
  const table = section.querySelector('table'); if(!table) return;
  const bar = document.createElement('div');
  bar.className = 'toolbar'; bar.style.marginBottom = '12px';
  bar.innerHTML =
    '<select id="nodeSortField" class="btn btn-secondary" style="padding:8px 10px">' +
      '<option value="last_seen">排序：最后心跳</option>' +
      '<option value="version_gap">排序：版本差</option>' +
      '<option value="latency">排序：平均延迟</option>' +
    '</select>' +
    '<select id="nodeSortDir" class="btn btn-secondary" style="padding:8px 10px">' +
      '<option value="desc">顺序：降序</option>' +
      '<option value="asc">顺序：升序</option>' +
    '</select>';
  section.insertBefore(bar, table);
  const state = getNodeSortState();
  bar.querySelector('#nodeSortField').value = state.field;
  bar.querySelector('#nodeSortDir').value = state.dir;
  bar.querySelector('#nodeSortField').addEventListener('change', ()=>{ setNodeSortState(document.getElementById('nodeSortField').value, document.getElementById('nodeSortDir').value); requestRefreshNodes(); });
  bar.querySelector('#nodeSortDir').addEventListener('change', ()=>{ setNodeSortState(document.getElementById('nodeSortField').value, document.getElementById('nodeSortDir').value); requestRefreshNodes(); });
}

function sortNodesForView(nodes){
  const state = getNodeSortState();
  const dir = state.dir === 'asc' ? 1 : -1;
  const arr = (nodes || []).map(n => ({...n, __lastSeenTs: Date.parse(n.last_seen || '') || 0, __versionGap: versionGap(n.node_version, n.desired_version), __avgLatency: calcAvgLatency(n.status_data)}));
  arr.sort((a,b)=>{
    let va=0, vb=0;
    if (state.field === 'version_gap') { va=a.__versionGap; vb=b.__versionGap; }
    else if (state.field === 'latency') { va=a.__avgLatency; vb=b.__avgLatency; }
    else { va=a.__lastSeenTs; vb=b.__lastSeenTs; }
    if (va<vb) return -1*dir;
    if (va>vb) return 1*dir;
    const na = String(a.name||a.id||''), nb = String(b.name||b.id||'');
    const nc = na.localeCompare(nb);
    if (nc !== 0) return nc;
    return String(a.id||'').localeCompare(String(b.id||''));
  });
  return arr;
}

async function guardedAction(key, tip, fn){ const now=Date.now(); const expires=actionGuards.get(key)||0; if(expires>now){ actionGuards.delete(key); await fn(); return; } actionGuards.set(key, now+5000); showToast(tip,'warning'); }

async function checkAuth(){ try { const r = await fetch('/api/config',{headers:authToken?{'Authorization':'Bearer '+authToken}:{}}); if(r.status===401){ showLoginPanel(); return; } const c=await r.json(); showMainPanel(); applyBranding(c.web_title); loadData(); } catch(e){ showLoginPanel(); } }

async function authenticate(){
  const p=document.getElementById('authPassword').value;
  const errorMsg=document.getElementById('errorMsg');
  errorMsg.textContent='';
  if(!p){ errorMsg.textContent='Please enter password'; return; }
  try {
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
    const data=await r.json();
    if(!r.ok){ errorMsg.textContent=data.error||'登录失败'; return; }
    authToken=data.token;
    localStorage.setItem('authToken',authToken);
    showMainPanel();
    await loadBranding();
    loadData();
  } catch(e){ errorMsg.textContent='登录失败'; }
}

async function logout(){ await guardedAction('logout','再次点击确认退出登录',async()=>{ try { await fetch('/api/logout',{headers:{'Authorization':'Bearer '+authToken}});} catch(e){} localStorage.removeItem('authToken'); authToken=''; showLoginPanel(); showToast('已退出登录','success'); }); }

function switchTab(t){ document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active')); document.querySelectorAll('.tab-content').forEach(e=>e.classList.remove('active')); event.target.classList.add('active'); document.getElementById('tab-'+t).classList.add('active'); if(t==='config') loadConfigSettings(); if(t==='panel') loadPanelConfig(); }
async function loadData(){ await loadRules(); }
async function loadBranding(){ try{ const h={'Authorization':'Bearer '+authToken}; const r=await fetch('/api/config',{headers:h}); if(!r.ok) return; const c=await r.json(); applyBranding(c.web_title);}catch(e){} }

async function loadRules(){
  try{
    const h={'Authorization':'Bearer '+authToken};
    const [rulesResp,nodesResp]=await Promise.all([fetch('/api/rules',{headers:h}),fetch('/api/panel/nodes',{headers:h})]);
    if(rulesResp.status===401){ logout(); return; }
    const rules=await rulesResp.json();
    const nodes=await nodesResp.json();
    const tb=document.getElementById('rulesBody');
    if(!rules.length){ tb.innerHTML='<tr><td colspan="8" style="text-align:center;padding:40px;color:#999">暂无规则</td></tr>'; return; }
    const onlineNodes = nodes.filter(n=>n.status==='online');
    tb.innerHTML = rules.map(rule=>{
      const route = rule.type==='sni' ? '<code>'+esc(rule.sni)+'</code>' : '<strong>:'+rule.listen_port+'</strong>';
      const syncedCount = onlineNodes.filter(n=>n.config_version>=rule.version).length;
      const syncStatus = onlineNodes.length>0 ? (syncedCount>=onlineNodes.length ? '<span class="badge badge-enabled">已同步</span>' : '<span class="badge badge-warning">同步中 '+syncedCount+'/'+onlineNodes.length+'</span>') : '<span class="badge badge-disabled">无节点</span>';
      const avg = (()=>{ const arr=[]; onlineNodes.forEach(n=>{ if(!n.status_data) return; rule.dest.forEach(d=>{ if(n.status_data[d]!==undefined) arr.push(n.status_data[d]);});}); if(!arr.length) return '--'; return Math.round(arr.reduce((a,b)=>a+b,0)/arr.length)+'ms';})();
      return '<tr>'+
        '<td>'+rule.id+'</td>'+
        '<td><strong>'+esc(rule.name)+'</strong></td>'+
        '<td><span class="badge badge-'+rule.type+'">'+rule.type.toUpperCase()+'</span></td>'+
        '<td>'+route+'</td>'+
        '<td>'+rule.dest.length+'</td>'+
        '<td>'+syncStatus+'</td>'+
        '<td><button class="btn btn-secondary" style="padding:4px 8px;font-size:12px" onclick="showLatency('+JSON.stringify(rule).replace(/"/g,'&quot;')+','+JSON.stringify(nodes).replace(/"/g,'&quot;')+')">'+avg+'</button></td>'+
        '<td><button class="btn btn-secondary" onclick="editRule('+rule.id+')">编辑</button> <button class="btn btn-danger" onclick="deleteRule('+rule.id+',\''+esc(rule.name)+'\')">删除</button></td>'+
      '</tr>';
    }).join('');
  } catch(e){}
}

function showLatency(rule,nodes){ let html='<h3 style="margin-bottom:15px">Latency: '+esc(rule.name)+'</h3>'; html+='<table style="font-size:13px"><thead><tr><th>Node</th><th>Target</th><th>Latency</th></tr></thead><tbody>'; nodes.filter(n=>n.status==='online').forEach(n=>{(rule.dest||[]).forEach(d=>{const ms=n.status_data?n.status_data[d]:undefined; const t=(ms===undefined)?'--':(ms===-1?'<span style="color:red">Timeout</span>':'<span style="color:green">'+ms+'ms</span>'); html+='<tr><td>'+esc(n.name)+'</td><td>'+esc(d)+'</td><td>'+t+'</td></tr>';});}); html+='</tbody></table><button class="btn btn-primary" style="width:100%;margin-top:20px" onclick="hideLatencyModal()">Close</button>'; document.getElementById('latencyContent').innerHTML=html; document.getElementById('latencyModal').classList.add('active'); }
function hideLatencyModal(){ document.getElementById('latencyModal').classList.remove('active'); }

async function loadConfigSettings(){ try{ const h={'Authorization':'Bearer '+authToken}; const r=await fetch('/api/config',{headers:h}); if(r.status===401){logout();return;} const c=await r.json(); document.getElementById('cfgSNIListen').value=c.sni_listen||''; document.getElementById('cfgDefaultBackend').value=c.default_backend||''; document.getElementById('cfgWebPanel').value=c.web_panel||''; document.getElementById('cfgWebAuth').value=c.web_auth||''; document.getElementById('cfgLogLevel').value=c.log_level||'info'; const t=c.web_title||'SNI Proxy Pro'; document.getElementById('cfgWebTitle').value=t; applyBranding(t);}catch(e){} }
async function saveConfigSettings(){ const c={sni_listen:document.getElementById('cfgSNIListen').value,default_backend:document.getElementById('cfgDefaultBackend').value,web_panel:document.getElementById('cfgWebPanel').value,web_auth:document.getElementById('cfgWebAuth').value,log_level:document.getElementById('cfgLogLevel').value,web_title:document.getElementById('cfgWebTitle').value}; try{ const h={'Content-Type':'application/json','Authorization':'Bearer '+authToken}; const r=await fetch('/api/config',{method:'POST',headers:h,body:JSON.stringify(c)}); if(r.status===401){logout();return;} if(r.ok) showToast('配置已保存','success'); else showToast('保存失败','error'); } catch(e){ showToast('保存失败','error'); } }

function showAddModal(t){ currentEditId=null; document.getElementById('modalTitle').textContent=t==='sni'?'新增 SNI 规则':'新增端口规则'; document.getElementById('inputName').value=''; document.getElementById('inputType').value=t; document.getElementById('inputSNI').value=''; document.getElementById('inputPort').value=''; document.getElementById('inputDest').value=''; document.getElementById('inputLBStrategy').value='round_robin'; document.getElementById('inputEnabled').checked=true; toggleRuleFields(); document.getElementById('ruleModal').classList.add('active'); }
async function editRule(id){ try{ const h={'Authorization':'Bearer '+authToken}; const r=await fetch('/api/rules',{headers:h}); if(r.status===401){logout();return;} const rules=await r.json(); const rule=rules.find(x=>x.id===id); if(!rule) return; currentEditId=id; document.getElementById('modalTitle').textContent='编辑规则'; document.getElementById('inputName').value=rule.name||''; document.getElementById('inputType').value=rule.type||'sni'; document.getElementById('inputSNI').value=rule.sni||''; document.getElementById('inputPort').value=rule.listen_port||''; document.getElementById('inputDest').value=(rule.dest||[]).join('\n'); document.getElementById('inputLBStrategy').value=rule.lb_strategy||'round_robin'; document.getElementById('inputEnabled').checked=!!rule.enabled; toggleRuleFields(); document.getElementById('ruleModal').classList.add('active'); } catch(e){ showToast('加载规则失败','error'); } }

async function saveRule(){ const name=document.getElementById('inputName').value.trim(); const type=document.getElementById('inputType').value; const sni=document.getElementById('inputSNI').value.trim(); const port=parseInt(document.getElementById('inputPort').value)||0; const destText=document.getElementById('inputDest').value.trim(); const lbStrategy=document.getElementById('inputLBStrategy').value; const enabled=document.getElementById('inputEnabled').checked; if(!name) return showToast('规则名称不能为空','warning'); if(type==='sni'&&!sni) return showToast('SNI 不能为空','warning'); if(type==='port'&&!port) return showToast('监听端口不能为空','warning'); if(!destText) return showToast('目标地址不能为空','warning'); const dest=destText.split('\n').map(s=>s.trim()).filter(Boolean); const body={name,type,sni:type==='sni'?sni:'',listen_port:type==='port'?port:0,dest,lb_strategy:lbStrategy,enabled}; try{ const h={'Content-Type':'application/json','Authorization':'Bearer '+authToken}; const url=currentEditId?'/api/rule?id='+currentEditId:'/api/rule'; const method=currentEditId?'PUT':'POST'; const r=await fetch(url,{method,headers:h,body:JSON.stringify(body)}); if(r.status===401){logout();return;} if(!r.ok) return showToast('保存规则失败','error'); hideModal(); loadRules(); } catch(e){ showToast('保存规则失败','error'); } }

async function deleteRule(id, ruleName){ await guardedAction('rule-delete-'+id,'再次点击确认删除规则 ['+(ruleName||id)+']', async()=>{ try{ const h={'Authorization':'Bearer '+authToken}; const r=await fetch('/api/rule?id='+id,{method:'DELETE',headers:h}); if(r.status===401){logout();return;} if(r.ok){ showToast('规则已删除','success'); loadRules(); } else showToast('删除规则失败','error'); } catch(e){ showToast('删除规则失败','error'); } }); }

function toggleRuleFields(){ const t=document.getElementById('inputType').value; document.getElementById('fieldSNI').style.display=t==='sni'?'block':'none'; document.getElementById('fieldPort').style.display=t==='port'?'block':'none'; }
function showImportModal(){ document.getElementById('importData').value=''; document.getElementById('importModal').classList.add('active'); }
function hideImportModal(){ document.getElementById('importModal').classList.remove('active'); }
async function doImport(){ const data=document.getElementById('importData').value.trim(); if(!data) return showToast('导入内容不能为空','warning'); try{ const h={'Content-Type':'application/json','Authorization':'Bearer '+authToken}; const r=await fetch('/api/rule/import',{method:'POST',headers:h,body:JSON.stringify({data})}); if(r.status===401){logout();return;} if(!r.ok) return showToast('导入失败','error'); const res=await r.json(); showToast('导入完成：'+res.imported+'，跳过：'+res.skipped+'，失败：'+res.failed,'success'); hideImportModal(); loadRules(); } catch(e){ showToast('导入失败','error'); } }
async function exportRules(){ try{ const h={'Authorization':'Bearer '+authToken}; const r=await fetch('/api/rule/export',{headers:h}); if(r.status===401){logout();return;} if(!r.ok) return showToast('导出失败','error'); const text=await r.text(); await navigator.clipboard.writeText(text); showToast('规则已复制到剪贴板','success'); } catch(e){ showToast('导出失败','error'); } }
function hideModal(){ document.getElementById('ruleModal').classList.remove('active'); }

async function loadPanelConfig(){ try{ const h={'Authorization':'Bearer '+authToken}; const r=await fetch('/api/panel/config',{headers:h}); if(r.status===401){logout();return;} const c=await r.json(); document.getElementById('panelToken').value=c.panel_token||''; ensureNodeSortControls(); requestRefreshNodes(); } catch(e){ showToast('加载面板配置失败','error'); } }
async function savePanelConfig(){ const c={panel_token:document.getElementById('panelToken').value}; try{ const h={'Content-Type':'application/json','Authorization':'Bearer '+authToken}; const r=await fetch('/api/panel/config',{method:'POST',headers:h,body:JSON.stringify(c)}); if(r.status===401){logout();return;} if(r.ok) showToast('面板配置已保存','success'); else showToast('保存失败','error'); } catch(e){ showToast('保存失败','error'); } }

async function refreshNodes(){
  if(nodesRefreshInFlight){ nodesRefreshQueued = true; return; }
  nodesRefreshInFlight = true;
  const reqSeq = ++nodesRefreshSeq;
  try{
    ensureNodeSortControls();
    const h={'Authorization':'Bearer '+authToken};
    const r=await fetch('/api/panel/nodes',{headers:h});
    if(r.status===401){logout();return;}
    if(!r.ok) return showToast('鍔犺浇节点澶辫触','error');
    if(reqSeq !== nodesRefreshSeq) return;
    const nodes=sortNodesForView(await r.json());
    const tb=document.getElementById('nodesBody');
    nodeCache.clear();
    (nodes||[]).forEach(n=>nodeCache.set(n.id,n));
    if(!nodes||!nodes.length){ tb.innerHTML='<tr><td colspan="7" style="text-align:center;padding:20px;color:#999">暂无节点接入</td></tr>'; return; }
    tb.innerHTML = nodes.map(n=>{
      const status = n.status==='online' ? '<span class="badge badge-success">在线</span>' : '<span class="badge badge-danger">离线</span>';
      const ver=esc(n.node_version||'--');
      const desired=esc(n.desired_version||'--');
      const lastSeen=fmtTime(n.last_seen);
      const ipDisplay=(n.ipv4?esc(n.ipv4):esc(n.addr||'--'))+(n.ipv6?'<br><small style="color:#6c757d">'+esc(n.ipv6)+'</small>':'');
      const updateText=updateBadgeText(n.last_update_status);
      const updateCls=updateBadgeClass(n.last_update_status);
      const updateMsg=esc(n.last_update_message||'');
      const rowState=rowActionState.get(n.id);
      const rowTone=rowState?rowState.tone:updateToneByStatus(n.last_update_status);
      const rowMsg=rowState?esc(rowState.text):esc(updateMsg||updateText);
      const locked = nodeActionLocks.has(n.id);
      return '<tr>'+
        '<td><strong>'+esc(n.name||n.id)+'</strong></td>'+
        '<td>'+ipDisplay+'</td>'+
        '<td>'+status+'</td>'+
        '<td><code>'+ver+'</code></td>'+
        '<td><code>'+desired+'</code></td>'+
        '<td>'+lastSeen+'</td>'+
        '<td>'+
          '<button class="btn btn-secondary" data-node-action="'+esc(n.id)+'" '+(locked?'disabled':'')+' onclick="openNodeEditor(\''+n.id+'\')">编辑</button> ' +
          '<button class="btn btn-primary" data-node-action="'+esc(n.id)+'" '+(locked?'disabled':'')+' onclick="updateNode(\''+n.id+'\')">更新</button> ' +
          '<button class="btn btn-danger" data-node-action="'+esc(n.id)+'" '+(locked?'disabled':'')+' onclick="deleteNode(\''+n.id+'\')">删除</button>'+
          '<div class="row-status row-status-'+rowTone+'" data-node-row-status="'+esc(n.id)+'">' +
            rowMsg+
          '</div>'+
        '</td>'+
      '</tr>';
    }).join('');
  } catch(e){ showToast('鍔犺浇节点澶辫触','error'); }
  finally{
    nodesRefreshInFlight = false;
    if(nodesRefreshQueued){
      nodesRefreshQueued = false;
      refreshNodes();
    }
  }
}

function openNodeEditor(id){ const n=nodeCache.get(id); if(!n) return showToast('节点不存在','error'); currentNodeEditId=id; document.getElementById('nodeEditName').value=n.name||''; document.getElementById('nodeEditListen').value=n.custom_sni_listen||''; document.getElementById('nodeModal').classList.add('active'); }
function hideNodeModal(){ document.getElementById('nodeModal').classList.remove('active'); currentNodeEditId=''; }

async function saveNodeSettings(){
  if(!currentNodeEditId) return;
  const n=nodeCache.get(currentNodeEditId);
  if(!n) return showToast('节点不存在','error');
  const newName=document.getElementById('nodeEditName').value.trim();
  const listenVal=document.getElementById('nodeEditListen').value.trim();
  if(!newName) return showToast('节点名称涓嶈兘涓虹┖','warning');
  const h={'Content-Type':'application/json','Authorization':'Bearer '+authToken};
  try{
    if(newName!==(n.name||'')){
      const r1=await fetch('/api/panel/node/rename',{method:'POST',headers:h,body:JSON.stringify({node_id:currentNodeEditId,new_name:newName})});
      if(r1.status===401){logout();return;}
      if(!r1.ok) return showToast('重命名失败','error');
    }
    if(listenVal!==(n.custom_sni_listen||'')){
      const r2=await fetch('/api/panel/node/set-listen',{method:'POST',headers:h,body:JSON.stringify({node_id:currentNodeEditId,sni_listen:listenVal})});
      if(r2.status===401){logout();return;}
      if(!r2.ok) return showToast('监听地址更新失败','error');
    }
    showToast('节点设置已保存','success');
    hideNodeModal();
    requestRefreshNodes();
  } catch(e){ showToast('保存澶辫触','error'); }
}

async function updateNode(id){
  if(nodeActionLocks.has(id)) return;
  const n=nodeCache.get(id)||{};
  const name=n.name||id;
  const ip=n.ipv4||n.addr||'--';
  const nowVer=n.node_version||'--';
  const target=n.desired_version||'--';
  await guardedAction('node-update-'+id,'再次点击确认更新 ['+name+' / '+ip+' / '+nowVer+' -> '+target+']',async()=>{
    setNodeActionLock(id,true);
    setRowActionState(id,'正在下发更新命令...','warning');
    try{
      const h={'Content-Type':'application/json','Authorization':'Bearer '+authToken};
      const r=await fetch('/api/panel/node/update',{method:'POST',headers:h,body:JSON.stringify({node_id:id})});
      if(r.status===401){logout();return;}
      if(r.ok){ setRowActionState(id,'更新已排队：'+nowVer+' -> '+target,'success'); showToast('更新命令已下发','success'); }
      else { setRowActionState(id,'下发失败','danger'); showToast('下发失败','error'); }
    } catch(e){ setRowActionState(id,'下发失败','danger'); showToast('下发失败','error'); }
    finally{ setNodeActionLock(id,false); requestRefreshNodes(); }
  });
}

async function deleteNode(id){
  if(nodeActionLocks.has(id)) return;
  const n=nodeCache.get(id)||{};
  const name=n.name||id;
  const ip=n.ipv4||n.addr||'--';
  const ver=n.node_version||'--';
  await guardedAction('node-delete-'+id,'再次点击确认删除 ['+name+' / '+ip+' / v'+ver+']',async()=>{
    setNodeActionLock(id,true);
    setRowActionState(id,'姝ｅ湪删除节点...','warning');
    try{
      const h={'Content-Type':'application/json','Authorization':'Bearer '+authToken};
      const r=await fetch('/api/panel/node/delete',{method:'POST',headers:h,body:JSON.stringify({node_id:id})});
      if(r.status===401){logout();return;}
      if(r.ok){ rowActionState.delete(id); showToast('节点已删除','success'); }
      else { setRowActionState(id,'删除澶辫触','danger'); showToast('删除澶辫触','error'); }
    } catch(e){ setRowActionState(id,'删除澶辫触','danger'); showToast('删除澶辫触','error'); }
    finally{ setNodeActionLock(id,false); requestRefreshNodes(); }
  });
}

checkAuth();
</script>


</body>
</html>`
}
