package xpfw

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

// ListenError is a port rule this node cannot currently serve because the port
// will not bind. Reported on every heartbeat until the bind succeeds, so the
// panel can show it instead of the rule silently doing nothing.
type ListenError struct {
	Port   int    `json:"port"`
	RuleID int    `json:"rule_id"`
	Error  string `json:"error"`
	Since  string `json:"since"`
}

type listenFailure struct {
	ruleID int
	err    string
	since  time.Time
}

var (
	listenFailMu sync.Mutex
	listenFails  = make(map[int]listenFailure)
)

func recordListenFailure(port, ruleID int, err error) {
	listenFailMu.Lock()
	defer listenFailMu.Unlock()
	prev, ok := listenFails[port]
	since := time.Now()
	if ok && prev.ruleID == ruleID {
		since = prev.since
	}
	listenFails[port] = listenFailure{ruleID: ruleID, err: err.Error(), since: since}
}

func clearListenFailure(port int) {
	listenFailMu.Lock()
	delete(listenFails, port)
	listenFailMu.Unlock()
}

// listenErrors reports the failures for ports the configuration still wants. A
// port dropped from the configuration while failing is no longer an error.
func listenErrors() []ListenError {
	portListenersMu.Lock()
	wanted := make(map[int]bool, len(desiredPorts))
	for port := range desiredPorts {
		wanted[port] = true
	}
	portListenersMu.Unlock()

	listenFailMu.Lock()
	defer listenFailMu.Unlock()
	var out []ListenError
	for port, f := range listenFails {
		if !wanted[port] {
			delete(listenFails, port)
			continue
		}
		out = append(out, ListenError{Port: port, RuleID: f.ruleID, Error: f.err, Since: f.since.Format(time.RFC3339)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// ConfigReject is a config this node refused to apply, reported until a config
// is applied successfully.
//
//	empty  the config had no rules while this node has some, and the panel did
//	       not say the rules were deleted on purpose. A panel reinstalled or
//	       restored with an empty database would otherwise wipe every node.
//	older  the config's version is lower than the one this node already runs.
//	       A panel restored from an old backup would otherwise roll every node
//	       back to it the moment the node restarted and pulled.
type ConfigReject struct {
	Reason       string `json:"reason"`
	PanelVersion int    `json:"panel_version"`
	LocalVersion int    `json:"local_version"`
	At           string `json:"at"`
}

var (
	configRejectMu sync.Mutex
	configReject   *ConfigReject
)

func setConfigReject(reason string, panelVersion, localVersion int) {
	configRejectMu.Lock()
	defer configRejectMu.Unlock()
	configReject = &ConfigReject{
		Reason:       reason,
		PanelVersion: panelVersion,
		LocalVersion: localVersion,
		At:           time.Now().Format(time.RFC3339),
	}
}

func clearConfigReject() {
	configRejectMu.Lock()
	configReject = nil
	configRejectMu.Unlock()
}

func currentConfigReject() *ConfigReject {
	configRejectMu.Lock()
	defer configRejectMu.Unlock()
	if configReject == nil {
		return nil
	}
	c := *configReject
	return &c
}

// decodeDestList reads a JSON address list as stored in the rules table. An
// empty column, which is what rows written before the column existed hold,
// decodes to nil.
func decodeDestList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
