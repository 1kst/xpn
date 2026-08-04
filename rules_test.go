package xpfw

import (
	"path/filepath"
	"testing"
)

// withTestDB points the package's global handle at a throwaway file. db is
// process-wide state, so the previous handle has to come back.
func withTestDB(t *testing.T) {
	t.Helper()

	database, err := initDB(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	prev := db
	db = database
	t.Cleanup(func() {
		db = prev
		database.Close()
	})
}

func ruleIDsInDB(t *testing.T) map[string]int {
	t.Helper()

	rows, err := db.Query(`SELECT id, name FROM rules ORDER BY id`)
	if err != nil {
		t.Fatalf("query rules: %v", err)
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatalf("scan rule: %v", err)
		}
		out[name] = id
	}
	return out
}

// TestApplyRulesKeepsPanelRuleIDs is the whole point of the rule id travelling in
// the config. The counters this node reports are keyed by rule id and the panel
// resolves them against its own rules table, so a locally assigned id makes every
// byte unattributable.
//
// The old code inserted without the id column, and because applyRules deletes and
// reinserts every rule on each config push, AUTOINCREMENT advanced by the whole
// rule count every time. The panel therefore saw ids that matched nothing and
// changed on every push, and labelled all of them as deleted rules.
func TestApplyRulesKeepsPanelRuleIDs(t *testing.T) {
	withTestDB(t)

	rules := []Rule{
		{ID: 1, Name: "CQVN", Type: RuleTypeSNI, SNI: "vn.example.com", Dest: []string{"10.0.0.1:443"}, LBStrategy: LBRoundRobin, Enabled: true},
		{ID: 7, Name: "CQSG", Type: RuleTypeSNI, SNI: "sg.example.com", Dest: []string{"10.0.0.2:443"}, LBStrategy: LBRoundRobin, Enabled: true},
		// A gap in the panel's ids, from a rule deleted there. The node must not
		// close it up.
		{ID: 59, Name: "CQUS", Type: RuleTypeSNI, SNI: "us.example.com", Dest: []string{"10.0.0.3:443"}, LBStrategy: LBRoundRobin, Enabled: true},
	}

	if err := applyRules(rules, 12); err != nil {
		t.Fatalf("applyRules: %v", err)
	}

	got := ruleIDsInDB(t)
	for _, want := range rules {
		if got[want.Name] != want.ID {
			t.Errorf("rule %q stored with id %d, want the panel's %d", want.Name, got[want.Name], want.ID)
		}
	}

	// Pushing the same config again must not renumber anything: this is what made
	// the reported ids climb into the thousands.
	for i := range 5 {
		if err := applyRules(rules, 13+i); err != nil {
			t.Fatalf("applyRules pass %d: %v", i+2, err)
		}
	}

	after := ruleIDsInDB(t)
	for name, id := range got {
		if after[name] != id {
			t.Errorf("rule %q id changed from %d to %d across config pushes", name, id, after[name])
		}
	}
	if len(after) != len(rules) {
		t.Errorf("rules table holds %d rows, want %d", len(after), len(rules))
	}
}

// TestApplyRulesFallsBackWhenPanelSendsNoID keeps an older panel working: without
// an id the rule still has to be installed and served, even though its traffic
// cannot be attributed.
func TestApplyRulesFallsBackWhenPanelSendsNoID(t *testing.T) {
	withTestDB(t)

	rules := []Rule{
		{Name: "NoID", Type: RuleTypeSNI, SNI: "x.example.com", Dest: []string{"10.0.0.9:443"}, LBStrategy: LBRoundRobin, Enabled: true},
	}
	if err := applyRules(rules, 1); err != nil {
		t.Fatalf("applyRules: %v", err)
	}

	got := ruleIDsInDB(t)
	if got["NoID"] <= 0 {
		t.Errorf("rule with no panel id got id %d, want a positive locally assigned one", got["NoID"])
	}
}

// TestApplyRulesPortForwarderGetsPanelID covers the other reporting path: port
// rules pass their id to the forwarder, which is what counterFor books bytes
// against. Reading it from LastInsertId reintroduced the local id.
func TestApplyRulesPortForwarderGetsPanelID(t *testing.T) {
	withTestDB(t)

	// Port 0 keeps the listener from actually binding while still exercising the
	// id that would be handed to it.
	rules := []Rule{
		{ID: 41, Name: "PortRule", Type: RuleTypePort, ListenPort: 0, Dest: []string{"10.0.0.4:80"}, LBStrategy: LBRoundRobin, Enabled: true},
	}
	if err := applyRules(rules, 3); err != nil {
		t.Fatalf("applyRules: %v", err)
	}

	if got := ruleIDsInDB(t)["PortRule"]; got != 41 {
		t.Errorf("port rule stored with id %d, want 41", got)
	}
}
