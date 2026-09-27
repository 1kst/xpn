package xpfw

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Failover for pinned landings. A rule that carries a fallback has had this
// entry node pinned to a landing of its own; the monitor here decides whether
// that landing is usable, and pick sends new connections to the fallback while
// it is not.
//
// Everything runs on the node. The panel only learns about it from heartbeats,
// so failover keeps working while the panel is unreachable.
const (
	failoverProbeInterval = 5 * time.Second
	failoverDialTimeout   = 3 * time.Second
	// failoverThreshold consecutive failures mark a landing down, and the same
	// number of consecutive successes mark it up again. With the probe interval
	// that is roughly 15 seconds either way; failed user connections count too,
	// so a landing that dies under load is caught sooner.
	failoverThreshold = 3
	// failoverEventCap bounds the events kept for a panel that is not acking
	// them, e.g. while it is offline. The oldest are dropped first.
	failoverEventCap = 100
)

type pinnedTarget struct {
	down    bool
	fails   int
	oks     int
	since   time.Time
	lastErr string
	rules   []int
}

// FailoverState is a pinned landing that is currently down.
type FailoverState struct {
	Target  string `json:"target"`
	RuleIDs []int  `json:"rule_ids"`
	Since   string `json:"since"`
	Error   string `json:"error,omitempty"`
}

// FailoverEvent is one transition, kept until the panel acknowledges it so a
// transition that happened while the panel was offline is still reported.
type FailoverEvent struct {
	Seq     uint64 `json:"seq"`
	Target  string `json:"target"`
	RuleIDs []int  `json:"rule_ids"`
	Down    bool   `json:"down"`
	At      string `json:"at"`
	Error   string `json:"error,omitempty"`
}

// FailoverReport rides on the heartbeat.
type FailoverReport struct {
	Down   []FailoverState `json:"down,omitempty"`
	Events []FailoverEvent `json:"events,omitempty"`
}

var (
	failoverMu     sync.Mutex
	pinnedTargets  = make(map[string]*pinnedTarget)
	failoverEvents []FailoverEvent
	failoverSeq    uint64
	// probing holds the landings with a probe in flight, so a burst of failed
	// user dials asks for one probe rather than one each.
	probing = make(map[string]bool)
)

// setPinnedTargets makes the monitor watch exactly the pinned landings of rules.
// A landing that stays pinned keeps its state, so a push that changes some other
// rule does not reset a landing that is down back to up.
func setPinnedTargets(rules []Rule) {
	next := make(map[string][]int)
	for _, r := range rules {
		if !r.Enabled || len(r.Fallback) == 0 {
			continue
		}
		for _, d := range r.Dest {
			if isLoopback(d) {
				continue
			}
			next[d] = append(next[d], r.ID)
		}
	}

	now := time.Now()
	failoverMu.Lock()
	defer failoverMu.Unlock()
	updated := make(map[string]*pinnedTarget, len(next))
	for addr, ids := range next {
		t := pinnedTargets[addr]
		if t == nil {
			t = &pinnedTarget{since: now}
		}
		sort.Ints(ids)
		t.rules = ids
		updated[addr] = t
	}
	pinnedTargets = updated
}

func failoverIsDown(addr string) bool {
	failoverMu.Lock()
	defer failoverMu.Unlock()
	t := pinnedTargets[addr]
	return t != nil && t.down
}

// failoverSuspect is how a failed user connection is reported: it probes the
// landing now instead of waiting for the next round. Only probes decide that a
// landing is down, because that decision closes every connection on it.
func failoverSuspect(addr string) {
	failoverMu.Lock()
	_, watched := pinnedTargets[addr]
	if !watched || probing[addr] {
		failoverMu.Unlock()
		return
	}
	probing[addr] = true
	failoverMu.Unlock()
	go probePinnedTarget(addr)
}

func probePinnedTarget(addr string) {
	conn, err := dialBackendWithDNSCache("tcp", addr, failoverDialTimeout)
	if conn != nil {
		conn.Close()
	}
	failoverMu.Lock()
	delete(probing, addr)
	failoverMu.Unlock()
	failoverObserve(addr, err)
}

// failoverObserve feeds one attempt to reach a pinned landing: a probe's result,
// or a user connection that got through. err nil is a success.
func failoverObserve(addr string, err error) {
	failoverMu.Lock()
	t := pinnedTargets[addr]
	if t == nil {
		failoverMu.Unlock()
		return
	}
	var transition *FailoverEvent
	now := time.Now()
	if err == nil {
		t.fails = 0
		if t.down {
			t.oks++
			if t.oks >= failoverThreshold {
				t.down, t.oks, t.since = false, 0, now
				transition = appendFailoverEventLocked(addr, t, false, now)
			}
		}
	} else {
		t.oks = 0
		t.lastErr = err.Error()
		if !t.down {
			t.fails++
			if t.fails >= failoverThreshold {
				t.down, t.fails, t.since = true, 0, now
				transition = appendFailoverEventLocked(addr, t, true, now)
			}
		}
	}
	failoverMu.Unlock()

	if transition == nil {
		return
	}
	if transition.Down {
		// Switch at once: the connections still on the landing are closed so
		// their clients reconnect to the fallback now, rather than after the idle
		// timeout on a landing that no longer answers.
		closed := closePinnedConnsTo(addr)
		log.Warnf("[Failover] pinned landing %s is down (rules %v): new connections use the fallback, %d connection(s) closed: %s",
			addr, transition.RuleIDs, closed, transition.Error)
	} else {
		// Connections already on the fallback are left where they are: they work,
		// and closing them would make a landing that flaps cost users a
		// disconnect every time it comes back.
		log.Infof("[Failover] pinned landing %s is back (rules %v): new connections use it again", addr, transition.RuleIDs)
	}
}

func appendFailoverEventLocked(addr string, t *pinnedTarget, down bool, at time.Time) *FailoverEvent {
	// Time based so a restarted node never reuses a number the panel has already
	// acknowledged, and forced forward so it stays strictly increasing.
	seq := uint64(at.UnixNano())
	if seq <= failoverSeq {
		seq = failoverSeq + 1
	}
	failoverSeq = seq
	ev := FailoverEvent{
		Seq:     seq,
		Target:  addr,
		RuleIDs: append([]int(nil), t.rules...),
		Down:    down,
		At:      at.Format(time.RFC3339),
	}
	if down {
		ev.Error = t.lastErr
	}
	failoverEvents = append(failoverEvents, ev)
	if len(failoverEvents) > failoverEventCap {
		failoverEvents = append([]FailoverEvent(nil), failoverEvents[len(failoverEvents)-failoverEventCap:]...)
	}
	return &ev
}

// failoverReport is what the next heartbeat carries, nil when there is nothing
// to say.
func failoverReport() *FailoverReport {
	failoverMu.Lock()
	defer failoverMu.Unlock()
	rep := &FailoverReport{}
	for addr, t := range pinnedTargets {
		if !t.down {
			continue
		}
		rep.Down = append(rep.Down, FailoverState{
			Target:  addr,
			RuleIDs: append([]int(nil), t.rules...),
			Since:   t.since.Format(time.RFC3339),
			Error:   t.lastErr,
		})
	}
	sort.Slice(rep.Down, func(i, j int) bool { return rep.Down[i].Target < rep.Down[j].Target })
	rep.Events = append(rep.Events, failoverEvents...)
	if len(rep.Down) == 0 && len(rep.Events) == 0 {
		return nil
	}
	return rep
}

// ackFailoverEvents drops the events the panel has confirmed. An ack of zero is
// what a panel too old to know about failover sends, and acknowledges nothing.
func ackFailoverEvents(upTo uint64) {
	if upTo == 0 {
		return
	}
	failoverMu.Lock()
	defer failoverMu.Unlock()
	kept := failoverEvents[:0]
	for _, ev := range failoverEvents {
		if ev.Seq > upTo {
			kept = append(kept, ev)
		}
	}
	failoverEvents = kept
}

func failoverLoop(ctx context.Context) {
	ticker := time.NewTicker(failoverProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probePinnedTargets()
		}
	}
}

// probePinnedTargets checks every pinned landing once, in parallel, and waits
// for all of them so rounds never overlap: a probe is bounded by
// failoverDialTimeout, which is shorter than the interval.
func probePinnedTargets() {
	failoverMu.Lock()
	addrs := make([]string, 0, len(pinnedTargets))
	for addr := range pinnedTargets {
		// One already in flight, prompted by a failed user dial, counts for this
		// round; a second would count the same outage twice.
		if probing[addr] {
			continue
		}
		probing[addr] = true
		addrs = append(addrs, addr)
	}
	failoverMu.Unlock()

	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			probePinnedTarget(addr)
		}(addr)
	}
	wg.Wait()
}
