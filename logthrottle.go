package xpfw

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// Per-connection logging on a busy node writes the same sentence hundreds of
// thousands of times a day. On this fleet the worst case is a node whose
// default_backend has nothing listening: every SNI miss dials it, fails, and logs
// one line — about 167,000 lines in a day on the busiest node, all of them
// identical apart from the client address.
//
// The information content of the 167,000th copy is zero, but the cost is not:
// journald's capacity is shared with every other service on the box, so one
// process producing at that rate evicts other services' history from the ring.
//
// So repeated events are collapsed to one line per key per interval, carrying the
// number suppressed since the last line was emitted. Reducing at the source is
// cheaper and more honest than rotating afterwards: the count is preserved, only
// the repetition is dropped.

const (
	// logThrottleInterval is how often a given key is allowed through. A minute is
	// short enough that an operator watching a failure live sees it move, and long
	// enough to turn a per-connection flood into something readable.
	logThrottleInterval = time.Minute
	// logThrottleMaxKeys bounds the state. Keys are derived from configuration
	// (backends, destinations) rather than from anything a client controls, so this
	// should never be approached; the cap exists because a bounded structure on a
	// long-running proxy is not optional, and because a future caller might be
	// tempted to key by something an attacker chooses.
	logThrottleMaxKeys = 128
)

type logThrottleState struct {
	last       time.Time
	suppressed uint64
}

var (
	logThrottleMu   sync.Mutex
	logThrottleKeys = make(map[string]*logThrottleState)

	// Counters for how much logging this process has actually done, reported to
	// the panel so an operator can see which node is noisy without shelling into
	// it. Monotonic since start and paired with the boot id, like every other
	// counter in the heartbeat.
	logLinesEmitted    atomic.Uint64
	logLinesSuppressed atomic.Uint64
)

// throttledLog emits at most one line per key per interval. The returned entry is
// nil when the event was suppressed, so the caller does the formatting work only
// when the line is actually going to be written.
//
// The count of the window that is still open is carried into the next emitted
// line rather than flushed on a timer: a tail of at most one interval is lost when
// the events stop, which is the moment the situation has ended anyway and the
// least interesting count there is.
func throttledLog(key string) (suppressed uint64, ok bool) {
	now := time.Now()

	logThrottleMu.Lock()
	st := logThrottleKeys[key]
	if st == nil {
		if len(logThrottleKeys) >= logThrottleMaxKeys {
			// Full. Log rather than silently drop: an unbounded key space is a bug
			// to be found, and losing the message would hide it.
			logThrottleMu.Unlock()
			logLinesEmitted.Add(1)
			return 0, true
		}
		st = &logThrottleState{last: now}
		logThrottleKeys[key] = st
		logThrottleMu.Unlock()
		logLinesEmitted.Add(1)
		return 0, true
	}

	if now.Sub(st.last) < logThrottleInterval {
		st.suppressed++
		logThrottleMu.Unlock()
		logLinesSuppressed.Add(1)
		return 0, false
	}

	suppressed = st.suppressed
	st.suppressed = 0
	st.last = now
	logThrottleMu.Unlock()
	logLinesEmitted.Add(1)
	return suppressed, true
}

// throttledFields adds the suppressed count to a log entry, and only when there is
// one: "repeated=0" on every line would be noise, and its absence already means
// this is the first occurrence in the window.
func throttledFields(fields logrus.Fields, suppressed uint64) logrus.Fields {
	if suppressed > 0 {
		fields["repeated"] = suppressed
	}
	return fields
}

// logCounters is what the heartbeat reports.
func logCounters() (emitted, suppressed uint64) {
	return logLinesEmitted.Load(), logLinesSuppressed.Load()
}

// resetLogThrottle clears the state. Only used by tests; the process never needs
// to forget, because the keys are bounded.
func resetLogThrottle() {
	logThrottleMu.Lock()
	logThrottleKeys = make(map[string]*logThrottleState)
	logThrottleMu.Unlock()
	logLinesEmitted.Store(0)
	logLinesSuppressed.Store(0)
}
