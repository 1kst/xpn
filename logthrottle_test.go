package xpfw

import (
	"fmt"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestThrottledLogCollapsesRepeats is the whole point: the same event arriving
// hundreds of thousands of times must produce one line, and the count of the rest
// must survive so the operator still knows the scale.
func TestThrottledLogCollapsesRepeats(t *testing.T) {
	resetLogThrottle()

	// First occurrence always goes through, with nothing suppressed yet.
	if n, ok := throttledLog("k"); !ok || n != 0 {
		t.Fatalf("first call = (%d, %v), want (0, true)", n, ok)
	}
	// Everything inside the window is held.
	for i := 0; i < 5000; i++ {
		if _, ok := throttledLog("k"); ok {
			t.Fatalf("call %d was emitted; only one line per interval may be", i+2)
		}
	}

	emitted, suppressed := logCounters()
	if emitted != 1 {
		t.Errorf("emitted = %d, want 1", emitted)
	}
	if suppressed != 5000 {
		t.Errorf("suppressed = %d, want 5000: the count is the only thing that carries the scale", suppressed)
	}
}

// TestThrottledLogCarriesTheCountForward checks the count is not silently dropped
// when the window rolls over: the next emitted line has to report what happened
// while nothing was being written.
func TestThrottledLogCarriesTheCountForward(t *testing.T) {
	resetLogThrottle()

	throttledLog("k")
	for i := 0; i < 42; i++ {
		throttledLog("k")
	}

	// Force the window open rather than sleeping for a minute.
	logThrottleMu.Lock()
	logThrottleKeys["k"].last = logThrottleKeys["k"].last.Add(-2 * logThrottleInterval)
	logThrottleMu.Unlock()

	n, ok := throttledLog("k")
	if !ok {
		t.Fatal("the call after the interval elapsed was suppressed")
	}
	if n != 42 {
		t.Errorf("reported %d suppressed, want 42", n)
	}
	// And the counter resets, so the next line does not double count.
	logThrottleMu.Lock()
	logThrottleKeys["k"].last = logThrottleKeys["k"].last.Add(-2 * logThrottleInterval)
	logThrottleMu.Unlock()
	if n, ok := throttledLog("k"); !ok || n != 0 {
		t.Errorf("second window = (%d, %v), want (0, true)", n, ok)
	}
}

// TestThrottledLogKeysAreIndependent covers the reason dial failures are keyed by
// backend: one broken destination flooding must not hide a second one breaking.
func TestThrottledLogKeysAreIndependent(t *testing.T) {
	resetLogThrottle()

	if _, ok := throttledLog("dial:10.0.0.1:443"); !ok {
		t.Fatal("first backend was suppressed")
	}
	for i := 0; i < 100; i++ {
		throttledLog("dial:10.0.0.1:443")
	}
	// A different backend failing for the first time has to be reported at once.
	if _, ok := throttledLog("dial:10.0.0.2:443"); !ok {
		t.Error("a second backend's first failure was suppressed by the first backend's flood")
	}
}

// TestThrottledLogIsBounded is the safety property. The keys in use come from
// configuration, but a future caller keying on something a client chooses would
// otherwise turn this into unbounded growth on a long-running proxy.
func TestThrottledLogIsBounded(t *testing.T) {
	resetLogThrottle()

	for i := 0; i < logThrottleMaxKeys*4; i++ {
		throttledLog(fmt.Sprintf("key-%d", i))
	}

	logThrottleMu.Lock()
	size := len(logThrottleKeys)
	logThrottleMu.Unlock()

	if size > logThrottleMaxKeys {
		t.Errorf("map grew to %d entries, cap is %d", size, logThrottleMaxKeys)
	}
	// Overflow must still log rather than swallow: an unbounded key space is a bug
	// to find, and dropping the message would hide it.
	emitted, _ := logCounters()
	if emitted < uint64(logThrottleMaxKeys) {
		t.Errorf("emitted = %d, want at least the %d distinct keys", emitted, logThrottleMaxKeys)
	}
}

// TestThrottledFieldsOmitsZero keeps the common line clean: "repeated=0" on every
// first occurrence would be noise, and its absence already carries that meaning.
func TestThrottledFieldsOmitsZero(t *testing.T) {
	if f := throttledFields(logrus.Fields{"a": 1}, 0); f["repeated"] != nil {
		t.Errorf("zero suppressed added repeated=%v", f["repeated"])
	}
	if f := throttledFields(logrus.Fields{"a": 1}, 7); f["repeated"] != uint64(7) {
		t.Errorf("repeated = %v, want 7", f["repeated"])
	}
}

// TestThrottledLogIsConcurrencySafe matters because every call site is on the
// per-connection path: this runs from as many goroutines as there are connections.
func TestThrottledLogIsConcurrencySafe(t *testing.T) {
	resetLogThrottle()

	const workers, each = 32, 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// A handful of keys, as in production, rather than one per call.
				throttledLog(fmt.Sprintf("dial:10.0.0.%d:443", w%4))
			}
		}(w)
	}
	wg.Wait()

	emitted, suppressed := logCounters()
	if emitted+suppressed != uint64(workers*each) {
		t.Errorf("emitted %d + suppressed %d = %d, want %d: every event must be accounted for",
			emitted, suppressed, emitted+suppressed, workers*each)
	}
	// Four keys, each allowed one line in the window.
	if emitted != 4 {
		t.Errorf("emitted = %d, want 4 (one per key)", emitted)
	}
}
