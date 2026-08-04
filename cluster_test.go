package xpfw

import (
	"testing"
	"time"
)

func TestParseDBTimeRoundTripsInLocalZone(t *testing.T) {
	// Timestamps are stored without a zone. Reading them back as UTC (the old
	// behaviour) put LastSeen in the future east of UTC, making time.Since
	// negative so offline nodes were never marked offline.
	for _, name := range []string{"Asia/Shanghai", "America/New_York", "UTC"} {
		loc, err := time.LoadLocation(name)
		if err != nil {
			t.Skipf("zone %s unavailable: %v", name, err)
		}
		// A heartbeat two hours ago, expressed in the zone the panel runs in.
		const age = 2 * time.Hour
		original := time.Now().In(loc).Add(-age).Truncate(time.Second)

		prev := time.Local
		time.Local = loc
		got := parseDBTime(formatDBTime(original))
		elapsed := time.Since(got)
		time.Local = prev

		if !got.Equal(original) {
			t.Errorf("%s: round trip gave %v, want %v", name, got, original)
		}
		// Reading the string back as UTC skewed this by the zone offset, which
		// east of UTC made it negative and disabled offline detection entirely.
		if elapsed < 0 {
			t.Errorf("%s: time.Since(parsed) = %v, must never be negative", name, elapsed)
		}
		if drift := elapsed - age; drift < -time.Minute || drift > time.Minute {
			t.Errorf("%s: elapsed %v differs from real age %v by %v", name, elapsed, age, drift)
		}
	}

	if !parseDBTime("").IsZero() {
		t.Error(`parseDBTime("") should be the zero time`)
	}
	if formatDBTime(time.Time{}) != "" {
		t.Error("formatDBTime(zero) should be empty so it round trips to zero")
	}
}
