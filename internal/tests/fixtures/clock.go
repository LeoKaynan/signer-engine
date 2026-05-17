package fixtures

import "time"

// DefaultSigningTime is the fixed signing time used by e2e tests across
// CAdES and PAdES suites so tests are deterministic.
var DefaultSigningTime = time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)

// DefaultClock returns a Clock function that always reports DefaultSigningTime.
func DefaultClock() func() time.Time {
	return func() time.Time { return DefaultSigningTime }
}
