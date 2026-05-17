package signaturepolicy

import "time"

// Clock is an injectable time source. The zero value returns time.Now().UTC().
type Clock func() time.Time

// Now returns the current time according to the clock, falling back to
// time.Now().UTC() when the clock is nil.
func (c Clock) Now() time.Time {
	if c != nil {
		return c()
	}
	return time.Now().UTC()
}
