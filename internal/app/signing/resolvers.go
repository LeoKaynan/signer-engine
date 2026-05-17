package signing

import "fmt"

// cadesModeIsDetached resolves a CAdES Mode into the detached boolean used by
// cades.Signer. Returns an error for unrecognized modes.
func cadesModeIsDetached(mode Mode) (bool, error) {
	switch mode {
	case ModeAttached:
		return false, nil
	case ModeDetached:
		return true, nil
	}
	return false, fmt.Errorf("unsupported cades mode: %s", mode)
}
