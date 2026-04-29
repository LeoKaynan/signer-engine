package icpbrasil

import (
	"encoding/hex"
	"fmt"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex constant: %v", err))
	}
	return b
}
