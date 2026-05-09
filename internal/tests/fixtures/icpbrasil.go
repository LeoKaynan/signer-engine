package fixtures

import (
	"testing"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/icpbrasil"
)

func NewICPBrasilPolicy(t testing.TB, name cades.PolicyName, rootsPEM []byte) cades.Policy {
	t.Helper()

	policy, err := icpbrasil.NewPolicyWithRootsPEM(name, rootsPEM)
	if err != nil {
		t.Fatalf("failed to create ICP-Brasil policy: %v", err)
	}
	return policy
}
