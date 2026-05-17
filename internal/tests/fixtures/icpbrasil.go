package fixtures

import (
	"testing"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/icpbrasil"
	"signer-engine/internal/signature/signaturepolicy"
)

func NewICPBrasilPolicy(t testing.TB, name signaturepolicy.PolicyName, rootsPEM []byte) cades.Policy {
	t.Helper()

	policy, err := icpbrasil.NewCAdESPolicyWithRootsPEM(name, rootsPEM)
	if err != nil {
		t.Fatalf("failed to create ICP-Brasil policy: %v", err)
	}
	return policy
}
