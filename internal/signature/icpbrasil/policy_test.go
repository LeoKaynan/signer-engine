package icpbrasil

import (
	"encoding/asn1"
	"testing"

	"signer-engine/internal/signature/cades"
	"signer-engine/internal/signature/cms"
	"signer-engine/internal/testutil/certfixture"
)

func TestPolicyADRB_SignedAttributes(t *testing.T) {
	credential := certfixture.NewCredential(t)
	policy, err := NewPolicy(PolicyNamePAADRBv24)
	if err != nil {
		t.Fatalf("NewPolicy failed: %v", err)
	}

	attrs, err := policy.SignedAttributes(cades.SigningContext{
		Certificate: credential.Certificate(),
	})
	if err != nil {
		t.Fatalf("SignedAttributes failed: %v", err)
	}

	if !hasAttribute(attrs, cades.OIDSigningCertificateV2) {
		t.Error("signing-certificate-v2 attribute not present")
	}
	if !hasAttribute(attrs, cades.OIDSignaturePolicyID) {
		t.Error("signature-policy-identifier attribute not present")
	}
	if hasAttribute(attrs, cms.OIDSigningTime) {
		t.Error("signing-time attribute should not be added by AD-RB policy")
	}
}

func TestPolicyADRT_UnsignedAttributeNames(t *testing.T) {
	policy, err := NewPolicy(PolicyNamePAADRTv24)
	if err != nil {
		t.Fatalf("NewPolicy failed: %v", err)
	}
	attrs := policy.UnsignedAttributeNames()
	if len(attrs) != 1 || attrs[0] != cades.SignatureTimeStampTokenAttr {
		t.Fatalf("unexpected unsigned attrs: %v", attrs)
	}
}

func hasAttribute(attrs []cms.Attribute, oid asn1.ObjectIdentifier) bool {
	for _, attr := range attrs {
		if attr.AttrType.Equal(oid) {
			return true
		}
	}
	return false
}
