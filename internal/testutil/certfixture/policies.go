package certfixture

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
)

var (
	OIDSubjectCPF    = asn1.ObjectIdentifier{2, 16, 76, 1, 3, 1}
	OIDSubjectCNPJ   = asn1.ObjectIdentifier{2, 16, 76, 1, 3, 3}
	OIDICPBrasilTest = asn1.ObjectIdentifier{2, 16, 76, 1, 2, 1}

	oidExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
)

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
}

func CertificatePoliciesExtension(t testing.TB, policies ...asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()

	extension, err := certificatePoliciesExtension(policies...)
	if err != nil {
		t.Fatalf("failed to marshal certificate policies extension: %v", err)
	}

	return extension
}

func certificatePoliciesExtension(policies ...asn1.ObjectIdentifier) (pkix.Extension, error) {
	policyInfos := make([]policyInformation, 0, len(policies))
	for _, policy := range policies {
		policyInfos = append(policyInfos, policyInformation{PolicyIdentifier: policy})
	}

	der, err := asn1.Marshal(policyInfos)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal certificate policies: %w", err)
	}

	return pkix.Extension{
		Id:    oidExtensionCertificatePolicies,
		Value: der,
	}, nil
}
