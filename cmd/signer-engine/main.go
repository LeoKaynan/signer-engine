package main

import (
	"flag"
	"fmt"
	"os"
	"signer-engine/internal/app/signing"
	"signer-engine/internal/signature/signaturepolicy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing command: expected sign")
	}
	switch args[0] {
	case "sign":
		return runSign(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)

	inPath := fs.String("in", "", "input file to sign (PDF for PAdES — signed or not; document or attached CMS for CAdES)")
	outPath := fs.String("out", "", "output signature file")
	existingSignaturePath := fs.String("existing-signature", "", "existing CMS to co-sign (CAdES detached only)")
	p12Path := fs.String("p12", "", "PKCS#12/PFX credential file")
	password := fs.String("password", "", "PKCS#12/PFX password")
	format := fs.String("format", "cades", "signature format: cades or pades")
	policy := fs.String("policy", "icpbrasil-adrb", "signature policy")
	mode := fs.String("mode", "detached", "signature mode: attached or detached (CAdES only)")
	credentialProvider := fs.String("credential-provider", "pkcs12", "credential provider: pkcs12")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outPath == "" {
		return fmt.Errorf("-out is required")
	}
	if *p12Path == "" {
		return fmt.Errorf("-p12 is required")
	}
	if *inPath == "" {
		return fmt.Errorf("-in is required")
	}

	isAttached := signing.Mode(*mode) == signing.ModeAttached
	isPAdES := signing.Format(*format) == signing.FormatPades
	hasExisting := *existingSignaturePath != ""

	if hasExisting && isPAdES {
		return fmt.Errorf("-existing-signature is not used for PAdES; signing an already-signed PDF (via -in) is detected automatically")
	}
	if hasExisting && isAttached {
		return fmt.Errorf("-existing-signature is not used for attached CAdES co-sign; pass the existing CMS via -in")
	}

	p12Data, err := os.ReadFile(*p12Path)
	if err != nil {
		return fmt.Errorf("read credential file: %w", err)
	}

	requestData, err := os.ReadFile(*inPath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}

	var existingSig []byte
	if hasExisting {
		existingSig, err = os.ReadFile(*existingSignaturePath)
		if err != nil {
			return fmt.Errorf("read existing signature file: %w", err)
		}
	}

	response, err := signing.NewFromEnv().Sign(signing.Request{
		Data:               requestData,
		ExistingSignature:  existingSig,
		CredentialProvider: signing.CredentialProvider(*credentialProvider),
		PKCS12Data:         p12Data,
		PKCS12Pass:         *password,
		Format:             signing.Format(*format),
		Policy:             signaturepolicy.PolicyName(*policy),
		Mode:               signing.Mode(*mode),
	})
	if err != nil {
		return err
	}

	if err := os.WriteFile(*outPath, response.Signature, 0o644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	return nil
}
