include .env
export

BINARY := signer-engine
CMD := ./cmd/signer-engine
TMP_DIR := tmp

INPUT ?= $(TMP_DIR)/input.txt
OUTPUT ?= $(TMP_DIR)/signature.p7s
COSIGN_OUTPUT ?= $(TMP_DIR)/cosignature.p7s
P12 ?= $(TMP_DIR)/cert2.pfx
PASSWORD ?= !Toht167
COSIGN_P12 ?= $(TMP_DIR)/cert.pfx
COSIGN_PASSWORD ?= 199516
FORMAT ?= cades
POLICY ?= PA_AD_RA_v2_5
MODE ?= attached

.PHONY: sign
sign:
	go run $(CMD) sign \
		-in "$(INPUT)" \
		-out "$(OUTPUT)" \
		-p12 "$(P12)" \
		-password "$(PASSWORD)" \
		-format "$(FORMAT)" \
		-policy "$(POLICY)" \
		-mode "$(MODE)" \
		-operation sign \
		-credential-provider pkcs12

.PHONY: cosign-attached
cosign-attached:
	go run $(CMD) sign \
		-existing-signature "$(OUTPUT)" \
		-out "$(COSIGN_OUTPUT)" \
		-p12 "$(COSIGN_P12)" \
		-password "$(COSIGN_PASSWORD)" \
		-format "$(FORMAT)" \
		-policy "$(POLICY)" \
		-mode attached \
		-operation co-sign \
		-credential-provider pkcs12

.PHONY: cosign-detached
cosign-detached:
	go run $(CMD) sign \
		-in "$(INPUT)" \
		-existing-signature "$(OUTPUT)" \
		-out "$(COSIGN_OUTPUT)" \
		-p12 "$(COSIGN_P12)" \
		-password "$(COSIGN_PASSWORD)" \
		-format "$(FORMAT)" \
		-policy "$(POLICY)" \
		-mode detached \
		-operation co-sign \
		-credential-provider pkcs12

