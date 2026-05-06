include .env
export

BINARY := signer-engine
CMD := ./cmd/signer-engine
TMP_DIR := tmp

INPUT ?= $(TMP_DIR)/input.txt
OUTPUT ?= $(TMP_DIR)/signature.p7s
P12 ?= $(TMP_DIR)/cert.pfx
PASSWORD ?= 199516
FORMAT ?= cades
POLICY ?= PA_AD_RV_v2_4
MODE ?= attached

.PHONY: sign
sign: tmp
	go run $(CMD) sign \
		-in "$(INPUT)" \
		-out "$(OUTPUT)" \
		-p12 "$(P12)" \
		-password "$(PASSWORD)" \
		-format "$(FORMAT)" \
		-policy "$(POLICY)" \
		-mode "$(MODE)" \
		-credential-provider pkcs12

