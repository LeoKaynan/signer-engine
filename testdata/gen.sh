#!/usr/bin/env bash
#
# Generates PKCS#12 fixtures for signer-engine tests.
#
# Usage:
#   ./testdata/gen.sh
#
# The resulting .p12 files are committed. Regenerate only when adding
# new fixtures or when an existing one needs to change.
#
# Password for every fixture: "test" (never use this in production).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASSWORD="test"

echo "generating fixtures in $SCRIPT_DIR"
echo "password: $PASSWORD"
echo

# -----------------------------------------------------------------------------
# valid_rsa2048.p12
# -----------------------------------------------------------------------------
# Self-signed RSA 2048 certificate, 100-year validity.
# Use case: happy path for Open/GetSigner/Sign.
gen_valid_rsa2048() {
    local name="valid_rsa2048"

    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TMP/$name.key" \
        -out "$TMP/$name.crt" \
        -days 36500 \
        -subj "/CN=signer-engine-test-rsa2048" \
        2>/dev/null

    openssl pkcs12 -export \
        -inkey "$TMP/$name.key" \
        -in "$TMP/$name.crt" \
        -out "$SCRIPT_DIR/$name.p12" \
        -password "pass:$PASSWORD"

    echo "  generated: $name.p12"
}

gen_valid_rsa2048

echo
echo "done."
