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

# -----------------------------------------------------------------------------
# with_chain.p12
# -----------------------------------------------------------------------------
# Leaf certificate issued by an intermediate CA, which is issued by a root CA.
# The p12 bundles the leaf key + leaf cert + intermediate cert. The root is
# not embedded (typical real-world setup: trust stores hold the root).
# Use case: exercises Signer.Chain() with a non-empty, valid chain.
gen_with_chain() {
    local name="with_chain"

    # 1. Root CA (self-signed, marked as CA).
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TMP/root.key" \
        -out "$TMP/root.crt" \
        -days 36500 \
        -subj "/CN=signer-engine-test-root" \
        -addext "basicConstraints=critical,CA:TRUE" \
        2>/dev/null

    # 2. Intermediate CA: CSR signed by root, also marked as CA.
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$TMP/intermediate.key" \
        -out "$TMP/intermediate.csr" \
        -subj "/CN=signer-engine-test-intermediate" \
        2>/dev/null

    openssl x509 -req \
        -in "$TMP/intermediate.csr" \
        -CA "$TMP/root.crt" -CAkey "$TMP/root.key" \
        -CAcreateserial \
        -out "$TMP/intermediate.crt" \
        -days 36500 \
        -extfile <(echo "basicConstraints=critical,CA:TRUE") \
        2>/dev/null

    # 3. Leaf cert: CSR signed by intermediate, NOT a CA.
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$TMP/leaf.key" \
        -out "$TMP/leaf.csr" \
        -subj "/CN=signer-engine-test-leaf" \
        2>/dev/null

    openssl x509 -req \
        -in "$TMP/leaf.csr" \
        -CA "$TMP/intermediate.crt" -CAkey "$TMP/intermediate.key" \
        -CAcreateserial \
        -out "$TMP/leaf.crt" \
        -days 36500 \
        2>/dev/null

    # 4. Bundle into p12: leaf key + leaf cert, with intermediate in the chain.
    openssl pkcs12 -export \
        -inkey "$TMP/leaf.key" \
        -in "$TMP/leaf.crt" \
        -certfile "$TMP/intermediate.crt" \
        -out "$SCRIPT_DIR/$name.p12" \
        -password "pass:$PASSWORD"

    echo "  generated: $name.p12"
}

gen_valid_rsa2048
gen_with_chain

echo
echo "done."
