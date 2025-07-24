#!/usr/bin/env bash
set -euo pipefail

export NODE_NO_WARNINGS=1

RUST="./target/debug/ecies-encryption-cli"  # Path to Rust binary
JS="pnpm tsx ./ts/cli/index.ts"                      # Path to JS CLI
MSG="hello from integration test"                   # Test message

pnpm install
pnpm build

cargo build

echo "=== Scenario 1: JS encrypt -> Rust decrypt ==="

# Generate keypair in JS
eval "$($JS generate-keypair | tee /dev/stderr | awk '
  /Private key:/ { print "JS_SK=" $3 }
  /Public key:/ { print "JS_PK=" $3 }
')"

# Encrypt in JS
JS_CIPHERTEXT=$($JS encrypt --pubkey "$JS_PK" --message "$MSG")

# Decrypt in Rust
RUST_OUTPUT=$($RUST decrypt --privkey "$JS_SK" --ciphertext "$JS_CIPHERTEXT")
echo "Rust output: $RUST_OUTPUT"

if [[ "$RUST_OUTPUT" == "$MSG" ]]; then
  echo "✅ JS → Rust decryption success"
else
  echo "❌ JS → Rust decryption failed"
  echo "Expected: $MSG"
  echo "Got: $RUST_OUTPUT"
  exit 1
fi


echo "=== Scenario 2: Rust encrypt -> JS decrypt ==="

# Generate keypair in Rust
eval "$($RUST generate-keypair | tee /dev/stderr | awk '
  /Private key:/ { print "RUST_SK=" $3 }
  /Public key:/ { print "RUST_PK=" $3 }
')"

# Encrypt in Rust
RUST_CIPHERTEXT=$($RUST encrypt --pubkey "$RUST_PK" --message "$MSG" | tail -n1)

echo "Rust ciphertext: $RUST_CIPHERTEXT"

# Decrypt in JS
JS_OUTPUT=$($JS decrypt --privkey "$RUST_SK" --ciphertext "$RUST_CIPHERTEXT")

if [[ "$JS_OUTPUT" == "$MSG" ]]; then
  echo "✅ Rust → JS decryption success"
else
  echo "❌ Rust → JS decryption failed"
  echo "Expected: $MSG"
  echo "Got: $JS_OUTPUT"
  exit 1
fi

echo "🎉 All integration tests passed!"
