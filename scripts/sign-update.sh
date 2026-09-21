#!/usr/bin/env bash
#
# Sign built core libraries for the update channel.
#
#   [NEOSHELL_UPDATE_KEY=<key.pem>] ./scripts/sign-update.sh <file> [file...]
#
# Writes <file>.sig (a raw 64-byte detached ed25519 signature) next to each
# input and prints the sha256/size/sig triple for update.json. The launcher
# verifies the same signature again before it installs anything.
#
set -euo pipefail

OPENSSL="${OPENSSL:-openssl}"
KEY="${NEOSHELL_UPDATE_KEY:-$HOME/.neoshell/update-signing-key.pem}"

[ $# -ge 1 ] || { echo "usage: $0 <file> [file...]" >&2; exit 1; }
command -v "$OPENSSL" >/dev/null 2>&1 || {
    echo "openssl not found; set OPENSSL=/path/to/openssl (OpenSSL 3.x required)" >&2
    exit 1
}
[ -f "$KEY" ] || { echo "signing key not found: $KEY (set NEOSHELL_UPDATE_KEY)" >&2; exit 1; }

PUB_PEM="$(mktemp "${TMPDIR:-/tmp}/neoshell-update-pub.XXXXXX")"
trap 'rm -f "$PUB_PEM"' EXIT
"$OPENSSL" pkey -in "$KEY" -pubout -out "$PUB_PEM"

for f in "$@"; do
    [ -f "$f" ] || { echo "no such file: $f" >&2; exit 1; }
    "$OPENSSL" pkeyutl -sign -inkey "$KEY" -rawin -in "$f" -out "$f.sig"
    # Never publish a signature that has not been checked against its own key.
    "$OPENSSL" pkeyutl -verify -pubin -inkey "$PUB_PEM" -rawin -in "$f" -sigfile "$f.sig" >/dev/null \
        || { echo "self-verification failed for $f" >&2; exit 1; }
    echo "$f -> $f.sig"
    echo "  \"sha256\": \"$("$OPENSSL" dgst -sha256 -r "$f" | cut -d' ' -f1)\","
    echo "  \"size\": $(wc -c < "$f" | tr -d ' '),"
    echo "  \"sig\": \"$(base64 < "$f.sig" | tr -d '\n')\""
done
