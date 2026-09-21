#!/usr/bin/env bash
#
# Generate the ed25519 keypair that signs NeoShell core-library updates.
#
#   ./scripts/gen-update-key.sh [out.pem]
#
# The PRIVATE key stays on the release machine (or in the CI secret store) and
# is never committed. It defaults to a path OUTSIDE the repository so it cannot
# be added by accident. The printed base64 PUBLIC key is compiled into both the
# launcher and the core:
#
#   NEOSHELL_UPDATE_PUBKEY=<base64> cargo build --release
#
# Without that variable the launcher refuses to install any staged update.
#
set -euo pipefail

OPENSSL="${OPENSSL:-openssl}"
KEY="${1:-$HOME/.neoshell/update-signing-key.pem}"

command -v "$OPENSSL" >/dev/null 2>&1 || {
    echo "openssl not found; set OPENSSL=/path/to/openssl (OpenSSL 3.x required)" >&2
    exit 1
}
[ -e "$KEY" ] && { echo "Refusing to overwrite an existing key: $KEY" >&2; exit 1; }

umask 077
mkdir -p "$(dirname "$KEY")"
"$OPENSSL" genpkey -algorithm ed25519 -out "$KEY"
chmod 600 "$KEY"

# An ed25519 SPKI DER is a 12-byte header followed by the 32-byte raw key.
PUB="$("$OPENSSL" pkey -in "$KEY" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')"

cat <<MSG

Private key written to: $KEY  (mode 600 — keep it out of git)
Public key (base64, 32 bytes):

    $PUB

Next steps:
  1. Store the private key as a CI secret; point NEOSHELL_UPDATE_KEY at it
     when signing. Never commit it.
  2. Set the build environment variable on every release build:
         NEOSHELL_UPDATE_PUBKEY=$PUB
  3. Sign each published library with scripts/sign-update.sh and upload the
     resulting .sig next to it, or paste the base64 into update.json's "sig".

Rotating this key invalidates every already-published signature, and clients
running an older launcher will only accept the key they were built with.
MSG
