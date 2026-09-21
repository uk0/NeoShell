#!/bin/bash
# macOS app signing script
# Usage: ./scripts/sign-macos.sh <app-path> [identity]
# If identity is "-", uses ad-hoc signing (no certificate needed)
#
# ─────────────────────────────────────────────────────────────────────────────
# NOTARIZATION — NOT DONE HERE. What it would take, recorded so the next person
# does not have to re-derive it:
#
#  1. A real *Developer ID Application* certificate (not "Apple Development",
#     and not the ad-hoc "-" default below). Ad-hoc signatures cannot be
#     notarized at all.
#  2. `--timestamp` on every codesign call. Notarization rejects signatures
#     without a secure timestamp. Already wired below for a real identity.
#  3. Inside-out signing, no `--deep` (deprecated by Apple for signing):
#     libneoshell_core.dylib → neoshell → NeoShell.app. Done below.
#  4. Sign the DMG too. The notarized artifact is the disk image, not the .app:
#     `codesign --sign "$IDENTITY" --timestamp dist/NeoShell-*.dmg`.
#     .github/workflows/release.yml currently ships the DMG unsigned.
#  5. `xcrun notarytool submit <dmg> --wait`, with App Store Connect API key
#     credentials (`--key AuthKey_<ID>.p8 --key-id <ID> --issuer <UUID>`) rather
#     than an Apple ID — no 2FA coupling, independently revocable. Note that
#     `notarytool store-credentials` is interactive and unusable in CI.
#  6. `xcrun stapler staple <dmg>` + `xcrun stapler validate`, then assert with
#     `spctl -a -t open --context context:primary-signature -v <dmg>`.
#     Without stapling, first launch needs to reach Apple over the network.
#  7. THE NON-OBVIOUS ONE: the self-update channel bypasses all of the above.
#     scripts/publish-update.sh ships a bare libneoshell_core.dylib that the
#     launcher dlopens, and entitlements.plist sets disable-library-validation
#     (required — the launcher swaps the core at runtime), so macOS will load an
#     un-notarized replacement happily. Every dylib uploaded to the update
#     server must itself be hardened-runtime signed with the same Team ID and
#     notarized, or notarizing the DMG only covers the first install.
#
# Entitlements are already notarization-compatible; all five keys in
# scripts/entitlements.plist are permitted. disable-library-validation must stay.
# ─────────────────────────────────────────────────────────────────────────────

set -e

APP_PATH="${1:?Usage: sign-macos.sh <app-path> [identity]}"
IDENTITY="${2:--}"  # Default: ad-hoc
ENTITLEMENTS="$(dirname "$0")/entitlements.plist"

# Create entitlements if not exists
if [ ! -f "$ENTITLEMENTS" ]; then
  cat > "$ENTITLEMENTS" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
  <key>com.apple.security.cs.allow-jit</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
  <key>com.apple.security.network.client</key><true/>
  <key>com.apple.security.files.user-selected.read-write</key><true/>
</dict></plist>
EOF
fi

echo "Signing $APP_PATH with identity: $IDENTITY"

# A secure timestamp is required for notarization and unavailable for ad-hoc.
TS=""
if [ "$IDENTITY" != "-" ]; then TS="--timestamp"; fi

sign_one() {
  codesign --force --options runtime $TS \
    --entitlements "$ENTITLEMENTS" \
    --sign "$IDENTITY" \
    "$1"
}

# Inside-out: nested code first, bundle last. No --deep (deprecated for signing).
if [ -f "$APP_PATH/Contents/MacOS/libneoshell_core.dylib" ]; then
  sign_one "$APP_PATH/Contents/MacOS/libneoshell_core.dylib"
fi
sign_one "$APP_PATH/Contents/MacOS/neoshell"
sign_one "$APP_PATH"

# Verify
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
echo "Signing complete and verified."
