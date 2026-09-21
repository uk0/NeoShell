#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# NeoShell Update Publisher
#
# Downloads latest release from GitHub, extracts dynamic libraries,
# signs them, generates update.json with SHA-256 digests and detached
# ed25519 signatures, and uploads everything to the update server.
#
# Usage:
#   ./scripts/publish-update.sh              # Use latest GitHub release
#   ./scripts/publish-update.sh v0.4.0       # Use specific version
#   DRY_RUN=1 ./scripts/publish-update.sh    # Preview without uploading
#
# Required env (for a real upload; DRY_RUN=1 needs none of it):
#   NEOSHELL_DEPLOY_HOST   SSH target, e.g. deploy@updates.example.com
# Optional env:
#   NEOSHELL_DEPLOY_ROOT   default /var/www/neoshell
#   NEOSHELL_UPDATE_URL    default https://neoshell.wwwneo.com/updates
#   NEOSHELL_REPO          default uk0/NeoShell
#   NEOSHELL_UPDATE_KEY    ed25519 signing key (default ~/.neoshell/update-signing-key.pem)
#   ALLOW_UNSIGNED=1       publish without signatures (clients will refuse them)
#
# NOTE: update.json is generated here and scp'd straight to the server. It is
#       deliberately NOT tracked in git — a stale copy with placeholder digests
#       would make every client reject the download.
# ═══════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

REPO="${NEOSHELL_REPO:-uk0/NeoShell}"
# Deploy target. Intentionally NOT defaulted — this is a public repo, so a
# baked-in host is both a leak and unusable for anyone else. Checked at the
# upload boundary, not here, so DRY_RUN=1 keeps working without it.
SERVER="${NEOSHELL_DEPLOY_HOST:-}"
SERVER_ROOT="${NEOSHELL_DEPLOY_ROOT:-/var/www/neoshell}"
SERVER_PATH="${SERVER_ROOT}/updates"
DOWNLOAD_PATH="${SERVER_ROOT}/downloads"
UPDATE_URL="${NEOSHELL_UPDATE_URL:-https://neoshell.wwwneo.com/updates}"
# Fresh private directory — a fixed /tmp path is pre-creatable by anyone on a
# shared machine, and this one holds what gets published.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/neoshell-update-publish.XXXXXX")"
SIGN_KEY="${NEOSHELL_UPDATE_KEY:-$HOME/.neoshell/update-signing-key.pem}"
DRY_RUN="${DRY_RUN:-0}"
trap 'rm -rf "$WORK_DIR"' EXIT

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[..]${NC} $1"; }
info() { echo -e "${CYAN}[>>]${NC} $1"; }
err()  { echo -e "${RED}[!!]${NC} $1"; exit 1; }

# ── Determine version ──────────────────────────────────────────
if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION=$(gh release view --repo "$REPO" --json tagName -q '.tagName' 2>/dev/null)
    [ -z "$VERSION" ] && err "Cannot determine latest release. Pass version as argument."
fi

# Strip 'v' prefix for clean version number
VER_NUM="${VERSION#v}"
info "Publishing update for NeoShell ${CYAN}${VER_NUM}${NC}"

# ── Prepare workspace ──────────────────────────────────────────
mkdir -p "$WORK_DIR"/{downloads,libs}
cd "$WORK_DIR"

# ── Download release artifacts ─────────────────────────────────
info "Downloading release ${VERSION} from GitHub..."
gh release download "$VERSION" --repo "$REPO" --dir downloads/ 2>&1 || err "Failed to download release"

echo ""
log "Downloaded artifacts:"
ls -lh downloads/

# ── Collect dynamic libraries (CI uploads them as separate release assets) ──
info "Collecting dynamic libraries from release assets..."

# Direct copy — CI already uploads versioned dylib/so/dll files
for f in downloads/libneoshell_core-*.dylib downloads/libneoshell_core-*.so downloads/neoshell_core-*.dll; do
    [ -f "$f" ] || continue
    cp "$f" "libs/$(basename $f)"
    log "Found: $(basename $f)"
done

echo ""
log "Collected libraries:"
ls -lh libs/ 2>/dev/null || warn "No libraries found"

# ── Sign libraries ─────────────────────────────────────────────
# An unsigned library is unusable: every 0.7.0+ client verifies a detached
# ed25519 signature before installing and refuses anything else. Publishing
# without one is a silent no-op update, so it has to be deliberate.
if [ -f "$SIGN_KEY" ]; then
    info "Signing libraries with ${SIGN_KEY}..."
    for f in libs/*; do
        [ -f "$f" ] || continue
        case "$f" in *.sig) continue ;; esac
        NEOSHELL_UPDATE_KEY="$SIGN_KEY" "$SCRIPT_DIR/sign-update.sh" "$f" >/dev/null \
            || err "Signing failed for $f"
        log "Signed: $(basename "$f")"
    done
elif [ "${ALLOW_UNSIGNED:-0}" = "1" ]; then
    warn "No signing key at ${SIGN_KEY} and ALLOW_UNSIGNED=1 — clients will REFUSE these libraries."
else
    err "No signing key at ${SIGN_KEY}.
  Create one with scripts/gen-update-key.sh, or point NEOSHELL_UPDATE_KEY at it.
  Set ALLOW_UNSIGNED=1 to publish anyway (clients will refuse the download)."
fi

# ── Generate checksums ─────────────────────────────────────────
info "Calculating checksums..."

declare -A MD5S
declare -A SHA256S
declare -A SIZES
declare -A SIGS
for f in libs/*; do
    [ -f "$f" ] || continue
    case "$f" in *.sig) continue ;; esac
    NAME=$(basename "$f")
    if command -v md5 &>/dev/null; then
        MD5S["$NAME"]=$(md5 -q "$f")
    else
        MD5S["$NAME"]=$(md5sum "$f" | awk '{print $1}')
    fi
    if command -v sha256sum &>/dev/null; then
        SHA256S["$NAME"]=$(sha256sum "$f" | awk '{print $1}')
    else
        SHA256S["$NAME"]=$(shasum -a 256 "$f" | awk '{print $1}')
    fi
    SIZES["$NAME"]=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null)
    if [ -f "$f.sig" ]; then
        SIGS["$NAME"]=$(base64 < "$f.sig" | tr -d '\n')
    else
        SIGS["$NAME"]=""
    fi
    log "$NAME → SHA256: ${SHA256S[$NAME]} (${SIZES[$NAME]} bytes)"
done

# ── Generate update.json ───────────────────────────────────────
info "Generating update.json..."

# Get changelog from git tag or release
CHANGELOG=$(gh release view "$VERSION" --repo "$REPO" --json body -q '.body' 2>/dev/null | head -5 | tr '\n' ' ' | sed 's/"/\\"/g')
[ -z "$CHANGELOG" ] && CHANGELOG="NeoShell ${VER_NUM} release"
TODAY=$(date +%Y-%m-%d)

# Library filename for each platform key the client looks up.
platform_file() {
    case "$1" in
        macos-aarch64)    echo "libneoshell_core-${VER_NUM}-macos-aarch64.dylib" ;;
        macos-x86_64)     echo "libneoshell_core-${VER_NUM}-macos-x86_64.dylib" ;;
        windows-x64)      echo "neoshell_core-${VER_NUM}-windows-x64.dll" ;;
        linux-x86_64)     echo "libneoshell_core-${VER_NUM}-linux-x86_64.so" ;;
        windows-win7-x64) echo "neoshell_core-${VER_NUM}-windows-win7-x64.dll" ;;
    esac
}

# Emit an entry only for an artifact that is present and fully described. A
# missing platform is omitted (those clients see "no update"), never published
# with a placeholder digest — the old `:-placeholder` / `:-0` defaults turned a
# naming drift into a live manifest that every client rejects.
DOWNLOADS=""
FOUND=0
for KEY in macos-aarch64 macos-x86_64 windows-x64 linux-x86_64 windows-win7-x64; do
    NAME="$(platform_file "$KEY")"
    if [ ! -f "libs/$NAME" ]; then
        warn "No artifact for ${KEY} (${NAME}) — omitting it from update.json"
        continue
    fi
    [ -n "${MD5S[$NAME]:-}" ]    || err "No MD5 for ${NAME}"
    [ -n "${SHA256S[$NAME]:-}" ] || err "No SHA256 for ${NAME}"
    [ -n "${SIZES[$NAME]:-}" ] && [ "${SIZES[$NAME]}" -gt 0 ] || err "No size for ${NAME}"
    [ -n "${SIGS[$NAME]:-}" ] || [ "${ALLOW_UNSIGNED:-0}" = "1" ] || err "No signature for ${NAME}"
    [ "$FOUND" -gt 0 ] && DOWNLOADS="${DOWNLOADS},"$'\n'
    DOWNLOADS="${DOWNLOADS}    \"${KEY}\": {
      \"url\": \"${UPDATE_URL}/libs/${NAME}\",
      \"md5\": \"${MD5S[$NAME]}\",
      \"sha256\": \"${SHA256S[$NAME]}\",
      \"sig\": \"${SIGS[$NAME]}\",
      \"size\": ${SIZES[$NAME]}
    }"
    FOUND=$((FOUND + 1))
done
[ "$FOUND" -gt 0 ] || err "No core libraries found for ${VERSION} — nothing to publish."

cat > update.json << ENDJSON
{
  "version": "${VER_NUM}",
  "date": "${TODAY}",
  "changelog": "${CHANGELOG}",
  "downloads": {
${DOWNLOADS}
  },
  "installers": {
    "macos-aarch64": "${UPDATE_URL}/../downloads/NeoShell-${VER_NUM}-macos-aarch64.dmg",
    "macos-x86_64": "${UPDATE_URL}/../downloads/NeoShell-${VER_NUM}-macos-x86_64.dmg",
    "windows-x64": "${UPDATE_URL}/../downloads/NeoShell-${VER_NUM}-windows-x64.zip",
    "windows-win7-x64": "${UPDATE_URL}/../downloads/NeoShell-${VER_NUM}-windows-win7-x64.zip",
    "linux-x86_64": "${UPDATE_URL}/../downloads/NeoShell-${VER_NUM}-linux-x86_64.AppImage"
  }
}
ENDJSON

echo ""
log "Generated update.json:"
cat update.json | python3 -m json.tool 2>/dev/null || cat update.json

# ── Upload to server ───────────────────────────────────────────
if [ "$DRY_RUN" = "1" ]; then
    echo ""
    # Keep the workspace so the generated manifest can actually be inspected.
    trap - EXIT
    warn "DRY RUN — skipping upload. Files left in: $WORK_DIR"
    exit 0
fi

if [ -z "$SERVER" ]; then
    err "NEOSHELL_DEPLOY_HOST is not set.
  Set it to the update server's SSH target, e.g.
      export NEOSHELL_DEPLOY_HOST=deploy@updates.example.com
  Optional: NEOSHELL_DEPLOY_ROOT (default /var/www/neoshell)
            NEOSHELL_UPDATE_URL  (default https://neoshell.wwwneo.com/updates)
  Or run with DRY_RUN=1 to generate update.json without uploading."
fi

echo ""
info "Uploading to ${SERVER}:${SERVER_PATH}..."

# Create directories
ssh "$SERVER" "mkdir -p ${SERVER_PATH}/libs" 2>/dev/null

# Upload dynamic libraries
for f in libs/*; do
    [ -f "$f" ] || continue
    scp "$f" "${SERVER}:${SERVER_PATH}/libs/$(basename $f)" && \
        log "Uploaded: $(basename $f)" || warn "Failed: $(basename $f)"
done

# Upload update.json
scp update.json "${SERVER}:${SERVER_PATH}/update.json" && \
    log "Uploaded: update.json"

# Also update the full installer downloads
info "Updating installer downloads..."
[ -n "$DOWNLOAD_PATH" ] || err "DOWNLOAD_PATH empty — refusing remote rm"
ssh "$SERVER" "rm -f '${DOWNLOAD_PATH}'/NeoShell-*"
for f in downloads/*; do
    [ -f "$f" ] || continue
    scp "$f" "${SERVER}:${DOWNLOAD_PATH}/$(basename "$f")" && \
        log "Uploaded: $(basename $f)"
done

# ── Verify ─────────────────────────────────────────────────────
echo ""
info "Verifying deployment..."
echo ""

ssh "$SERVER" "echo '=== Update Server ===' && ls -lh ${SERVER_PATH}/libs/ 2>/dev/null && echo '---' && cat ${SERVER_PATH}/update.json | head -4 && echo '...' && echo '=== Downloads ===' && ls -lh ${DOWNLOAD_PATH}/"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  NeoShell v${VER_NUM} update published successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "  Update URL: ${UPDATE_URL}/update.json"
echo "  Lib count:  $(ls libs/ 2>/dev/null | wc -l | tr -d ' ') platform(s)"
echo "  Existing users will see the update within 1 hour."
echo ""
