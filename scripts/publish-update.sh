#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# NeoShell Update Publisher
#
# Downloads latest release from GitHub, extracts dynamic libraries,
# generates update.json with MD5 checksums, and uploads everything
# to the update server.
#
# Usage:
#   ./scripts/publish-update.sh              # Use latest GitHub release
#   ./scripts/publish-update.sh v0.4.0       # Use specific version
#   DRY_RUN=1 ./scripts/publish-update.sh    # Preview without uploading
# ═══════════════════════════════════════════════════════════════

set -e

REPO="uk0/NeoShell"
SERVER="root@dpnet1"
SERVER_PATH="/var/www/neoshell/updates"
UPDATE_URL="https://neoshell.wwwneo.com/updates"
WORK_DIR="/tmp/neoshell-update-publish"
DRY_RUN="${DRY_RUN:-0}"

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
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"/{downloads,libs}
cd "$WORK_DIR"

# ── Download release artifacts ─────────────────────────────────
info "Downloading release ${VERSION} from GitHub..."
gh release download "$VERSION" --repo "$REPO" --dir downloads/ 2>&1 || err "Failed to download release"

echo ""
log "Downloaded artifacts:"
ls -lh downloads/

# ── Extract dynamic libraries from each platform ───────────────
info "Extracting dynamic libraries..."

# macOS ARM64 (.dmg → .dylib)
DMG_ARM="downloads/NeoShell-${VER_NUM}-macos-aarch64.dmg"
if [ -f "$DMG_ARM" ]; then
    MOUNT_DIR=$(hdiutil attach "$DMG_ARM" -nobrowse -readonly 2>/dev/null | grep "Volumes" | awk -F'\t' '{print $NF}')
    if [ -d "$MOUNT_DIR" ]; then
        cp "$MOUNT_DIR/NeoShell.app/Contents/MacOS/libneoshell_core.dylib" \
           "libs/libneoshell_core-${VER_NUM}-macos-aarch64.dylib" 2>/dev/null && \
           log "Extracted: macos-aarch64 dylib" || warn "No dylib in ARM64 DMG"
        hdiutil detach "$MOUNT_DIR" -quiet 2>/dev/null || true
    fi
fi

# macOS x86_64 (.dmg → .dylib)
DMG_X86="downloads/NeoShell-${VER_NUM}-macos-x86_64.dmg"
if [ -f "$DMG_X86" ]; then
    MOUNT_DIR=$(hdiutil attach "$DMG_X86" -nobrowse -readonly 2>/dev/null | grep "Volumes" | awk -F'\t' '{print $NF}')
    if [ -d "$MOUNT_DIR" ]; then
        cp "$MOUNT_DIR/NeoShell.app/Contents/MacOS/libneoshell_core.dylib" \
           "libs/libneoshell_core-${VER_NUM}-macos-x86_64.dylib" 2>/dev/null && \
           log "Extracted: macos-x86_64 dylib" || warn "No dylib in x86 DMG"
        hdiutil detach "$MOUNT_DIR" -quiet 2>/dev/null || true
    fi
fi

# Windows (.zip → .dll)
ZIP_WIN="downloads/NeoShell-${VER_NUM}-windows-x64.zip"
if [ -f "$ZIP_WIN" ]; then
    mkdir -p /tmp/neo-win-extract
    unzip -o "$ZIP_WIN" -d /tmp/neo-win-extract/ 2>/dev/null
    DLL=$(find /tmp/neo-win-extract -name "neoshell_core.dll" 2>/dev/null | head -1)
    if [ -n "$DLL" ]; then
        cp "$DLL" "libs/neoshell_core-${VER_NUM}-windows-x64.dll"
        log "Extracted: windows-x64 dll"
    else
        warn "No dll in Windows zip"
    fi
    rm -rf /tmp/neo-win-extract
fi

# Linux (.AppImage → .so)
APPIMAGE="downloads/NeoShell-${VER_NUM}-linux-x86_64.AppImage"
if [ -f "$APPIMAGE" ]; then
    chmod +x "$APPIMAGE"
    mkdir -p /tmp/neo-linux-extract
    cd /tmp/neo-linux-extract
    "$WORK_DIR/$APPIMAGE" --appimage-extract 2>/dev/null || true
    SO=$(find . -name "libneoshell_core.so" 2>/dev/null | head -1)
    if [ -n "$SO" ]; then
        cp "$SO" "$WORK_DIR/libs/libneoshell_core-${VER_NUM}-linux-x86_64.so"
        log "Extracted: linux-x86_64 so"
    else
        warn "No .so in AppImage"
    fi
    rm -rf /tmp/neo-linux-extract
    cd "$WORK_DIR"
fi

echo ""
log "Extracted libraries:"
ls -lh libs/ 2>/dev/null || warn "No libraries extracted"

# ── Generate MD5 checksums ─────────────────────────────────────
info "Calculating MD5 checksums..."

declare -A MD5S
declare -A SIZES
for f in libs/*; do
    [ -f "$f" ] || continue
    NAME=$(basename "$f")
    if command -v md5 &>/dev/null; then
        MD5S["$NAME"]=$(md5 -q "$f")
    else
        MD5S["$NAME"]=$(md5sum "$f" | awk '{print $1}')
    fi
    SIZES["$NAME"]=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null)
    log "$NAME → MD5: ${MD5S[$NAME]} (${SIZES[$NAME]} bytes)"
done

# ── Generate update.json ───────────────────────────────────────
info "Generating update.json..."

# Get changelog from git tag or release
CHANGELOG=$(gh release view "$VERSION" --repo "$REPO" --json body -q '.body' 2>/dev/null | head -5 | tr '\n' ' ' | sed 's/"/\\"/g')
[ -z "$CHANGELOG" ] && CHANGELOG="NeoShell ${VER_NUM} release"
TODAY=$(date +%Y-%m-%d)

cat > update.json << ENDJSON
{
  "version": "${VER_NUM}",
  "date": "${TODAY}",
  "changelog": "${CHANGELOG}",
  "downloads": {
    "macos-aarch64": {
      "url": "${UPDATE_URL}/libs/libneoshell_core-${VER_NUM}-macos-aarch64.dylib",
      "md5": "${MD5S[libneoshell_core-${VER_NUM}-macos-aarch64.dylib]:-placeholder}",
      "size": ${SIZES[libneoshell_core-${VER_NUM}-macos-aarch64.dylib]:-0}
    },
    "macos-x86_64": {
      "url": "${UPDATE_URL}/libs/libneoshell_core-${VER_NUM}-macos-x86_64.dylib",
      "md5": "${MD5S[libneoshell_core-${VER_NUM}-macos-x86_64.dylib]:-placeholder}",
      "size": ${SIZES[libneoshell_core-${VER_NUM}-macos-x86_64.dylib]:-0}
    },
    "windows-x64": {
      "url": "${UPDATE_URL}/libs/neoshell_core-${VER_NUM}-windows-x64.dll",
      "md5": "${MD5S[neoshell_core-${VER_NUM}-windows-x64.dll]:-placeholder}",
      "size": ${SIZES[neoshell_core-${VER_NUM}-windows-x64.dll]:-0}
    },
    "linux-x86_64": {
      "url": "${UPDATE_URL}/libs/libneoshell_core-${VER_NUM}-linux-x86_64.so",
      "md5": "${MD5S[libneoshell_core-${VER_NUM}-linux-x86_64.so]:-placeholder}",
      "size": ${SIZES[libneoshell_core-${VER_NUM}-linux-x86_64.so]:-0}
    },
    "windows-win7-x64": {
      "url": "${UPDATE_URL}/libs/neoshell_core-${VER_NUM}-windows-win7-x64.dll",
      "md5": "${MD5S[neoshell_core-${VER_NUM}-windows-win7-x64.dll]:-placeholder}",
      "size": ${SIZES[neoshell_core-${VER_NUM}-windows-win7-x64.dll]:-0}
    }
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
    warn "DRY RUN — skipping upload. Files in: $WORK_DIR"
    exit 0
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
ssh "$SERVER" "rm -f /var/www/neoshell/downloads/NeoShell-*"
for f in downloads/*; do
    [ -f "$f" ] || continue
    scp "$f" "${SERVER}:/var/www/neoshell/downloads/$(basename $f)" && \
        log "Uploaded: $(basename $f)"
done

# ── Verify ─────────────────────────────────────────────────────
echo ""
info "Verifying deployment..."
echo ""

ssh "$SERVER" "echo '=== Update Server ===' && ls -lh ${SERVER_PATH}/libs/ 2>/dev/null && echo '---' && cat ${SERVER_PATH}/update.json | head -4 && echo '...' && echo '=== Downloads ===' && ls -lh /var/www/neoshell/downloads/"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  NeoShell v${VER_NUM} update published successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "  Update URL: ${UPDATE_URL}/update.json"
echo "  Lib count:  $(ls libs/ 2>/dev/null | wc -l | tr -d ' ') platform(s)"
echo "  Existing users will see the update within 1 hour."
echo ""
