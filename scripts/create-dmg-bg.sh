#!/bin/bash
# Generate DMG installer background image (1200x600)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/dmg-background.png"

# Pick a bold font (macOS, Linux, CI fallback)
BOLD_FONT=""
REGULAR_FONT=""
for f in \
  "/System/Library/Fonts/Supplemental/Arial Bold.ttf" \
  "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" \
  "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"; do
  if [ -f "$f" ]; then BOLD_FONT="$f"; break; fi
done
for f in \
  "/System/Library/Fonts/Supplemental/Arial.ttf" \
  "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf" \
  "/usr/share/fonts/TTF/DejaVuSans.ttf"; do
  if [ -f "$f" ]; then REGULAR_FONT="$f"; break; fi
done

FONT_BOLD_ARGS=()
FONT_REG_ARGS=()
[ -n "$BOLD_FONT" ] && FONT_BOLD_ARGS=(-font "$BOLD_FONT")
[ -n "$REGULAR_FONT" ] && FONT_REG_ARGS=(-font "$REGULAR_FONT")

magick -size 1200x600 xc:'#0c0c16' \
  \( -size 1200x600 xc:none \
     -fill 'rgba(232,168,76,0.03)' \
     -draw "circle 900,300 900,600" \
  \) -composite \
  \( -size 1200x600 xc:none \
     -fill 'rgba(93,228,199,0.02)' \
     -draw "circle 300,200 300,500" \
  \) -composite \
  "${FONT_BOLD_ARGS[@]}" -pointsize 28 -fill '#e8a84c' \
  -gravity north -annotate +0+60 "NeoShell" \
  "${FONT_REG_ARGS[@]}" -pointsize 14 -fill '#5c584f' \
  -gravity north -annotate +0+100 "Drag NeoShell.app to Applications" \
  "$OUT"

echo "Created $OUT"
