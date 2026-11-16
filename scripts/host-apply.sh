#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${HOME}/public_html"
cp "$ROOT/public/index.html" "$ROOT/public/styles.css" "$ROOT/public/app.js" \
   "$ROOT/public/admin.html" "$ROOT/public/admin.js" "$ROOT/public/admin.css" \
   "$ROOT/public/7477218.txt" "$ROOT/public/hero.jpg" "$DEST/"
echo "Copied store files to $DEST"
echo "Do not overwrite public_html/.htaccess. Keep the Node app Running."
