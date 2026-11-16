#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${HOME}/public_html"
cp "$ROOT/public/index.html" "$ROOT/public/styles.css" "$ROOT/public/app.js" \
   "$ROOT/public/admin.html" "$ROOT/public/admin.js" "$ROOT/public/admin.css" \
   "$ROOT/public/7477218.txt" "$DEST/"
cp "$ROOT/.htaccess" "$DEST/.htaccess"
echo "Copied store files to $DEST"
echo "Restart the Node.js app in cPanel, then open /admin"
