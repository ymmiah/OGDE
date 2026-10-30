#!/bin/sh
# Assemble a static publish directory from site/ and the canonical brand files.
set -eu
cd "$(dirname "$0")/.."
out="site/public"
rm -rf "$out"
mkdir -p "$out/assets/brand"
sed 's#\.\./assets/brand/#assets/brand/#g' site/index.html > "$out/index.html"
cp site/styles.css site/_headers "$out/"
cp assets/brand/ogde-logo.svg \
   assets/brand/ogde-logo.png \
   assets/brand/ogde-logo.jpg \
   assets/brand/ogde-icon.svg \
   assets/brand/ogde-icon.png \
   assets/brand/ogde-icon-32.png \
   assets/brand/ogde-icon-180.png \
   assets/brand/favicon.ico \
   "$out/assets/brand/"
echo "Publish directory: $out"
