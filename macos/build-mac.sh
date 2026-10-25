#!/bin/sh
# Builds dist/CertGen.app (Apple Silicon or Intel, whichever this Mac is). Usage: ./build-mac.sh   (VERSION=1.0 by default)
set -e
cd "$(dirname "$0")"
VERSION=${VERSION:-1.0}
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt pyinstaller
.venv/bin/pyinstaller --noconfirm --windowed --name CertGen --icon icon.icns \
  --osx-bundle-identifier local.certgen.app --add-data "static:static" app.py
plutil -replace CFBundleShortVersionString -string "$VERSION" dist/CertGen.app/Contents/Info.plist
plutil -replace CFBundleVersion -string "$VERSION" dist/CertGen.app/Contents/Info.plist
codesign --force --deep --sign - dist/CertGen.app   # ad-hoc re-sign after editing Info.plist
echo "Built dist/CertGen.app $VERSION"
