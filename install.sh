#!/bin/bash
set -e

# TODO: Update this to your GitHub repository (username/repo)
GITHUB_REPO="danst0/omega-backup"
BINARY_NAME="omega-backup"
INSTALL_DIR="/usr/local/bin"

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    echo "Error: Only x86_64 is currently supported."
    exit 1
fi

# Detect OS
OS=$(uname -s)
if [ "$OS" != "Linux" ]; then
    echo "Error: Only Linux is currently supported."
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo) to install to $INSTALL_DIR"
    exit 1
fi

echo "Finding latest release for $GITHUB_REPO..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: Could not find latest release. (Check if GITHUB_REPO is correct or if any releases exist)"
    exit 1
fi

echo "Downloading version $LATEST_TAG..."
ASSET_URL="https://github.com/$GITHUB_REPO/releases/download/$LATEST_TAG/omega-backup-x86_64-linux-musl.tar.gz"

TEMP_DIR=$(mktemp -d)
curl -L -o "$TEMP_DIR/release.tar.gz" "$ASSET_URL"

echo "Extracting..."
tar -xzf "$TEMP_DIR/release.tar.gz" -C "$TEMP_DIR"

echo "Installing to $INSTALL_DIR..."
mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

rm -rf "$TEMP_DIR"

echo "✅ Successfully installed $BINARY_NAME $LATEST_TAG to $INSTALL_DIR"
