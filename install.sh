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

# Determine install directory
# Priority:
# 1. ~/.local/bin (if in PATH or existing)
# 2. ~/bin (if in PATH)
# 3. /usr/local/bin (system default)
# 4. Ask user (if interactive)

USER_LOCAL_BIN="$HOME/.local/bin"
USER_BIN="$HOME/bin"
SYSTEM_BIN="/usr/local/bin"

INSTALL_DIR=""

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" == *":$USER_LOCAL_BIN:"* ]]; then
    INSTALL_DIR="$USER_LOCAL_BIN"
elif [[ ":$PATH:" == *":$USER_BIN:"* ]]; then
    INSTALL_DIR="$USER_BIN"
elif [ -d "$USER_LOCAL_BIN" ]; then
    # Even if not in PATH, if it exists, it's a good candidate
    INSTALL_DIR="$USER_LOCAL_BIN"
    echo "Warning: $USER_LOCAL_BIN is not in your PATH."
fi

# If no user dir found, default to system
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="$SYSTEM_BIN"
fi

# Function to check if we can write to a directory
can_write() {
    if [ -w "$1" ]; then
        return 0
    fi
    if [ ! -e "$1" ] && [ -w "$(dirname "$1")" ]; then
        return 0
    fi
    return 1
}

# Interactive prompt if we can't write to default or user wants to change
if [ ! -w "$INSTALL_DIR" ] && [ ! -w "$(dirname "$INSTALL_DIR")" ]; then
    if [ -t 0 ]; then
        echo "Default install directory $INSTALL_DIR is not writable."
        read -p "Enter installation directory (or press Enter to try sudo with $INSTALL_DIR): " USER_INPUT
        if [ -n "$USER_INPUT" ]; then
            INSTALL_DIR="$USER_INPUT"
        fi
    fi
fi

# Prepare install dir
if [ ! -d "$INSTALL_DIR" ]; then
    if can_write "$(dirname "$INSTALL_DIR")"; then
        mkdir -p "$INSTALL_DIR"
    else
        echo "Creating $INSTALL_DIR requires sudo..."
        if ! sudo mkdir -p "$INSTALL_DIR"; then
            echo "Error: Failed to create $INSTALL_DIR"
            exit 1
        fi
        # If we created it with sudo, we might need to chown it if it's in user home
        if [[ "$INSTALL_DIR" == "$HOME"* ]]; then
            sudo chown "$USER":"$USER" "$INSTALL_DIR"
        fi
    fi
fi

# Check write permission again
USE_SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
    if [ -t 0 ]; then
        echo "Installation to $INSTALL_DIR requires root permissions."
        # Check if sudo is available
        if command -v sudo >/dev/null 2>&1; then
            USE_SUDO="sudo"
            # Verify sudo works (ask for password early)
            sudo -v || exit 1
        else
            echo "Error: sudo not found and $INSTALL_DIR is not writable."
            exit 1
        fi
    else
        echo "Error: Cannot write to $INSTALL_DIR. Run as root or choose a writable directory."
        exit 1
    fi
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
$USE_SUDO mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
$USE_SUDO chmod +x "$INSTALL_DIR/$BINARY_NAME"

rm -rf "$TEMP_DIR"

echo "✅ Successfully installed $BINARY_NAME $LATEST_TAG to $INSTALL_DIR"
