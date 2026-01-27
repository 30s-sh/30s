#!/bin/sh
# 30s CLI installer
# Usage: curl -sSL https://30s.sh/install.sh | sh

set -e

RELEASES_URL="https://30s-releases.sfo3.cdn.digitaloceanspaces.com"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="30s"

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux) echo "linux" ;;
        *) echo "unsupported" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;;
        amd64) echo "amd64" ;;
        arm64) echo "arm64" ;;
        aarch64) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

# Compute SHA256 hash (works on both macOS and Linux)
compute_sha256() {
    if command -v sha256sum > /dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum > /dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

main() {
    OS=$(detect_os)
    ARCH=$(detect_arch)

    if [ "$OS" = "unsupported" ]; then
        echo "Error: Unsupported operating system"
        exit 1
    fi

    if [ "$ARCH" = "unsupported" ]; then
        echo "Error: Unsupported architecture"
        exit 1
    fi

    # Get latest version (or use VERSION env var)
    if [ -z "$VERSION" ]; then
        VERSION=$(curl -sSL "${RELEASES_URL}/latest.txt")
    fi

    ARTIFACT_NAME="${BINARY_NAME}-${OS}-${ARCH}"
    DOWNLOAD_URL="${RELEASES_URL}/cli/${VERSION}/${ARTIFACT_NAME}"
    CHECKSUMS_URL="${RELEASES_URL}/cli/${VERSION}/checksums.txt"

    echo "Downloading 30s ${VERSION} for ${OS}/${ARCH}..."

    # Create temp file
    TMP_FILE=$(mktemp)
    trap "rm -f ${TMP_FILE}" EXIT

    # Download binary
    if command -v curl > /dev/null; then
        curl -sSL "$DOWNLOAD_URL" -o "$TMP_FILE"
    elif command -v wget > /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$TMP_FILE"
    else
        echo "Error: curl or wget required"
        exit 1
    fi

    # Verify checksum
    echo "Verifying checksum..."
    if command -v curl > /dev/null; then
        EXPECTED_HASH=$(curl -sSL "$CHECKSUMS_URL" | grep "$ARTIFACT_NAME" | awk '{print $1}')
    else
        EXPECTED_HASH=$(wget -qO- "$CHECKSUMS_URL" | grep "$ARTIFACT_NAME" | awk '{print $1}')
    fi

    ACTUAL_HASH=$(compute_sha256 "$TMP_FILE")

    if [ -z "$ACTUAL_HASH" ]; then
        echo "Warning: Could not compute checksum (sha256sum/shasum not found)"
    elif [ -z "$EXPECTED_HASH" ]; then
        echo "Warning: Could not fetch expected checksum"
    elif [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        echo "Error: Checksum verification failed!"
        echo "  Expected: $EXPECTED_HASH"
        echo "  Got:      $ACTUAL_HASH"
        exit 1
    else
        echo "Checksum verified."
    fi

    # Make executable
    chmod +x "$TMP_FILE"

    # Install (may need sudo)
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    echo ""
    echo "30s ${VERSION} installed to ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""
    echo "Get started:"
    echo "  30s init <your-email>"
}

main
