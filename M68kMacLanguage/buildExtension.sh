#!/usr/bin/env bash

usage() {
    cat << EOF
Usage: $0 [GHIDRA_INSTALL_DIR]

Builds the Ghidra extension, and puts the built extension ZIP in a place where it's ready to install from the Ghidra GUI.
The extension is NOT automatically installed.

Arguments:
  GHIDRA_INSTALL_DIR  Path to Ghidra installation directory
                      (can also be provided by exported GHIDRA_INSTALL_DIR environment variable)
EOF
    exit 1
}

# Exit immediately if a command exits with a non-zero status.
# -e: Exit on error
# -u: Treat unset variables as an error and exit immediately
# -o pipefail: Prevent errors in a pipeline from being masked; if any command in a pipeline fails, the entire pipeline fails
set -euo pipefail

# PARSE COMMAND-LINE ARGUMENTS.
if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help)
            usage
            ;;
        *)
            GHIDRA_INSTALL_DIR="$1"
            ;;
    esac
fi

# VALIDATE THE GHIDRA INSTALLATION DIRECTORY.
echo "GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR"
if [[ -z "${GHIDRA_INSTALL_DIR:-}" || ! -d "$GHIDRA_INSTALL_DIR" ]]; then
    echo "ERROR: GHIDRA_INSTALL_DIR not set or directory not found"
    echo ""
    usage
fi

# BUILD THE EXTENSION.
echo "Building extension..."
rm -r dist/
gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"

# COPY THE EXTENSION WHERE GHIDRA CAN FIND IT TO INSTALL.
# This does NOT install the extension, but instead makes it show up in "File > Configure > Install Extensions...",
# where it can be enabled.
# TODO: Delete older versions of the same extension.
echo ""
echo "Copying extension ZIP..."
mkdir -p "$GHIDRA_INSTALL_DIR/Extensions/Ghidra"
cp -v dist/* "$GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
