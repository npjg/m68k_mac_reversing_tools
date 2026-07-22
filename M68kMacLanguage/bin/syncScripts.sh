#!/usr/bin/env bash

usage() {
    cat << EOF
Usage: $0 [GHIDRA_INSTALL_DIR]

Syncs scripts belonging to a Ghidra extension to the proper directory so the extension doesn't have to be rebuilt
to use the new scripts.

Arguments:
  GHIDRA_INSTALL_DIR  Path to Ghidra installation directory
                      (can also be provided by exported GHIDRA_INSTALL_DIR environment variable)
EOF
    exit 1
}

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

# TODO: Support other extensions too... don't hardcode this extension name.
cp -r ghidra_scripts "$GHIDRA_INSTALL_DIR/Extensions/M68kMacLanguage/"