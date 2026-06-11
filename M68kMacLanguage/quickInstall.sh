#!/usr/bin/env bash

usage() {
    cat << EOF
Usage: $0 [GHIDRA_INSTALL_DIR] [GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR]
       $0 [--no-kill] [GHIDRA_INSTALL_DIR] [GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR]

Rebuild the Ghidra extension, extract it to replace a currently-installed version, and restart Ghidra.

This is a workaround for "reloading" extensions if you are unwilling or unable to use Eclipse.
Even when you're using Eclipse and GhidraDev, Ghidra doesn't seem to provide a way to hot-reload
extensions (but maybe I just didn't try hard enough).

Arguments:
  --no-kill             Skip force-killing running Ghidra processes.
  GHIDRA_INSTALL_DIR    Path to Ghidra installation directory
                        (can also be provided by exported GHIDRA_INSTALL_DIR environment variable)
  GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR   Path to Ghidra user extensions directory
                        (can also be provided by exported GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR environment variable)
EOF
    exit 1
}

# Exit immediately if a command exits with a non-zero status.
# -e: Exit on error
# -u: Treat unset variables as an error and exit immediately
# -o pipefail: Prevent errors in a pipeline from being masked; if any command in a pipeline fails, the entire pipeline fails
set -euo pipefail

# PARSE COMMAND-LINE ARGUMENTS.
NO_KILL=0
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --no-kill)
            NO_KILL=1
            shift
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                POSITIONAL+=("$1")
                shift
            done
            ;;
        -*)
            echo "ERROR: Unknown option: $1"
            echo ""
            usage
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
    GHIDRA_INSTALL_DIR="${POSITIONAL[0]}"
fi

if [[ ${#POSITIONAL[@]} -gt 1 ]]; then
    GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR="${POSITIONAL[1]}"
fi

# VALIDATE THE GHIDRA INSTALLATION DIRECTORY.
if [[ -z "${GHIDRA_INSTALL_DIR:-}" || ! -d "$GHIDRA_INSTALL_DIR" ]]; then
    echo "ERROR: GHIDRA_INSTALL_DIR not set or directory not found: ${GHIDRA_INSTALL_DIR:-}"
    echo ""
    usage
fi

echo "GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR"
echo ""

# VALIDATE THE GHIDRA EXTENSIONS DIRECTORY.
if [[ -z "${GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR:-}" || ! -d "$GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR" ]]; then
    echo "ERROR: GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR not set or directory not found: ${GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR:-}"
    echo ""
    usage
fi

echo "GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR: $GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR"
echo ""

# FORCE STOP GHIDRA.
# TODO: This could lead to data loss! Make sure to warn about that or quit in a nicer fashion.
# However, this is fine for my current extension development.
if [[ "$NO_KILL" -eq 1 ]]; then
    echo "Skipping Ghidra kill..."
else
    echo "Force stopping Ghidra..."
    pkill -f ghidra || true
fi

echo "Building extension..."
rm -r dist/
gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"

# EXTRACT THE EXTENSION.
# Extracting directly in this location helps us avoid needing to manually re-install the extension
# every time something changes. However, for this to work the extension must have been manually installed
# once, so Ghidra knows to look for it in this location.
echo ""
echo "Extracting to user extensions..."
mkdir -p "$GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR"
cd "$GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR"
rm -rf "M68kMacLanguage/"  # Remove old version
cd -
unzip -o dist/*.zip -d "$GHIDRA_DIRECT_EXTENSION_INSTALLATION_DIR"

# RESTART GHIDRA.
echo ""
echo "Please restart Ghidra to load changes."
