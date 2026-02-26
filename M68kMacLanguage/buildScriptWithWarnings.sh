#!/usr/bin/env bash

# See https://appsec.at/blog/2023/07/31/ghidra-extension-development/.

usage() {
    cat << EOF
Usage: $0 SCRIPT_FILE [GHIDRA_INSTALL_DIR]

Builds a Ghidra script with additional warnings enabled.

Arguments:
  SCRIPT_FILE         Full path to the Java script to compile
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
            SCRIPT_FILE="$1"
            ;;
    esac
fi

# VALIDATE THE GHIDRA INSTALLATION DIRECTORY.
echo "GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR"
if [[ $# -gt 1 ]]; then
    GHIDRA_INSTALL_DIR="$2"
fi
if [[ -z "${GHIDRA_INSTALL_DIR:-}" || ! -d "$GHIDRA_INSTALL_DIR" ]]; then
    echo "ERROR: GHIDRA_INSTALL_DIR not set or directory not found"
    echo ""
    usage
fi

# VALIDATE THE SCRIPT FILE.
if [[ -z "${SCRIPT_FILE:-}" ||  ! -f "$SCRIPT_FILE" ]]; then
    echo "ERROR: SCRIPT_FILE not provided or not found"
    echo ""
    usage
fi

# BUILD A CLASSPATH FROM GHIDRA JARS.
CLASSPATH="$(find "$GHIDRA_INSTALL_DIR/Ghidra" "$GHIDRA_INSTALL_DIR/Framework" -name '*.jar' -print0 | tr '\0' ':')"

# TRY TO COMPILE THE SCRIPT.
echo "Compiling: $SCRIPT_FILE"
echo "Using Ghidra: $GHIDRA_INSTALL_DIR"
javac -Xlint:deprecation -Xlint:unchecked -Xdiags:verbose \
  -cp "$CLASSPATH" \
  "$SCRIPT_FILE"
