#!/usr/bin/env bash

# This allows us to update the data files in the repo while having
# the edits take effect immediately for Ghidra.

GHIDRA_INSTALL_DIR="/opt/homebrew/Caskroom/ghidra/11.4-20250620/ghidra_11.4_PUBLIC"
GHIDRA_DATA_DIR="$GHIDRA_INSTALL_DIR/Ghidra/Features/Base/data"
GHIDRA_PROCESSOR_M68K_DIR="$GHIDRA_INSTALL_DIR/Ghidra/Processors/68000/data/languages"

ln -sf "$PWD/data/m68k_mac_fp68k" "$GHIDRA_DATA_DIR/"
ln -sf "$PWD/data/m68k_mac_syscalls" "$GHIDRA_DATA_DIR/"
ln -sf "$PWD/data/m68k_mac_system_globals" "$GHIDRA_DATA_DIR/"

ln -sf "$PWD/processor/68000_mac_codewarrior.cspec" "$GHIDRA_PROCESSOR_M68K_DIR/"
ln -sf "$PWD/processor/68000_mac.sla" "$GHIDRA_PROCESSOR_M68K_DIR/"
ln -sf "$PWD/processor/68000_mac.slaspec" "$GHIDRA_PROCESSOR_M68K_DIR/"
ln -sf "$PWD/processor/68000-mac.cspec" "$GHIDRA_PROCESSOR_M68K_DIR/"
ln -sf "$PWD/processor/68000.ldefs" "$GHIDRA_PROCESSOR_M68K_DIR/"
