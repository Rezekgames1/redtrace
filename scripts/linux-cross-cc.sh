#!/bin/bash
# cc-rs supplies Rust's four-part triple; Zig uses x86_64-linux-gnu.
compiler_args=()
for compiler_arg in "$@"; do
  case "$compiler_arg" in
    --target=x86_64-unknown-linux-gnu) ;;
    *) compiler_args+=("$compiler_arg") ;;
  esac
done
exec "${REDTRACE_ZIG:?Set REDTRACE_ZIG to the Zig executable}" cc -target x86_64-linux-gnu "${compiler_args[@]}"
