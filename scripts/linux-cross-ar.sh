#!/bin/sh
exec "${REDTRACE_ZIG:?Set REDTRACE_ZIG to the Zig executable}" ar "$@"
