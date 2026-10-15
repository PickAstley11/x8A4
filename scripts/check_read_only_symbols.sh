#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <library> <cli>" >&2
  exit 2
fi

library=$1
cli=$2
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
exports_file="$project_dir/x8A4.exports"
forbidden='_(kwrite|physwrite|kcall|kmalloc|kdealloc|write|writev|pwrite|pwritev|fwrite|unlink|remove|rmdir|rename|truncate|ftruncate|chmod|fchmod|chown|fchown|fsync|fdatasync|mkdir|symlink|link|mount|system|popen|execve|setenv)([^[:alnum:]_]|$)|IORegistryEntrySet|IOConnectCall|IOServiceOpen'
source_forbidden='(^|[^[:alnum:]_])(kwrite|physwrite|kcall|kmalloc|kdealloc|io_generate_apnonce|io_clear_apnonce|set_nvram_entry|x8A4_sync_nvram|x8A4_set_boot_nonce|x8A4_set_nonce_seeds|x8A4_set_apnonce_generator|x8A4_clear_apnonce_generator)([^[:alnum:]_]|$)|IORegistryEntrySet|IOConnectCall|set-apnonce-generator|clear-apnonce-generator|set-cryptex-nonce'

if grep -REn "$source_forbidden" "$project_dir/Kernel" "$project_dir/Registry" \
    "$project_dir/Services" "$project_dir/Logger" "$project_dir/Include/x8A4" \
    "$project_dir/x8A4.c" "$project_dir/x8A4_CLI.c"; then
  echo "Read-only source audit found a removed mutation API or operation." >&2
  exit 1
fi

for arch in arm64 arm64e; do
  for binary in "$library" "$cli"; do
    imports="$(nm -arch "$arch" -u "$binary")"
    if printf '%s\n' "$imports" | grep -E "$forbidden"; then
      echo "Unsafe import found in $binary ($arch)" >&2
      exit 1
    fi
  done

  actual="$(nm -arch "$arch" -gU "$library" | awk '{print $NF}' | sort)"
  expected="$(sort "$exports_file")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Unexpected x8A4 library exports for $arch" >&2
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true
    exit 1
  fi
done

echo "Read-only symbol audit passed for arm64 and arm64e."
