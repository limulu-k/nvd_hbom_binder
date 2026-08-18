#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
MAPPING_SCRIPT="$PROJECT_DIR/scripts/build_git_repo_cve_mapping.py"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    printf 'Python 실행 파일을 찾을 수 없습니다: %s\n' "$PYTHON_BIN" >&2
    exit 2
fi
if [[ ! -f "$MAPPING_SCRIPT" ]]; then
    printf '매핑 스크립트를 찾을 수 없습니다: %s\n' "$MAPPING_SCRIPT" >&2
    exit 2
fi

command_args=("$PYTHON_BIN" -u "$MAPPING_SCRIPT")
case "${1:-}" in
    build|query|stats|-h|--help)
        ;;
    *)
        command_args+=(build)
        ;;
esac
command_args+=("$@")

printf '실행 명령:'
printf ' %q' "${command_args[@]}"
printf '\n'

exec "${command_args[@]}"
