#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
REPO_CVE_DB="${REPO_CVE_DB:-$PROJECT_DIR/workspace/repo_cve.sqlite}"
QUERY_SCRIPT="$PROJECT_DIR/scripts/query_repo_cve.py"

usage() {
    printf '%s\n' \
        "사용법:" \
        "  ./05_query_repo_cve.sh <owner@repo> <version> [query_repo_cve 옵션...]" \
        "" \
        "예시:" \
        "  ./05_query_repo_cve.sh HDFGroup@hdf5 1.8.10" \
        "  ./05_query_repo_cve.sh HDFGroup@hdf5 1.14.6 --all-states" \
        "  ./05_query_repo_cve.sh HDFGroup@hdf5 1.8.10 --cve CVE-2016-4330" \
        "  ./05_query_repo_cve.sh wolfSSL@wolfssl 5.7.0 --format json" \
        "  ./05_query_repo_cve.sh HDFGroup@hdf5 1.8.10 --policy strict --format json" \
        "" \
        "환경변수:" \
        "  PYTHON_BIN       Python 실행 파일 (기본: python)" \
        "  REPO_CVE_DB      조회 DB (기본: workspace/repo_cve.sqlite)"
}

if [[ $# -eq 1 && ("$1" == "-h" || "$1" == "--help") ]]; then
    usage
    exit 0
fi
if [[ $# -lt 2 ]]; then
    usage >&2
    exit 2
fi

repo_key="$1"
version="$2"
shift 2

if [[ ! "$repo_key" =~ ^[^@]+@[^@]+$ ]]; then
    printf '저장소는 owner@repo 형식이어야 합니다: %s\n' "$repo_key" >&2
    exit 2
fi
if [[ -z "$version" ]]; then
    printf '버전을 입력해야 합니다.\n' >&2
    exit 2
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    printf 'Python 실행 파일을 찾을 수 없습니다: %s\n' "$PYTHON_BIN" >&2
    exit 2
fi
if [[ ! -f "$QUERY_SCRIPT" ]]; then
    printf '쿼리 스크립트를 찾을 수 없습니다: %s\n' "$QUERY_SCRIPT" >&2
    exit 2
fi
if [[ ! -f "$REPO_CVE_DB" ]]; then
    printf 'DB를 찾을 수 없습니다: %s\n' "$REPO_CVE_DB" >&2
    exit 2
fi

command_args=(
    "$PYTHON_BIN" -u "$QUERY_SCRIPT"
    "$repo_key"
    --version "$version"
    --db "$REPO_CVE_DB"
)
command_args+=("$@")

printf '실행 명령:'
printf ' %q' "${command_args[@]}"
printf '\n'

exec "${command_args[@]}"
