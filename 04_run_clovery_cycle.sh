#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
SOURCE_JSONL="${SOURCE_JSONL:-/home/flba/korea_univ/cve_binder_llm/data/nvd-cves.current.jsonl}"
OSV_DIR="${OSV_DIR:-/home/flba/korea_univ/cve_binder_llm/data/osv}"
CLOVERY_DB="${CLOVERY_DB:-}"
CLOVERY_STEP_TIMEOUT="${CLOVERY_STEP_TIMEOUT:-21600}"
CLOVERY_MAX_CPG_PAIRS="${CLOVERY_MAX_CPG_PAIRS:-5000}"
CLOVERY_FULL_CLONE="${CLOVERY_FULL_CLONE:-1}"

usage() {
    printf '%s\n' \
        "사용법:" \
        "  ./04_run_clovery_cycle.sh [run] [clovery_cycle run 옵션...]" \
        "  ./04_run_clovery_cycle.sh plan [clovery_cycle plan 옵션...]" \
        "  ./04_run_clovery_cycle.sh status [clovery_cycle status 옵션...]" \
        "" \
        "예시:" \
        "  ./04_run_clovery_cycle.sh" \
        "  ./04_run_clovery_cycle.sh --only HDFGroup@hdf5" \
        "  ./04_run_clovery_cycle.sh run --retry-failed --only HDFGroup@hdf5" \
        "  ./04_run_clovery_cycle.sh plan" \
        "  ./04_run_clovery_cycle.sh status -v" \
        "" \
        "환경변수:" \
        "  PYTHON_BIN                 Python 실행 파일 (기본: python)" \
        "  SOURCE_JSONL               NVD current JSONL 경로" \
        "  OSV_DIR                    OSV mirror 경로" \
        "  CLOVERY_DB                 applicability DB 경로 (미지정 시 cycle 자동 선택)" \
        "  CLOVERY_STEP_TIMEOUT       단계 제한시간 초 (기본: 21600)" \
        "  CLOVERY_MAX_CPG_PAIRS      CPG pair 제한 (기본: 5000)" \
        "  CLOVERY_FULL_CLONE         1이면 --full-clone 사용 (기본: 1)"
}

require_file() {
    local target_path="$1"
    if [[ ! -f "$target_path" ]]; then
        printf '파일을 찾을 수 없습니다: %s\n' "$target_path" >&2
        exit 2
    fi
}

require_directory() {
    local target_path="$1"
    if [[ ! -d "$target_path" ]]; then
        printf '디렉터리를 찾을 수 없습니다: %s\n' "$target_path" >&2
        exit 2
    fi
}

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    printf 'Python 실행 파일을 찾을 수 없습니다: %s\n' "$PYTHON_BIN" >&2
    exit 2
fi

CYCLE_SCRIPT="$PROJECT_DIR/scripts/clovery/clovery_cycle.py"
require_file "$CYCLE_SCRIPT"

subcommand="run"
if [[ $# -gt 0 ]]; then
    case "$1" in
        plan|run|status)
            subcommand="$1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
    esac
fi

command_args=("$PYTHON_BIN" -u "$CYCLE_SCRIPT")

case "$subcommand" in
    plan)
        require_file "$SOURCE_JSONL"
        require_directory "$OSV_DIR"
        command_args+=(
            plan
            --source-jsonl "$SOURCE_JSONL"
            --osv-dir "$OSV_DIR"
        )
        if [[ -n "$CLOVERY_DB" ]]; then
            require_file "$CLOVERY_DB"
            command_args+=(--db "$CLOVERY_DB")
        fi
        ;;
    run)
        require_file "$SOURCE_JSONL"
        require_directory "$OSV_DIR"
        command_args+=(
            run
            --retry-failed
            --step-timeout "$CLOVERY_STEP_TIMEOUT"
            --max-cpg-pairs "$CLOVERY_MAX_CPG_PAIRS"
            --source-jsonl "$SOURCE_JSONL"
            --osv-dir "$OSV_DIR"
        )
        if [[ "$CLOVERY_FULL_CLONE" == "1" ]]; then
            command_args+=(--full-clone)
        elif [[ "$CLOVERY_FULL_CLONE" != "0" ]]; then
            printf 'CLOVERY_FULL_CLONE은 0 또는 1이어야 합니다: %s\n' \
                "$CLOVERY_FULL_CLONE" >&2
            exit 2
        fi
        if [[ -n "$CLOVERY_DB" ]]; then
            require_file "$CLOVERY_DB"
            command_args+=(--db "$CLOVERY_DB")
        fi
        ;;
    status)
        command_args+=(status)
        ;;
esac

command_args+=("$@")

printf '실행 명령:'
printf ' %q' "${command_args[@]}"
printf '\n'

exec "${command_args[@]}"
