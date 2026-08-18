#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
TORCHRUN_BIN="${TORCHRUN_BIN:-torchrun}"
QWEN_NPROC_PER_NODE="${QWEN_NPROC_PER_NODE:-1}"
TRAIN_SCRIPT="$PROJECT_DIR/scripts/train_qwen_cve_bindings.py"

if [[ ! "$QWEN_NPROC_PER_NODE" =~ ^[1-9][0-9]*$ ]]; then
    printf 'QWEN_NPROC_PER_NODE는 양의 정수여야 합니다: %s\n' \
        "$QWEN_NPROC_PER_NODE" >&2
    exit 2
fi
if [[ ! -f "$TRAIN_SCRIPT" ]]; then
    printf '학습 스크립트를 찾을 수 없습니다: %s\n' "$TRAIN_SCRIPT" >&2
    exit 2
fi

if (( QWEN_NPROC_PER_NODE == 1 )); then
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        printf 'Python 실행 파일을 찾을 수 없습니다: %s\n' "$PYTHON_BIN" >&2
        exit 2
    fi
    command_args=("$PYTHON_BIN" -u "$TRAIN_SCRIPT")
else
    if ! command -v "$TORCHRUN_BIN" >/dev/null 2>&1; then
        printf 'torchrun 실행 파일을 찾을 수 없습니다: %s\n' "$TORCHRUN_BIN" >&2
        exit 2
    fi
    command_args=(
        "$TORCHRUN_BIN"
        --standalone
        "--nproc-per-node=$QWEN_NPROC_PER_NODE"
        "$TRAIN_SCRIPT"
    )
fi
command_args+=("$@")

printf '실행 명령:'
printf ' %q' "${command_args[@]}"
printf '\n'

exec "${command_args[@]}"
