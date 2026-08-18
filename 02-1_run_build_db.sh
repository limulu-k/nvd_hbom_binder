#!/usr/bin/env bash

set -Eeuo pipefail

cd "$(dirname "$0")"

LOG_DIR="logs"
RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
LOG_FILE="${LOG_DIR}/execute_${RUN_TIMESTAMP}.log"
NVD_BUILD_INPUT="${NVD_BUILD_INPUT:-data/nvd-cves.current.jsonl}"

mkdir -p "$LOG_DIR"
mkdir -p workspace

if [[ ! -r "$NVD_BUILD_INPUT" ]]; then
    echo "오류: history-maintained NVD 입력을 읽을 수 없습니다: $NVD_BUILD_INPUT" >&2
    echo "먼저 ./01-1_update_nvd_data.sh를 실행하거나 NVD_BUILD_INPUT을 지정하세요." >&2
    exit 2
fi

# 각 출력 줄 앞에 timestamp를 추가한다.
timestamp_lines() {
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$line"
    done
}

CMD=(
    python -u -m scripts.nvd_normalization build
    --input "$NVD_BUILD_INPUT"
    --llm data/nvd-cves-desc_parse.jsonl
    --llm-fail data/nvd-cves-desc_parse-fail.jsonl
    --db workspace/nvd_applicability.sqlite
    --replace
    --progress-every 1000
)

echo "로그 파일: $LOG_FILE"

# Python의 종료 코드를 별도로 보존하기 위해 일시적으로 errexit를 해제한다.
set +e

{
    echo "============================================================"
    echo "NVD normalization build 시작"

    printf '실행 명령:'
    printf ' %q' "${CMD[@]}"
    printf '\n'

    echo "로그 파일: $LOG_FILE"
    echo "============================================================"

    "${CMD[@]}"
    exit_code=$?

    echo "============================================================"
    echo "NVD normalization build 종료"
    echo "종료 코드: $exit_code"
    echo "============================================================"

    exit "$exit_code"
} 2>&1 | timestamp_lines | tee -a "$LOG_FILE"

# PIPESTATUS[0]은 위 중괄호 블록, 즉 Python 명령의 최종 종료 코드다.
exit_code=${PIPESTATUS[0]}

set -e
exit "$exit_code"
