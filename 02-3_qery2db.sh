#!/usr/bin/env bash

set -Eeuo pipefail

cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-python}"
DB_PATH="${NVD_APPLICABILITY_DB:-workspace/nvd_applicability.sqlite}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "오류: Python 실행 파일을 찾을 수 없습니다: $PYTHON_BIN" >&2
    exit 2
fi

if [[ ! -r "$DB_PATH" ]]; then
    echo "오류: NVD applicability DB를 읽을 수 없습니다: $DB_PATH" >&2
    echo "먼저 ./02-1_run_build_db.sh를 실행하거나 NVD_APPLICABILITY_DB를 지정하세요." >&2
    exit 2
fi

exec "$PYTHON_BIN" utils/query2nvddb.py --db "$DB_PATH" "$@"
