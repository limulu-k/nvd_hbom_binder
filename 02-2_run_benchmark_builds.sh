#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BENCHMARK_DIR="${BENCHMARK_DIR:-workspace/benchmark}"
LOG_DIR="${BENCHMARK_DIR}/logs"
SUMMARY_DIR="${BENCHMARK_DIR}/build_summaries"
METRICS_DIR="${BENCHMARK_DIR}/metrics"
REPORT_DIR="${BENCHMARK_DIR}/reports"
EVALUATION_DIR="${BENCHMARK_DIR}/evaluation"
VISUALIZATION_DIR="${BENCHMARK_DIR}/visualizations"
ANALYSIS_DIR="${BENCHMARK_DIR}/analysis"
RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

PYTHON_BIN="${PYTHON_BIN:-python3}"
SQLITE_BIN="${SQLITE_BIN:-sqlite3}"
JQ_BIN="${JQ_BIN:-jq}"
PROGRESS_EVERY="${PROGRESS_EVERY:-1000}"
EVALUATION_PROGRESS_EVERY="${EVALUATION_PROGRESS_EVERY:-25}"
HISTORY_CONFLICT_JOBS="${HISTORY_CONFLICT_JOBS:-4}"
# 빠른 검증 예: BENCHMARK_LIMIT=1000 ./03_run_benchmark_builds.sh
BENCHMARK_LIMIT="${BENCHMARK_LIMIT:-}"

NVD_ORIGINAL="${NVD_ORIGINAL:-data/nvd-cves.jsonl}"
NVD_CURRENT="${NVD_CURRENT:-data/nvd-cves.current.jsonl}"
LLM_SUCCESS="${LLM_SUCCESS:-data/nvd-cves-desc_parse.jsonl}"
LLM_FAILURE="${LLM_FAILURE:-data/nvd-cves-desc_parse-fail.jsonl}"
EVALUATION_GOLD="${EVALUATION_GOLD:-data/nvd_labeling_250_v2.jsonl}"
EVALUATION_SCRIPT="${EVALUATION_SCRIPT:-utils/evaluate_nvd_labeling_250.py}"
VISUALIZATION_SCRIPT="${VISUALIZATION_SCRIPT:-utils/visualize_evaluation.py}"
EVALUATION_PREFIX="${EVALUATION_PREFIX:-nvd_labeling_250_v2}"
NVD_HISTORY="${NVD_HISTORY:-data/nvd-cve-history/nvd-cve-history.jsonl.gz}"
CONFLICT_ANALYSIS_SCRIPT="${CONFLICT_ANALYSIS_SCRIPT:-utils/analysis/cve_cpe_conflicts.py}"
HISTORY_POLICY_SCRIPT="${HISTORY_POLICY_SCRIPT:-utils/analysis/build_history_conflict_policy.py}"
HISTORY_CONFLICT_DETAILS="${HISTORY_CONFLICT_DETAILS:-${ANALYSIS_DIR}/history_policy_cve_conflicts.jsonl}"
HISTORY_CONFLICT_SUMMARY="${HISTORY_CONFLICT_SUMMARY:-${ANALYSIS_DIR}/history_policy_cve_conflicts.json}"
HISTORY_CONFLICT_POLICY="${HISTORY_CONFLICT_POLICY:-${ANALYSIS_DIR}/history_conflict_policy.jsonl}"
HISTORY_CONFLICT_REPORT="${HISTORY_CONFLICT_REPORT:-${ANALYSIS_DIR}/history_conflict_policy_report.json}"

mkdir -p \
    "$LOG_DIR" \
    "$SUMMARY_DIR" \
    "$METRICS_DIR" \
    "$REPORT_DIR" \
    "$EVALUATION_DIR" \
    "$VISUALIZATION_DIR" \
    "$ANALYSIS_DIR"

timestamp_lines() {
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$line"
    done
}

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "필수 명령을 찾을 수 없습니다: $command_name" >&2
        exit 2
    fi
}

require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "입력 파일을 찾을 수 없습니다: $path" >&2
        exit 2
    fi
}

require_command "$PYTHON_BIN"
require_command "$SQLITE_BIN"
require_command "$JQ_BIN"
require_file "$NVD_ORIGINAL"
require_file "$NVD_CURRENT"
require_file "$LLM_SUCCESS"
require_file "$LLM_FAILURE"
require_file "$EVALUATION_GOLD"
require_file "$EVALUATION_SCRIPT"
require_file "$VISUALIZATION_SCRIPT"
require_file "$NVD_HISTORY"
require_file "$CONFLICT_ANALYSIS_SCRIPT"
require_file "$HISTORY_POLICY_SCRIPT"

if [[ ! "$PROGRESS_EVERY" =~ ^[0-9]+$ ]]; then
    echo "PROGRESS_EVERY는 0 이상의 정수여야 합니다: $PROGRESS_EVERY" >&2
    exit 2
fi
if [[ -n "$BENCHMARK_LIMIT" ]] && [[ ! "$BENCHMARK_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
    echo "BENCHMARK_LIMIT는 양의 정수여야 합니다: $BENCHMARK_LIMIT" >&2
    exit 2
fi
if [[ ! "$EVALUATION_PROGRESS_EVERY" =~ ^[0-9]+$ ]]; then
    echo "EVALUATION_PROGRESS_EVERY는 0 이상의 정수여야 합니다: $EVALUATION_PROGRESS_EVERY" >&2
    exit 2
fi

extract_results() {
    local build_id="$1"
    local input_path="$2"
    local llm_enabled="$3"
    local database_path="$4"
    local summary_path="${SUMMARY_DIR}/${build_id}.json"
    local metrics_path="${METRICS_DIR}/${build_id}.json"
    local temporary_summary="${summary_path}.tmp"
    local temporary_metrics="${metrics_path}.tmp"
    local database_bytes

    database_bytes="$(stat -c '%s' "$database_path")"

    "$SQLITE_BIN" -readonly "$database_path" \
        "SELECT summary_json FROM pipeline_run ORDER BY pipeline_run_id DESC LIMIT 1" \
        | "$JQ_BIN" '.' > "$temporary_summary"
    mv -f "$temporary_summary" "$summary_path"

    "$SQLITE_BIN" -readonly -json "$database_path" "
        SELECT
            (SELECT status FROM pipeline_run
              ORDER BY pipeline_run_id DESC LIMIT 1) AS pipeline_status,
            (SELECT value FROM metadata
              WHERE key='publish_health') AS publish_health,
            (SELECT record_count FROM pipeline_run
              ORDER BY pipeline_run_id DESC LIMIT 1) AS published_cve_count,
            (SELECT issue_count FROM pipeline_run
              ORDER BY pipeline_run_id DESC LIMIT 1) AS normalization_issue_count,
            (SELECT COUNT(*) FROM raw_cve) AS raw_cve_count,
            (SELECT COUNT(*) FROM raw_cve
              WHERE admission_status='rejected_upstream') AS rejected_upstream_count,
            (SELECT COUNT(*) FROM source_claim) AS source_claim_count,
            (SELECT COUNT(*) FROM product_entity) AS product_entity_count,
            (SELECT COUNT(*) FROM product_alias) AS product_alias_count,
            (SELECT COUNT(*) FROM applicability_assertion) AS assertion_count,
            (SELECT COUNT(*) FROM applicability_assertion
              WHERE reconciliation_status='active') AS active_assertion_count,
            (SELECT COUNT(*) FROM cve_applicability_binding) AS binding_count,
            (SELECT COUNT(*) FROM binding_assertion_member
              WHERE is_active=1) AS active_binding_assertion_count,
            (SELECT COUNT(*) FROM cve_applicability_binding
              WHERE provisional_llm_identity=1) AS provisional_llm_binding_count,
            (SELECT COUNT(*) FROM llm_result) AS llm_result_count,
            (SELECT COUNT(*) FROM llm_claim) AS llm_claim_count,
            (SELECT COUNT(*) FROM llm_claim
              WHERE axis='vendor') AS llm_vendor_claim_count,
            (SELECT COUNT(*) FROM llm_claim
              WHERE axis='product') AS llm_product_claim_count,
            (SELECT COUNT(*) FROM llm_claim
              WHERE axis='version') AS llm_version_claim_count,
            (SELECT COUNT(*) FROM normalization_issue
              WHERE failure_code='F-LLM-04') AS llm_issue_count,
            (SELECT COUNT(*) FROM normalization_issue
              WHERE failure_code='F-LLM-04'
                AND details_json LIKE '%description_missing_or_stale%')
                AS llm_stale_description_count;
    " | "$JQ_BIN" \
        --arg build_id "$build_id" \
        --arg input "$input_path" \
        --argjson llm_enabled "$llm_enabled" \
        --argjson database_bytes "$database_bytes" \
        '.[0] + {
            build_id: $build_id,
            input: $input,
            llm_enabled: $llm_enabled,
            database_bytes: $database_bytes
        }' > "$temporary_metrics"
    mv -f "$temporary_metrics" "$metrics_path"
}

run_build() {
    local build_id="$1"
    local input_path="$2"
    local llm_enabled="$3"
    local database_path="${BENCHMARK_DIR}/${build_id}.sqlite"
    local log_path="${LOG_DIR}/${build_id}_${RUN_TIMESTAMP}.log"
    local command=(
        "$PYTHON_BIN" -u -m scripts.nvd_normalization build
        --input "$input_path"
        --db "$database_path"
        --replace
        --progress-every "$PROGRESS_EVERY"
    )

    if [[ "$llm_enabled" == "true" ]]; then
        command+=(--llm "$LLM_SUCCESS" --llm-fail "$LLM_FAILURE")
    else
        command+=(--without-llm)
    fi
    if [[ -n "$BENCHMARK_LIMIT" ]]; then
        command+=(--limit "$BENCHMARK_LIMIT")
    fi

    echo "[$build_id] 시작: $log_path"
    set +e
    {
        echo "============================================================"
        echo "benchmark build 시작"
        echo "build_id: $build_id"
        echo "input: $input_path"
        echo "llm_enabled: $llm_enabled"
        printf '실행 명령:'
        printf ' %q' "${command[@]}"
        printf '\n'
        echo "============================================================"

        "${command[@]}"
        exit_code=$?

        echo "============================================================"
        echo "benchmark build 종료"
        echo "종료 코드: $exit_code"
        echo "============================================================"
        exit "$exit_code"
    } 2>&1 | timestamp_lines | tee "$log_path"
    local exit_code=${PIPESTATUS[0]}
    set -e

    if (( exit_code != 0 )); then
        echo "[$build_id] 실패했습니다. 로그: $log_path" >&2
        exit "$exit_code"
    fi

    extract_results "$build_id" "$input_path" "$llm_enabled" "$database_path"
    echo "[$build_id] 완료: $database_path"
}

run_evaluation_and_visualization() {
    local build_id="$1"
    local previous_build_id="${2:-}"
    local database_path="${BENCHMARK_DIR}/${build_id}.sqlite"
    local evaluation_output_dir="${EVALUATION_DIR}/${build_id}"
    local visualization_output_dir="${VISUALIZATION_DIR}/${build_id}"
    local evaluation_log="${LOG_DIR}/${build_id}_evaluation_${RUN_TIMESTAMP}.log"
    local visualization_log="${LOG_DIR}/${build_id}_visualization_${RUN_TIMESTAMP}.log"
    local evaluation_json="${evaluation_output_dir}/${EVALUATION_PREFIX}_evaluation.json"
    local cases_jsonl="${evaluation_output_dir}/${EVALUATION_PREFIX}_evaluation_cases.jsonl"
    local errors_csv="${evaluation_output_dir}/${EVALUATION_PREFIX}_cve_errors.csv"
    local previous_evaluation="${evaluation_output_dir}/.no_previous_evaluation.json"
    local metrics_path="${METRICS_DIR}/${build_id}.json"
    local temporary_metrics="${metrics_path}.tmp"
    local evaluation_command=(
        "$PYTHON_BIN" -u "$EVALUATION_SCRIPT"
        --db "$database_path"
        --gold "$EVALUATION_GOLD"
        --output-dir "$evaluation_output_dir"
        --output-prefix "$EVALUATION_PREFIX"
        --progress-every "$EVALUATION_PROGRESS_EVERY"
    )
    if [[ "$build_id" == 03_* || "$build_id" == 04_* ]]; then
        require_file "$HISTORY_CONFLICT_POLICY"
        evaluation_command+=(
            --history-conflict-policy "$HISTORY_CONFLICT_POLICY"
        )
    fi

    mkdir -p "$evaluation_output_dir" "$visualization_output_dir"
    if [[ -n "$previous_build_id" ]]; then
        previous_evaluation="${EVALUATION_DIR}/${previous_build_id}/${EVALUATION_PREFIX}_evaluation.json"
        require_file "$previous_evaluation"
    fi

    echo "[$build_id] labeling-250 평가 시작: $evaluation_log"
    set +e
    "${evaluation_command[@]}" 2>&1 \
        | timestamp_lines \
        | tee "$evaluation_log"
    local evaluation_exit_code=${PIPESTATUS[0]}
    set -e
    if ((evaluation_exit_code != 0)); then
        echo "[$build_id] 평가가 실패했습니다. 로그: $evaluation_log" >&2
        exit "$evaluation_exit_code"
    fi
    require_file "$evaluation_json"
    require_file "$cases_jsonl"
    require_file "$errors_csv"

    local visualization_command=(
        "$PYTHON_BIN" -u "$VISUALIZATION_SCRIPT"
        --evaluation "$evaluation_json"
        --cases "$cases_jsonl"
        --errors "$errors_csv"
        --previous-evaluation "$previous_evaluation"
        --output-dir "$visualization_output_dir"
    )
    echo "[$build_id] 평가 시각화 시작: $visualization_log"
    set +e
    "${visualization_command[@]}" 2>&1 \
        | timestamp_lines \
        | tee "$visualization_log"
    local visualization_exit_code=${PIPESTATUS[0]}
    set -e
    if ((visualization_exit_code != 0)); then
        echo "[$build_id] 시각화가 실패했습니다. 로그: $visualization_log" >&2
        exit "$visualization_exit_code"
    fi
    require_file "${visualization_output_dir}/v10_analysis_summary.json"

    "$JQ_BIN" \
        --slurpfile evaluation "$evaluation_json" \
        --arg evaluation_dir "$evaluation_output_dir" \
        --arg visualization_dir "$visualization_output_dir" \
        '. + {
            labeling_250: {
                dataset: $evaluation[0].dataset,
                overall: $evaluation[0].overall,
                false_negative_state_totals:
                    $evaluation[0].false_negative_state_totals,
                timing: $evaluation[0].timing,
                files: $evaluation[0].files,
                evaluation_dir: $evaluation_dir,
                visualization_dir: $visualization_dir
            }
        }' "$metrics_path" > "$temporary_metrics"
    mv -f "$temporary_metrics" "$metrics_path"
    echo "[$build_id] 평가·시각화 완료: $visualization_output_dir"
}

build_history_conflict_policy() {
    local conflict_log="${LOG_DIR}/history_conflict_analysis_${RUN_TIMESTAMP}.log"
    local policy_log="${LOG_DIR}/history_conflict_policy_${RUN_TIMESTAMP}.log"
    local conflict_command=(
        "$PYTHON_BIN" -u "$CONFLICT_ANALYSIS_SCRIPT"
        --input "$NVD_CURRENT"
        --jobs "$HISTORY_CONFLICT_JOBS"
        --samples 0
        --details "$HISTORY_CONFLICT_DETAILS"
        --json-out "$HISTORY_CONFLICT_SUMMARY"
    )
    if [[ -n "$BENCHMARK_LIMIT" ]]; then
        conflict_command+=(--limit "$BENCHMARK_LIMIT")
    fi

    echo "[history-policy] CNA/CPE 충돌 분석 시작: $conflict_log"
    "${conflict_command[@]}" 2>&1 | timestamp_lines | tee "$conflict_log"
    require_file "$HISTORY_CONFLICT_DETAILS"

    echo "[history-policy] history 정책 생성 시작: $policy_log"
    "$PYTHON_BIN" -u "$HISTORY_POLICY_SCRIPT" \
        --conflicts "$HISTORY_CONFLICT_DETAILS" \
        --history "$NVD_HISTORY" \
        --output "$HISTORY_CONFLICT_POLICY" \
        --report "$HISTORY_CONFLICT_REPORT" \
        2>&1 | timestamp_lines | tee "$policy_log"
    require_file "$HISTORY_CONFLICT_POLICY"
    require_file "$HISTORY_CONFLICT_REPORT"
}

numeric_delta_filter='def numeric_delta($before; $after):
    reduce ($after | keys_unsorted[]) as $key
        ({};
         if (($after[$key] | type) == "number"
             and ($before[$key] | type) == "number")
         then .[$key] = ($after[$key] - $before[$key])
         else .
         end);'

make_comparison() {
    local case_id="$1"
    local description="$2"
    local before_path="$3"
    local after_path="$4"
    local output_path="$5"
    local temporary_output="${output_path}.tmp"

    "$JQ_BIN" -n \
        --arg case_id "$case_id" \
        --arg description "$description" \
        --slurpfile before "$before_path" \
        --slurpfile after "$after_path" \
        "${numeric_delta_filter}
        {
            case_id: \$case_id,
            description: \$description,
            before: \$before[0],
            after: \$after[0],
            numeric_delta: numeric_delta(\$before[0]; \$after[0])
        }" > "$temporary_output"
    mv -f "$temporary_output" "$output_path"
}

# 네 가지 고유 조합. 01은 case 1과 case 2의 공통 baseline이다.
run_build "01_nvd_without_llm" "$NVD_ORIGINAL" false
run_build "02_nvd_with_llm" "$NVD_ORIGINAL" true
run_build "03_current_without_llm" "$NVD_CURRENT" false
run_build "04_current_with_llm" "$NVD_CURRENT" true

# History 정책은 current DB 평가에만 적용한다. 원본 NVD 두 baseline은 기존
# conflict_review/inclusive 동작을 유지한다.
build_history_conflict_policy

# 각 DB를 동일 gold set으로 평가하고 독립된 디렉터리에 시각화한다.
# 이전 평가 연결은 각 비교 축과 일치시킨다.
run_evaluation_and_visualization "01_nvd_without_llm"
run_evaluation_and_visualization "02_nvd_with_llm" "01_nvd_without_llm"
run_evaluation_and_visualization "03_current_without_llm" "01_nvd_without_llm"
run_evaluation_and_visualization "04_current_with_llm" "03_current_without_llm"

CASE1_REPORT="${REPORT_DIR}/case1_llm_before_after_history_before.json"
CASE2_REPORT="${REPORT_DIR}/case2_history_before_after_without_llm.json"
CASE3_REPORT="${REPORT_DIR}/case3_history_with_llm.json"
FINAL_REPORT="${BENCHMARK_DIR}/benchmark_report.json"

make_comparison \
    "case1" \
    "history 적용 전 NVD에서 LLM parser 미사용/사용 비교" \
    "${METRICS_DIR}/01_nvd_without_llm.json" \
    "${METRICS_DIR}/02_nvd_with_llm.json" \
    "$CASE1_REPORT"

make_comparison \
    "case2" \
    "LLM parser 미사용 상태에서 history 적용 전/후 비교" \
    "${METRICS_DIR}/01_nvd_without_llm.json" \
    "${METRICS_DIR}/03_current_without_llm.json" \
    "$CASE2_REPORT"

make_comparison \
    "case3" \
    "원본 NVD/LLM 미사용 기준과 history+LLM 동시 사용 결과 비교" \
    "${METRICS_DIR}/01_nvd_without_llm.json" \
    "${METRICS_DIR}/04_current_with_llm.json" \
    "$CASE3_REPORT"

"$JQ_BIN" -n \
    --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg benchmark_dir "$BENCHMARK_DIR" \
    --arg limit "${BENCHMARK_LIMIT:-full}" \
    --slurpfile case1 "$CASE1_REPORT" \
    --slurpfile case2 "$CASE2_REPORT" \
    --slurpfile case3 "$CASE3_REPORT" \
    '{
        generated_at: $generated_at,
        benchmark_dir: $benchmark_dir,
        limit: $limit,
        cases: [$case1[0], $case2[0], $case3[0]]
    }' > "${FINAL_REPORT}.tmp"
mv -f "${FINAL_REPORT}.tmp" "$FINAL_REPORT"

echo "============================================================"
echo "모든 benchmark build가 완료되었습니다."
echo "통합 결과: $FINAL_REPORT"
echo "개별 비교: $REPORT_DIR"
echo "빌드 요약: $SUMMARY_DIR"
echo "DB 지표: $METRICS_DIR"
echo "평가 결과: $EVALUATION_DIR"
echo "시각화: $VISUALIZATION_DIR"
echo "로그: $LOG_DIR"
echo "============================================================"
