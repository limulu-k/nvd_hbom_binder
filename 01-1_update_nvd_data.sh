#!/usr/bin/env bash

set -Eeuo pipefail

cd "$(dirname "$0")"

FEED_DIR="${NVD_FEED_DIR:-nvd-json-2.0}"
OUTPUT_FILE="${NVD_JSONL_FILE:-data/nvd-cves.jsonl}"
BASE_URL="${NVD_FEED_BASE_URL:-https://nvd.nist.gov/feeds/json/cve/2.0}"
START_YEAR="${NVD_START_YEAR:-2002}"
END_YEAR="${NVD_END_YEAR:-$(date -u '+%Y')}"
LOCK_FILE="${NVD_UPDATE_LOCK_FILE:-workspace/update_nvd_data.lock}"
MERGE_SCRIPT="${NVD_MERGE_SCRIPT:-utils/merge_nvd_cves.py}"
HISTORY_SCRIPT="${NVD_HISTORY_SCRIPT:-utils/download_nvd_cve_history.py}"
MAINTENANCE_SCRIPT="${NVD_MAINTENANCE_SCRIPT:-utils/maintain_nvd_cves.py}"
LLM_UPDATE_SCRIPT="${NVD_LLM_UPDATE_SCRIPT:-utils/update_nvd_llm_parsed.py}"
LLM_INFERENCE_SCRIPT="${NVD_LLM_INFERENCE_SCRIPT:-scripts/infer_nvd_cve_bindings.py}"
HISTORY_DIR="${NVD_HISTORY_DIR:-data/nvd-cve-history}"
HISTORY_API_KEY_ENV="${NVD_HISTORY_API_KEY_ENV:-NVD_API_KEY}"
HISTORY_PAGE_SIZE="${NVD_HISTORY_PAGE_SIZE:-5000}"
HISTORY_REQUEST_DELAY="${NVD_HISTORY_REQUEST_DELAY:-6.0}"
CURRENT_OUTPUT="${NVD_CURRENT_JSONL_FILE:-data/nvd-cves.current.jsonl}"
CURRENT_REPORT="${NVD_CURRENT_REPORT_FILE:-data/nvd-cves.current.report.json}"
CURRENT_QUARANTINE="${NVD_CURRENT_QUARANTINE_FILE:-data/nvd-cves.current.quarantine.jsonl}"
SNAPSHOT_AS_OF="${NVD_SNAPSHOT_AS_OF:-}"
LLM_INPUT="${NVD_LLM_INPUT_FILE:-}"
LLM_PARSED_OUTPUT="${NVD_LLM_PARSED_FILE:-data/nvd-cves-desc_parse.jsonl}"
LLM_FAIL_OUTPUT="${NVD_LLM_FAIL_FILE:-data/nvd-cves-desc_parse-fail.jsonl}"
LLM_ADAPTER="${NVD_LLM_ADAPTER:-models/qwen3-merged800-20260723-155213}"
LLM_NPROC_PER_NODE="${NVD_LLM_NPROC_PER_NODE:-1}"
LLM_BATCH_SIZE="${NVD_LLM_BATCH_SIZE:-2}"
LLM_MAX_INPUT_TOKENS="${NVD_LLM_MAX_INPUT_TOKENS:-4096}"
LLM_MAX_NEW_TOKENS="${NVD_LLM_MAX_NEW_TOKENS:-512}"
PYTHON_BIN="${PYTHON_BIN:-python}"
CURL_BIN="${CURL_BIN:-curl}"
TORCHRUN_BIN="${TORCHRUN_BIN:-torchrun}"

FORCE_DOWNLOAD=0
FORCE_MERGE=0
MERGE_JSONL=1
UPDATE_HISTORY=1
BUILD_CURRENT=1
VERIFY_HISTORY=0
UPDATE_LLM_PARSED=0
CURRENT_EXTRA_INPUTS=()

usage() {
    cat <<'EOF'
Usage: ./01-1_update_nvd_data.sh [options]

Download changed official NVD CVE JSON 2.0 feeds, rebuild the merged CVE
JSONL, resume/update the complete CVE Change History dataset, and publish a
history-maintained current-only JSONL. Newer CPE details replace overlapping
ranges, retain disjoint ranges, and remove deprecated/removed matches.

Options:
  --feed-dir DIR       Decompressed NVD JSON directory (default: nvd-json-2.0)
  --output FILE        Merged JSONL output (default: data/nvd-cves.jsonl)
  --base-url URL       Feed base URL (primarily useful for testing)
  --start-year YEAR    First annual feed (default: 2002)
  --end-year YEAR      Last annual feed (default: current UTC year)
  --force-download     Download feeds even when local metadata matches
  --force-merge        Rebuild JSONL even when the feed manifest is unchanged
  --no-merge           Do not rebuild the merged CVE JSONL or current JSONL
  --history-dir DIR    Change History pages/manifest/output directory
                       (default: data/nvd-cve-history)
  --history-api-key-env NAME
                       Environment variable containing the NVD API key
                       (default: NVD_API_KEY)
  --history-page-size N
                       Change History API page size (default: 5000)
  --history-request-delay SEC
                       Minimum delay between history requests (default: 6.0)
  --verify-history     Validate all saved history pages before resuming
  --no-history         Do not call the Change History downloader; use the
                       existing merged history file for current maintenance
  --no-current         Do not build current/quarantine/report JSONL artifacts
  --current-output FILE
                       Current-only JSONL (default: data/nvd-cves.current.jsonl)
  --current-report FILE
                       Maintenance report JSON
  --current-quarantine FILE
                       Excluded/stale CVE JSONL
  --current-input FILE Add a supplemental current CVE JSONL input; repeatable
  --snapshot-as-of TS  Explicit CVE snapshot coverage timestamp. By default,
                       derive the earliest timestamp from feed metadata.
  --update-llm-parsed  Opt in to incremental LLM inference after current JSONL
                       maintenance, then atomically update parsed/failure data
  --llm-input FILE     NVD JSONL to compare and parse (default: current-output)
  --llm-parsed-output FILE
                       Complete parsed JSONL updated in place
                       (default: data/nvd-cves-desc_parse.jsonl)
  --llm-fail-output FILE
                       Non-ok parsed result subset
                       (default: data/nvd-cves-desc_parse-fail.jsonl)
  --llm-adapter DIR    Trained Qwen LoRA adapter directory
  --llm-nproc-per-node N
                       Number of inference GPU processes (default: 1)
  --llm-batch-size N   Inference batch size per GPU (default: 2)
  -h, --help           Show this help

Environment variables with equivalent defaults:
  NVD_FEED_DIR, NVD_JSONL_FILE, NVD_FEED_BASE_URL, NVD_START_YEAR,
  NVD_END_YEAR, NVD_UPDATE_LOCK_FILE, NVD_MERGE_SCRIPT, NVD_HISTORY_SCRIPT,
  NVD_MAINTENANCE_SCRIPT, NVD_HISTORY_DIR, NVD_HISTORY_API_KEY_ENV,
  NVD_HISTORY_PAGE_SIZE, NVD_HISTORY_REQUEST_DELAY, NVD_CURRENT_JSONL_FILE,
  NVD_CURRENT_REPORT_FILE, NVD_CURRENT_QUARANTINE_FILE, NVD_SNAPSHOT_AS_OF,
  NVD_LLM_UPDATE_SCRIPT, NVD_LLM_INFERENCE_SCRIPT, NVD_LLM_INPUT_FILE,
  NVD_LLM_PARSED_FILE, NVD_LLM_FAIL_FILE, NVD_LLM_ADAPTER,
  NVD_LLM_NPROC_PER_NODE, NVD_LLM_BATCH_SIZE, NVD_LLM_MAX_INPUT_TOKENS,
  NVD_LLM_MAX_NEW_TOKENS, PYTHON_BIN, CURL_BIN, TORCHRUN_BIN
EOF
}

while (($#)); do
    case "$1" in
        --feed-dir)
            [[ $# -ge 2 ]] || { echo "[ERROR] --feed-dir requires a value" >&2; exit 2; }
            FEED_DIR="$2"
            shift 2
            ;;
        --output)
            [[ $# -ge 2 ]] || { echo "[ERROR] --output requires a value" >&2; exit 2; }
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --base-url)
            [[ $# -ge 2 ]] || { echo "[ERROR] --base-url requires a value" >&2; exit 2; }
            BASE_URL="$2"
            shift 2
            ;;
        --start-year)
            [[ $# -ge 2 ]] || { echo "[ERROR] --start-year requires a value" >&2; exit 2; }
            START_YEAR="$2"
            shift 2
            ;;
        --end-year)
            [[ $# -ge 2 ]] || { echo "[ERROR] --end-year requires a value" >&2; exit 2; }
            END_YEAR="$2"
            shift 2
            ;;
        --force-download)
            FORCE_DOWNLOAD=1
            shift
            ;;
        --force-merge)
            FORCE_MERGE=1
            shift
            ;;
        --no-merge)
            MERGE_JSONL=0
            shift
            ;;
        --history-dir)
            [[ $# -ge 2 ]] || { echo "[ERROR] --history-dir requires a value" >&2; exit 2; }
            HISTORY_DIR="$2"
            shift 2
            ;;
        --history-api-key-env)
            [[ $# -ge 2 ]] || { echo "[ERROR] --history-api-key-env requires a value" >&2; exit 2; }
            HISTORY_API_KEY_ENV="$2"
            shift 2
            ;;
        --history-page-size)
            [[ $# -ge 2 ]] || { echo "[ERROR] --history-page-size requires a value" >&2; exit 2; }
            HISTORY_PAGE_SIZE="$2"
            shift 2
            ;;
        --history-request-delay)
            [[ $# -ge 2 ]] || { echo "[ERROR] --history-request-delay requires a value" >&2; exit 2; }
            HISTORY_REQUEST_DELAY="$2"
            shift 2
            ;;
        --verify-history)
            VERIFY_HISTORY=1
            shift
            ;;
        --no-history)
            UPDATE_HISTORY=0
            shift
            ;;
        --no-current)
            BUILD_CURRENT=0
            shift
            ;;
        --current-output)
            [[ $# -ge 2 ]] || { echo "[ERROR] --current-output requires a value" >&2; exit 2; }
            CURRENT_OUTPUT="$2"
            shift 2
            ;;
        --current-report)
            [[ $# -ge 2 ]] || { echo "[ERROR] --current-report requires a value" >&2; exit 2; }
            CURRENT_REPORT="$2"
            shift 2
            ;;
        --current-quarantine)
            [[ $# -ge 2 ]] || { echo "[ERROR] --current-quarantine requires a value" >&2; exit 2; }
            CURRENT_QUARANTINE="$2"
            shift 2
            ;;
        --current-input)
            [[ $# -ge 2 ]] || { echo "[ERROR] --current-input requires a value" >&2; exit 2; }
            CURRENT_EXTRA_INPUTS+=("$2")
            shift 2
            ;;
        --snapshot-as-of)
            [[ $# -ge 2 ]] || { echo "[ERROR] --snapshot-as-of requires a value" >&2; exit 2; }
            SNAPSHOT_AS_OF="$2"
            shift 2
            ;;
        --update-llm-parsed)
            UPDATE_LLM_PARSED=1
            shift
            ;;
        --llm-input)
            [[ $# -ge 2 ]] || { echo "[ERROR] --llm-input requires a value" >&2; exit 2; }
            LLM_INPUT="$2"
            shift 2
            ;;
        --llm-parsed-output)
            [[ $# -ge 2 ]] || { echo "[ERROR] --llm-parsed-output requires a value" >&2; exit 2; }
            LLM_PARSED_OUTPUT="$2"
            shift 2
            ;;
        --llm-fail-output)
            [[ $# -ge 2 ]] || { echo "[ERROR] --llm-fail-output requires a value" >&2; exit 2; }
            LLM_FAIL_OUTPUT="$2"
            shift 2
            ;;
        --llm-adapter)
            [[ $# -ge 2 ]] || { echo "[ERROR] --llm-adapter requires a value" >&2; exit 2; }
            LLM_ADAPTER="$2"
            shift 2
            ;;
        --llm-nproc-per-node)
            [[ $# -ge 2 ]] || { echo "[ERROR] --llm-nproc-per-node requires a value" >&2; exit 2; }
            LLM_NPROC_PER_NODE="$2"
            shift 2
            ;;
        --llm-batch-size)
            [[ $# -ge 2 ]] || { echo "[ERROR] --llm-batch-size requires a value" >&2; exit 2; }
            LLM_BATCH_SIZE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[ERROR] unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$LLM_INPUT" ]]; then
    LLM_INPUT="$CURRENT_OUTPUT"
fi

if [[ ! "$START_YEAR" =~ ^[0-9]{4}$ || ! "$END_YEAR" =~ ^[0-9]{4}$ ]]; then
    echo "[ERROR] start/end year must be four decimal digits" >&2
    exit 2
fi
if ((10#$START_YEAR > 10#$END_YEAR)); then
    echo "[ERROR] start year must not be greater than end year" >&2
    exit 2
fi
if [[ ! "$HISTORY_PAGE_SIZE" =~ ^[0-9]+$ ]] \
    || ((10#$HISTORY_PAGE_SIZE < 1 || 10#$HISTORY_PAGE_SIZE > 5000)); then
    echo "[ERROR] history page size must be between 1 and 5000" >&2
    exit 2
fi
if [[ ! "$HISTORY_REQUEST_DELAY" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "[ERROR] history request delay must be a non-negative number" >&2
    exit 2
fi
if [[ ! "$HISTORY_API_KEY_ENV" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "[ERROR] invalid history API-key environment variable name" >&2
    exit 2
fi
if ((UPDATE_LLM_PARSED)); then
    if [[ ! "$LLM_NPROC_PER_NODE" =~ ^[1-9][0-9]*$ ]]; then
        echo "[ERROR] llm nproc per node must be a positive integer" >&2
        exit 2
    fi
    if [[ ! "$LLM_BATCH_SIZE" =~ ^[1-9][0-9]*$ ]]; then
        echo "[ERROR] llm batch size must be a positive integer" >&2
        exit 2
    fi
    if [[ ! "$LLM_MAX_INPUT_TOKENS" =~ ^[0-9]+$ ]] || ((10#$LLM_MAX_INPUT_TOKENS < 256)); then
        echo "[ERROR] NVD_LLM_MAX_INPUT_TOKENS must be at least 256" >&2
        exit 2
    fi
    if [[ ! "$LLM_MAX_NEW_TOKENS" =~ ^[0-9]+$ ]] || ((10#$LLM_MAX_NEW_TOKENS < 16)); then
        echo "[ERROR] NVD_LLM_MAX_NEW_TOKENS must be at least 16" >&2
        exit 2
    fi
fi

for command in "$CURL_BIN" gzip sha256sum stat flock "$PYTHON_BIN"; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "[ERROR] required command not found: $command" >&2
        exit 2
    fi
done
if ((MERGE_JSONL)) && [[ ! -r "$MERGE_SCRIPT" ]]; then
    echo "[ERROR] merge script is not readable: $MERGE_SCRIPT" >&2
    exit 2
fi
if ((UPDATE_HISTORY)) && [[ ! -r "$HISTORY_SCRIPT" ]]; then
    echo "[ERROR] history script is not readable: $HISTORY_SCRIPT" >&2
    exit 2
fi
if ((UPDATE_HISTORY)) && [[ -z "${!HISTORY_API_KEY_ENV:-}" ]]; then
    echo "[ERROR] set the NVD API key in environment variable '$HISTORY_API_KEY_ENV'" >&2
    exit 2
fi
if ((BUILD_CURRENT)) && [[ ! -r "$MAINTENANCE_SCRIPT" ]]; then
    echo "[ERROR] maintenance script is not readable: $MAINTENANCE_SCRIPT" >&2
    exit 2
fi
if ((BUILD_CURRENT)) && ! "$PYTHON_BIN" "$MAINTENANCE_SCRIPT" --help >/dev/null; then
    echo "[ERROR] current maintenance script failed its import/startup check: $MAINTENANCE_SCRIPT" >&2
    exit 2
fi
if ((UPDATE_LLM_PARSED)); then
    if [[ ! -r "$LLM_UPDATE_SCRIPT" ]]; then
        echo "[ERROR] LLM update script is not readable: $LLM_UPDATE_SCRIPT" >&2
        exit 2
    fi
    if [[ ! -r "$LLM_INFERENCE_SCRIPT" ]]; then
        echo "[ERROR] LLM inference script is not readable: $LLM_INFERENCE_SCRIPT" >&2
        exit 2
    fi
    if [[ ! -d "$LLM_ADAPTER" ]]; then
        echo "[ERROR] LLM adapter directory does not exist: $LLM_ADAPTER" >&2
        exit 2
    fi
    if ((LLM_NPROC_PER_NODE > 1)) && ! command -v "$TORCHRUN_BIN" >/dev/null 2>&1; then
        echo "[ERROR] torchrun command not found: $TORCHRUN_BIN" >&2
        exit 2
    fi
fi
for extra_input in "${CURRENT_EXTRA_INPUTS[@]}"; do
    if [[ ! -r "$extra_input" ]]; then
        echo "[ERROR] supplemental current input is not readable: $extra_input" >&2
        exit 2
    fi
done

BASE_URL="${BASE_URL%/}"
mkdir -p \
    "$FEED_DIR" \
    "$(dirname "$OUTPUT_FILE")" \
    "$(dirname "$LOCK_FILE")" \
    "$HISTORY_DIR" \
    "$(dirname "$CURRENT_OUTPUT")" \
    "$(dirname "$CURRENT_REPORT")" \
    "$(dirname "$CURRENT_QUARANTINE")"
if ((UPDATE_LLM_PARSED)); then
    mkdir -p "$(dirname "$LLM_PARSED_OUTPUT")" "$(dirname "$LLM_FAIL_OUTPUT")"
fi

exec 9>"$LOCK_FILE"
echo "[lock] waiting for $LOCK_FILE"
flock 9

feed_parent="$(dirname "$FEED_DIR")"
mkdir -p "$feed_parent"
stage_dir="$(mktemp -d "$feed_parent/.nvd-update.XXXXXX")"
cleanup() {
    rm -rf "$stage_dir"
}
trap cleanup EXIT

meta_value() {
    local key="$1"
    local file="$2"
    sed -n "s/^${key}://p" "$file" | head -n 1 | tr -d '\r'
}

validate_meta() {
    local file="$1"
    local name="$2"
    local sha size modified
    sha="$(meta_value sha256 "$file")"
    size="$(meta_value size "$file")"
    modified="$(meta_value lastModifiedDate "$file")"
    if [[ ! "$sha" =~ ^[[:xdigit:]]{64}$ ]]; then
        echo "[ERROR] invalid SHA-256 in ${name}.meta" >&2
        return 1
    fi
    if [[ ! "$size" =~ ^[0-9]+$ ]] || ((size <= 0)); then
        echo "[ERROR] invalid uncompressed size in ${name}.meta" >&2
        return 1
    fi
    if [[ -z "$modified" ]]; then
        echo "[ERROR] missing lastModifiedDate in ${name}.meta" >&2
        return 1
    fi
}

validate_envelope() {
    local json_file="$1"
    "$PYTHON_BIN" - "$json_file" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
with path.open("rb") as stream:
    prefix = stream.read(1024 * 1024)

if not prefix.lstrip().startswith(b"{"):
    raise SystemExit(f"invalid JSON object envelope: {path}")
required = (
    rb'"format"\s*:\s*"NVD_CVE"',
    rb'"version"\s*:\s*"2\.0"',
    rb'"timestamp"\s*:',
    rb'"vulnerabilities"\s*:\s*\[',
)
for pattern in required:
    if re.search(pattern, prefix) is None:
        raise SystemExit(f"missing NVD 2.0 envelope field in {path}: {pattern!r}")
PY
}

download_feed() {
    local name="$1"
    local expected_sha="$2"
    local expected_size="$3"
    local gz_file="$stage_dir/${name}.json.gz"
    local json_file="$stage_dir/${name}.json"
    local actual_sha actual_size

    echo "[download] ${name}.json.gz"
    "$CURL_BIN" -fL --retry 5 --retry-delay 2 --retry-all-errors \
        --connect-timeout 30 --max-time 1800 \
        "$BASE_URL/${name}.json.gz" -o "$gz_file"
    gzip -t "$gz_file"
    gzip -dc "$gz_file" >"$json_file"

    actual_size="$(stat -c '%s' "$json_file")"
    if [[ "$actual_size" != "$expected_size" ]]; then
        echo "[ERROR] ${name}.json size mismatch: expected=$expected_size actual=$actual_size" >&2
        return 1
    fi
    actual_sha="$(sha256sum "$json_file" | awk '{print toupper($1)}')"
    if [[ "$actual_sha" != "${expected_sha^^}" ]]; then
        echo "[ERROR] ${name}.json SHA-256 mismatch" >&2
        echo "[ERROR] expected=${expected_sha^^}" >&2
        echo "[ERROR] actual=$actual_sha" >&2
        return 1
    fi
    validate_envelope "$json_file"
    rm -f "$gz_file"
}

feed_names=()
for ((year=10#$START_YEAR; year<=10#$END_YEAR; year++)); do
    feed_names+=("nvdcve-2.0-$year")
done
feed_names+=("nvdcve-2.0-modified" "nvdcve-2.0-recent")

manifest_file="$stage_dir/source-feed.manifest"
changed_names=()
meta_only_names=()

echo "[update] base_url=$BASE_URL"
echo "[update] feed_dir=$FEED_DIR"
echo "[update] annual_range=$START_YEAR..$END_YEAR feeds=${#feed_names[@]}"

for name in "${feed_names[@]}"; do
    remote_meta="$stage_dir/${name}.remote.meta"
    target_json="$FEED_DIR/${name}.json"
    target_meta="$FEED_DIR/${name}.meta"

    echo "[meta] $name"
    "$CURL_BIN" -fL --retry 5 --retry-delay 2 --retry-all-errors \
        --connect-timeout 30 --max-time 120 \
        "$BASE_URL/${name}.meta" -o "$remote_meta"
    validate_meta "$remote_meta" "$name"

    remote_sha="$(meta_value sha256 "$remote_meta")"
    remote_size="$(meta_value size "$remote_meta")"
    remote_modified="$(meta_value lastModifiedDate "$remote_meta")"
    local_matches=0
    if ((FORCE_DOWNLOAD == 0)) && [[ -f "$target_json" ]]; then
        local_size="$(stat -c '%s' "$target_json")"
        if [[ "$local_size" == "$remote_size" ]]; then
            if [[ -r "$target_meta" ]] \
                && [[ "$(meta_value sha256 "$target_meta" | tr '[:lower:]' '[:upper:]')" == "${remote_sha^^}" ]]; then
                local_matches=1
            else
                local_sha="$(sha256sum "$target_json" | awk '{print toupper($1)}')"
                if [[ "$local_sha" == "${remote_sha^^}" ]]; then
                    local_matches=1
                    meta_only_names+=("$name")
                fi
            fi
        fi
    fi

    if ((local_matches)); then
        echo "[skip] $name is current ($remote_modified)"
        continue
    fi

    download_feed "$name" "$remote_sha" "$remote_size"
    changed_names+=("$name")
done

# All downloads are verified before any existing JSON feed is replaced.
for name in "${changed_names[@]}"; do
    mv -f "$stage_dir/${name}.json" "$FEED_DIR/${name}.json"
    mv -f "$stage_dir/${name}.remote.meta" "$FEED_DIR/${name}.meta"
    echo "[installed] $FEED_DIR/${name}.json"
done
for name in "${meta_only_names[@]}"; do
    mv -f "$stage_dir/${name}.remote.meta" "$FEED_DIR/${name}.meta"
done

echo "[update] changed_feeds=${#changed_names[@]} metadata_initialized=${#meta_only_names[@]}"

# Describe the exact set of JSON files consumed by the merge script, including
# any pre-existing annual feed outside a deliberately narrowed update range.
: >"$manifest_file"
while IFS= read -r json_file; do
    name="$(basename "$json_file" .json)"
    target_meta="$FEED_DIR/${name}.meta"
    local_size="$(stat -c '%s' "$json_file")"
    if [[ -r "$target_meta" ]]; then
        validate_meta "$target_meta" "$name"
        local_sha="$(meta_value sha256 "$target_meta" | tr '[:lower:]' '[:upper:]')"
        local_modified="$(meta_value lastModifiedDate "$target_meta")"
        meta_size="$(meta_value size "$target_meta")"
        if [[ "$meta_size" != "$local_size" ]]; then
            echo "[ERROR] installed ${name}.json no longer matches its metadata size" >&2
            exit 1
        fi
    else
        local_sha="$(sha256sum "$json_file" | awk '{print toupper($1)}')"
        local_modified="unknown"
    fi
    printf '%s\t%s\t%s\t%s\n' \
        "$name" "$local_sha" "$local_size" "$local_modified" >>"$manifest_file"
done < <(find "$FEED_DIR" -maxdepth 1 -type f -name 'nvdcve-2.0-*.json' -print | sort)

if ((MERGE_JSONL == 0)); then
    echo "[merge] skipped by --no-merge"
else
    output_manifest="${OUTPUT_FILE}.sources.manifest"
    merge_required=0
    if ((FORCE_MERGE)) || [[ ! -f "$OUTPUT_FILE" ]] || [[ ! -f "$output_manifest" ]]; then
        merge_required=1
    elif ! cmp -s "$manifest_file" "$output_manifest"; then
        merge_required=1
    fi

    if ((merge_required)); then
        echo "[merge] rebuilding $OUTPUT_FILE"
        "$PYTHON_BIN" "$MERGE_SCRIPT" \
            --input-dir "$FEED_DIR" \
            --output "$OUTPUT_FILE"
        manifest_temp="${output_manifest}.tmp.$$"
        cp "$manifest_file" "$manifest_temp"
        mv -f "$manifest_temp" "$output_manifest"
        echo "[merge] source_manifest=$output_manifest"
    else
        echo "[merge] source manifest unchanged; keeping $OUTPUT_FILE"
    fi
fi

history_file="$HISTORY_DIR/nvd-cve-history.jsonl.gz"
if ((UPDATE_HISTORY)); then
    history_command=(
        "$PYTHON_BIN" "$HISTORY_SCRIPT"
        --output-dir "$HISTORY_DIR"
        --api-key-env "$HISTORY_API_KEY_ENV"
        --page-size "$HISTORY_PAGE_SIZE"
        --request-delay "$HISTORY_REQUEST_DELAY"
    )
    if ((VERIFY_HISTORY)); then
        history_command+=(--verify-existing)
    fi
    echo "[history] refreshing $history_file"
    "${history_command[@]}"
else
    echo "[history] download skipped by --no-history"
fi

derive_snapshot_as_of() {
    "$PYTHON_BIN" - "$manifest_file" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import sys

timestamps = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    fields = line.split("\t")
    if len(fields) != 4 or fields[3] == "unknown":
        print("")
        raise SystemExit(0)
    try:
        value = datetime.fromisoformat(fields[3].replace("Z", "+00:00"))
    except ValueError:
        print("")
        raise SystemExit(0)
    if value.tzinfo is None:
        print("")
        raise SystemExit(0)
    timestamps.append(value.astimezone(timezone.utc))

if not timestamps:
    print("")
else:
    print(min(timestamps).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
PY
}

if ((BUILD_CURRENT == 0)); then
    echo "[current] skipped by --no-current"
elif ((MERGE_JSONL == 0)); then
    echo "[current] skipped because --no-merge was specified"
else
    if [[ ! -r "$OUTPUT_FILE" ]]; then
        echo "[ERROR] merged CVE JSONL is not readable: $OUTPUT_FILE" >&2
        exit 1
    fi
    if [[ ! -r "$history_file" ]]; then
        echo "[ERROR] merged Change History is not readable: $history_file" >&2
        echo "[ERROR] remove --no-history or provide a complete existing history directory" >&2
        exit 1
    fi
    effective_snapshot_as_of="$SNAPSHOT_AS_OF"
    if [[ -z "$effective_snapshot_as_of" ]]; then
        effective_snapshot_as_of="$(derive_snapshot_as_of)"
    fi
    current_command=(
        "$PYTHON_BIN" "$MAINTENANCE_SCRIPT"
        --input "$OUTPUT_FILE"
    )
    for extra_input in "${CURRENT_EXTRA_INPUTS[@]}"; do
        current_command+=(--input "$extra_input")
    done
    current_command+=(
        --history "$history_file"
        --require-history-manifest
        --output "$CURRENT_OUTPUT"
        --report "$CURRENT_REPORT"
        --quarantine "$CURRENT_QUARANTINE"
    )
    if [[ -n "$effective_snapshot_as_of" ]]; then
        current_command+=(--snapshot-as-of "$effective_snapshot_as_of")
        echo "[current] snapshot_as_of=$effective_snapshot_as_of"
    else
        echo "[current] no globally safe feed timestamp; using conservative stale checks"
    fi
    echo "[current] rebuilding $CURRENT_OUTPUT"
    "${current_command[@]}"
fi

if ((UPDATE_LLM_PARSED)); then
    if [[ ! -r "$LLM_INPUT" ]]; then
        echo "[ERROR] LLM comparison input is not readable: $LLM_INPUT" >&2
        exit 1
    fi
    llm_pending="$stage_dir/nvd-cves.llm-pending.jsonl"
    llm_manifest="$stage_dir/nvd-cves.llm-update.manifest.json"
    llm_incremental="$stage_dir/nvd-cves.llm-incremental.jsonl"
    echo "[llm] preparing incremental input from $LLM_INPUT"
    "$PYTHON_BIN" "$LLM_UPDATE_SCRIPT" prepare \
        --input "$LLM_INPUT" \
        --parsed "$LLM_PARSED_OUTPUT" \
        --pending "$llm_pending" \
        --manifest "$llm_manifest"
    llm_pending_count="$(wc -l < "$llm_pending")"
    echo "[llm] pending_records=$llm_pending_count"
    if ((llm_pending_count > 0)); then
        if ((LLM_NPROC_PER_NODE == 1)); then
            llm_command=("$PYTHON_BIN" -u "$LLM_INFERENCE_SCRIPT")
        else
            llm_command=(
                "$TORCHRUN_BIN"
                --standalone
                "--nproc-per-node=$LLM_NPROC_PER_NODE"
                "$LLM_INFERENCE_SCRIPT"
            )
        fi
        llm_command+=(
            --input "$llm_pending"
            --adapter "$LLM_ADAPTER"
            --output "$llm_incremental"
            --batch-size "$LLM_BATCH_SIZE"
            --max-input-tokens "$LLM_MAX_INPUT_TOKENS"
            --max-new-tokens "$LLM_MAX_NEW_TOKENS"
        )
        echo "[llm] running inference with $LLM_NPROC_PER_NODE GPU process(es)"
        "${llm_command[@]}"
    else
        : >"$llm_incremental"
        echo "[llm] no new or changed descriptions; inference skipped"
    fi
    echo "[llm] applying incremental results to $LLM_PARSED_OUTPUT"
    "$PYTHON_BIN" "$LLM_UPDATE_SCRIPT" apply \
        --input "$LLM_INPUT" \
        --parsed "$LLM_PARSED_OUTPUT" \
        --pending "$llm_pending" \
        --manifest "$llm_manifest" \
        --inference "$llm_incremental" \
        --output "$LLM_PARSED_OUTPUT" \
        --fail-output "$LLM_FAIL_OUTPUT"
else
    echo "[llm] skipped; pass --update-llm-parsed to enable inference"
fi

echo "[success] NVD update pipeline completed"
echo "[success] merged_cves=$OUTPUT_FILE"
if [[ -r "$history_file" ]]; then
    echo "[success] merged_history=$history_file"
else
    echo "[success] merged_history=not_available"
fi
if ((BUILD_CURRENT)) && ((MERGE_JSONL)); then
    echo "[success] current_cves=$CURRENT_OUTPUT"
    echo "[success] quarantine=$CURRENT_QUARANTINE"
    echo "[success] maintenance_report=$CURRENT_REPORT"
fi
