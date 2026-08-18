# `03_run_benchmark_builds.sh` 사용 및 처리 로직

## 1. 목적

`03_run_benchmark_builds.sh`는 두 가지 데이터 축과 두 가지 LLM 축을 조합해 네 개의 applicability DB를 만들고, 동일한 gold set으로 평가·시각화·비교한다.

비교 축:

- NVD 원본 병합본 vs Change History가 반영된 current 본
- LLM description parser 미사용 vs 사용

생성하는 네 빌드는 다음과 같다.

| ID | 입력 | LLM | 의미 |
|---|---|---|---|
| `01_nvd_without_llm` | `nvd-cves.jsonl` | 미사용 | 원본 NVD baseline |
| `02_nvd_with_llm` | `nvd-cves.jsonl` | 사용 | 원본에서 LLM 효과 |
| `03_current_without_llm` | `nvd-cves.current.jsonl` | 미사용 | History 효과 |
| `04_current_with_llm` | `nvd-cves.current.jsonl` | 사용 | History와 LLM 동시 적용 |

## 2. 기본 사용법

```bash
cd ~/korea_univ/cve_binder
./03_run_benchmark_builds.sh
```

전체 데이터 대신 빠른 smoke benchmark를 수행하려면:

```bash
BENCHMARK_LIMIT=1000 ./03_run_benchmark_builds.sh
```

별도 결과 디렉터리를 사용하려면:

```bash
BENCHMARK_DIR=workspace/benchmark_trial \
BENCHMARK_LIMIT=5000 \
./03_run_benchmark_builds.sh
```

스크립트는 명령행 인자를 해석하지 않는다. 모든 변경은 환경 변수로 지정한다.

## 3. 필수 프로그램과 입력

필수 명령:

- `python3` 또는 `PYTHON_BIN`
- `sqlite3` 또는 `SQLITE_BIN`
- `jq` 또는 `JQ_BIN`

필수 입력:

| 환경 변수 | 기본 경로 |
|---|---|
| `NVD_ORIGINAL` | `data/nvd-cves.jsonl` |
| `NVD_CURRENT` | `data/nvd-cves.current.jsonl` |
| `LLM_SUCCESS` | `data/nvd-cves-desc_parse.jsonl` |
| `LLM_FAILURE` | `data/nvd-cves-desc_parse-fail.jsonl` |
| `EVALUATION_GOLD` | `data/nvd_labeling_250_v2.jsonl` |
| `NVD_HISTORY` | `data/nvd-cve-history/nvd-cve-history.jsonl.gz` |
| `EVALUATION_SCRIPT` | `utils/evaluate_nvd_labeling_250.py` |
| `VISUALIZATION_SCRIPT` | `utils/visualize_evaluation.py` |
| `CONFLICT_ANALYSIS_SCRIPT` | `utils/analysis/cve_cpe_conflicts.py` |
| `HISTORY_POLICY_SCRIPT` | `utils/analysis/build_history_conflict_policy.py` |

평가 시각화에는 Python 환경의 `matplotlib`, `numpy`도 필요하다.

## 4. 주요 환경 변수

| 변수 | 기본값 | 의미 |
|---|---|---|
| `BENCHMARK_DIR` | `workspace/benchmark` | 모든 benchmark 결과의 루트 |
| `PROGRESS_EVERY` | `1000` | DB ingest progress 간격. 0 허용 |
| `EVALUATION_PROGRESS_EVERY` | `25` | gold query 평가 progress 간격. 0 허용 |
| `HISTORY_CONFLICT_JOBS` | `4` | CNA/CPE conflict 분석 worker 수 |
| `BENCHMARK_LIMIT` | 빈 값 | 각 DB와 conflict 분석에 사용할 앞부분 CVE 수 |
| `EVALUATION_PREFIX` | `nvd_labeling_250_v2` | 평가 artifact 파일 이름 prefix |
| `HISTORY_CONFLICT_DETAILS` | benchmark analysis 하위 JSONL | conflict 상세 결과 |
| `HISTORY_CONFLICT_SUMMARY` | benchmark analysis 하위 JSON | conflict 집계 |
| `HISTORY_CONFLICT_POLICY` | benchmark analysis 하위 JSONL | query-time 판정 정책 |
| `HISTORY_CONFLICT_REPORT` | benchmark analysis 하위 JSON | 정책 생성 보고서 |

`BENCHMARK_LIMIT`는 양의 정수여야 한다. `PROGRESS_EVERY`와 `EVALUATION_PROGRESS_EVERY`는 0 이상의 정수여야 한다.

## 5. 출력 디렉터리

기본 결과 구조:

```text
workspace/benchmark/
├── 01_nvd_without_llm.sqlite
├── 02_nvd_with_llm.sqlite
├── 03_current_without_llm.sqlite
├── 04_current_with_llm.sqlite
├── benchmark_report.json
├── logs/
├── build_summaries/
├── metrics/
├── reports/
├── evaluation/
├── visualizations/
└── analysis/
```

- `build_summaries/`: 각 DB의 `pipeline_run.summary_json`
- `metrics/`: DB table count, LLM claim 수, publish health, 평가 지표
- `evaluation/`: gold set별 JSON/JSONL/CSV/Markdown 결과
- `visualizations/`: 지표·오류 구성·성능 그래프와 분석 summary
- `analysis/`: CNA/CPE conflict와 history policy
- `reports/`: 비교 case 1~3의 before/after/delta
- `logs/`: 빌드·평가·시각화·history 분석 로그

## 6. 세부 실행 알고리즘

### 6.1 사전 검증

결과 디렉터리를 먼저 만들고 필수 명령과 모든 입력 파일의 존재를 검사한다. 하나라도 없으면 네 개의 비싼 빌드를 시작하기 전에 exit code `2`로 종료한다.

### 6.2 네 개 DB 순차 빌드

각 조합은 다음 기본 명령으로 새 DB를 만든다.

```bash
python3 -u -m scripts.nvd_normalization build \
  --input INPUT.jsonl \
  --db workspace/benchmark/BUILD_ID.sqlite \
  --replace \
  --progress-every 1000 \
  --without-llm
```

LLM 조합은 `--without-llm` 대신 다음을 추가한다.

```text
--llm data/nvd-cves-desc_parse.jsonl
--llm-fail data/nvd-cves-desc_parse-fail.jsonl
```

`BENCHMARK_LIMIT`가 있으면 모든 build에 동일한 `--limit`을 전달한다. 각 build stdout/stderr에는 timestamp를 붙여 고유 로그에 저장하며, Python exit code를 `PIPESTATUS`로 보존한다. 앞 build가 실패하면 이후 조합은 실행하지 않는다.

정규화 자체의 claim·assertion·identity·audit 알고리즘은 `run_build_db.md`의 설명과 같다. 차이는 입력/LLM 조합과 출력 DB 경로뿐이다.

### 6.3 DB 내부 지표 추출

각 build가 성공하면 SQLite를 read-only로 열어 최근 `pipeline_run.summary_json`을 별도 파일로 저장한다. 이어서 다음과 같은 값을 하나의 metrics JSON에 넣는다.

- publish status와 health
- 게시 CVE 수, normalization issue 수
- raw/rejected CVE 수
- source claim, product entity/alias 수
- 전체/active assertion 수
- binding과 active binding member 수
- LLM result/claim 및 vendor/product/version claim 수
- stale description 등 `F-LLM-04` issue 수
- DB 파일 크기

임시 JSON에 쓴 뒤 `mv`로 교체하여 반쪽 metrics 파일을 남기지 않는다.

### 6.4 Current CNA/CPE conflict 분석

네 DB가 완성되면 `NVD_CURRENT`를 대상으로 structured CNA `Affected` 범위와 NVD CPE 범위의 충돌을 분석한다. 분석 결과는 conflict detail JSONL과 summary JSON으로 저장한다.

`BENCHMARK_LIMIT`가 있으면 conflict 분석에도 같은 limit을 적용한다. `HISTORY_CONFLICT_JOBS`만큼 병렬 worker를 사용한다.

### 6.5 History conflict policy 생성

Conflict detail과 전체 Change History를 결합해 query-time sidecar policy를 만든다.

판정 방향:

- `cpe_broader`, `cna_broader`, `partial_overlap`: current CPE 판단 사용
- `disjoint`: 같은 current CPE interval의 마지막 명시 action이 `Added`이면 수용
- 제거된 interval, scheme mismatch, 근거 부족: `conflict_review` 유지
- 동일 CVE/product에 서로 다른 action이 섞이면 product-only fallback을 허용하지 않고 review 유지

이 sidecar는 current DB인 03과 04 평가에만 전달한다. 원본 baseline인 01과 02에는 적용하지 않는다.

### 6.6 동일 gold set 평가

각 DB에 대해 gold JSONL의 `(vendor, product, version)` query를 모두 실행한다. Gold의 `cve_id` 목록은 대문자화·중복 제거하고, query key 중복이나 예상 밖 field가 있으면 실패한다.

Query engine 결과에서 두 정책을 동시에 평가한다.

- `inclusive`: `affected`와 보수적 후보 상태를 포함하는 발견 중심 결과
- `strict`: strict positive로 인정되는 결과만 포함

각 query key마다 gold set과 predicted set의 교집합/차집합으로 TP, FP, FN을 계산한다. 이어서 precision, recall, F0.5, F1, F2, Jaccard, false discovery rate, false negative rate, exact-match 여부를 계산한다.

전체 집계에는 모든 key의 TP/FP/FN을 합친 micro 지표와 key별 지표 평균인 macro precision/recall이 포함된다. 오류 CVE별 candidate state도 기록해 “후보는 찾았지만 strict로 판정하지 못한 FN”과 “identity 단계에서 찾지 못한 FN”을 구분할 수 있다.

### 6.7 평가 artifact 검증과 시각화

평가기 완료 후 다음 파일이 실제 생성됐는지 확인한다.

- `*_evaluation.json`
- `*_evaluation_cases.jsonl`
- `*_cve_errors.csv`

그다음 시각화기가 metrics overview, inclusive/strict 오류 구성, 상위 오류 key, query 성능, 이전 build 비교 등을 생성한다. `v10_analysis_summary.json`이 없으면 시각화 성공으로 인정하지 않는다.

비교 기준은 다음처럼 연결한다.

| 평가 대상 | 이전 결과 | 비교 의미 |
|---|---|---|
| 01 | 없음 | baseline |
| 02 | 01 | 원본 NVD에서 LLM 효과 |
| 03 | 01 | LLM 없이 History 효과 |
| 04 | 03 | current 데이터에서 LLM 추가 효과 |

평가 summary의 dataset, overall, false-negative state totals, timing, artifact 경로를 해당 build의 metrics JSON에 다시 합친다.

### 6.8 세 가지 최종 비교

`jq`로 before와 after metrics에서 양쪽 값이 모두 숫자인 같은 key만 뺄셈해 `numeric_delta`를 만든다.

| Case | Before | After | 질문 |
|---|---|---|---|
| case 1 | 01 | 02 | History 적용 전 LLM 사용 효과는 무엇인가? |
| case 2 | 01 | 03 | LLM 없이 History 적용 효과는 무엇인가? |
| case 3 | 01 | 04 | baseline 대비 History+LLM 동시 효과는 무엇인가? |

세 case를 `workspace/benchmark/benchmark_report.json` 하나로 묶는다.

## 7. 결과 해석 시 주의점

- Case 3은 두 요소를 동시에 바꾼 종합 비교다. LLM만의 효과는 case 1, History만의 효과는 case 2로 분리해 봐야 한다.
- 03/04에만 history conflict policy가 적용되므로 단순 DB row count뿐 아니라 query policy 차이도 평가에 반영된다.
- `BENCHMARK_LIMIT` smoke 결과는 전체 corpus 품질을 대표하지 않는다. 제한된 DB에 전체 gold query를 적용하므로 recall이 크게 낮아질 수 있다.
- Inclusive precision과 strict precision은 서로 다른 운영 목적을 나타낸다. Inclusive는 후보 누락을 줄이는 대신 provisional/review 후보를 포함할 수 있다.
- `numeric_delta`는 최상위에서 양쪽이 숫자인 필드만 계산한다. 중첩된 평가 객체 전체를 재귀적으로 빼는 기능은 아니다.

## 8. 실패와 재실행

`set -Eeuo pipefail`이 적용되며, 어느 단계든 실패하면 이후 단계는 실행하지 않는다. 각 정규화 DB는 임시 DB에서 audit/integrity를 통과한 뒤 원자 교체된다.

다시 실행하면 동일한 네 DB 및 JSON 결과를 교체한다. 로그는 timestamp 파일로 새로 남는다. 기존 결과와 분리해 보존하려면 재실행 전에 `BENCHMARK_DIR`를 다른 경로로 지정하는 것이 안전하다.

## 9. 권장 확인 순서

```bash
jq '.cases[] | {case_id, numeric_delta}' \
  workspace/benchmark/benchmark_report.json

jq '.overall' \
  workspace/benchmark/evaluation/04_current_with_llm/nvd_labeling_250_v2_evaluation.json

jq '.' \
  workspace/benchmark/analysis/history_conflict_policy_report.json
```

숫자 변화만 보지 말고 `evaluation/`의 오류 CVE 목록과 `visualizations/`의 분석 summary를 함께 확인해야 원인을 판단할 수 있다.
