# `01-1_update_nvd_data.sh` 사용 및 처리 로직

## 1. 목적

`01-1_update_nvd_data.sh`는 NVD 원본 데이터를 내려받는 작업부터 정규화 DB의 입력으로 사용할 current-only JSONL을 만드는 작업까지 한 번에 수행한다. 선택적으로 새 CVE 또는 description이 변경된 CVE만 LLM으로 추론해 누적 parsed JSONL도 갱신할 수 있다.

전체 흐름은 다음과 같다.

```text
NVD JSON 2.0 연도별/최근/수정 feed 확인
→ 변경된 feed만 다운로드·검증
→ 전체 feed를 하나의 JSONL로 병합
→ NVD CVE Change History 전체 데이터 갱신
→ 최신 CVE 본문과 Change History를 조합
→ current JSONL + quarantine + report 게시
→ [선택] 신규·변경 description 선별
→ [선택] 학습된 Qwen LoRA로 증분 추론
→ [선택] 전체 parsed JSONL + 추론 실패 JSONL 원자 갱신
```

이 스크립트는 항상 자신의 위치, 즉 프로젝트 루트로 이동한 뒤 상대 경로를 해석한다. 어느 디렉터리에서 호출해도 기본 파일 위치는 프로젝트 루트 기준이다.

## 2. 기본 사용법

Change History API를 갱신하려면 NVD API 키가 필요하다.

```bash
cd nvd_hbom_binder
export NVD_API_KEY='발급받은_API_키'
./01-1_update_nvd_data.sh
```

기본 실행에서는 LLM 추론을 하지 않는다. current JSONL 갱신 뒤 증분 LLM 추론까지 실행하려면 명시적으로 `--update-llm-parsed`를 추가한다.

```bash
export NVD_API_KEY='발급받은_API_키'
./01-1_update_nvd_data.sh --update-llm-parsed
```

여러 GPU를 사용하려면 프로세스 수를 지정한다. `--llm-batch-size`는 GPU당 batch 크기다.

```bash
export NVD_API_KEY='발급받은_API_키'
./01-1_update_nvd_data.sh \
  --update-llm-parsed \
  --llm-nproc-per-node 4 \
  --llm-batch-size 2
```

도움말:

```bash
./01-1_update_nvd_data.sh --help
```

이미 완전한 Change History 파일이 있고 API를 호출하지 않으려면 다음과 같이 실행한다.

```bash
./01-1_update_nvd_data.sh --no-history
```

Feed만 확인·병합하고 current 결과를 만들지 않으려면:

```bash
export NVD_API_KEY='발급받은_API_키'
./01-1_update_nvd_data.sh --no-current
```

특정 연도 범위로 빠르게 점검하려면:

```bash
export NVD_API_KEY='발급받은_API_키'
./01-1_update_nvd_data.sh --start-year 2024 --end-year 2026
```

주의: 연도 범위를 좁혀도 `nvd-json-2.0/`에 이미 존재하는 다른 연도 JSON은 병합 manifest와 최종 JSONL에 포함된다. 범위 옵션은 이번 갱신에서 확인할 feed 이름을 제한하는 옵션이지, 기존 feed를 삭제하거나 병합 대상에서 제외하는 옵션이 아니다.

## 3. 필수 프로그램과 입력

스크립트가 시작할 때 다음 명령의 존재를 검사한다.

- `curl`
- `gzip`
- `sha256sum`
- `stat`
- `flock`
- `python` 또는 `PYTHON_BIN`으로 지정한 실행 파일

기본적으로 호출하는 Python 스크립트는 다음과 같다.

- `utils/merge_nvd_cves.py`: feed 병합 및 완전 동일 레코드 중복 제거
- `utils/download_nvd_cve_history.py`: Change History 페이지 다운로드·재개·병합
- `utils/maintain_nvd_cves.py`: current-only JSONL 생성과 CPE history 재생
- `utils/nvd_history_cpe.py`: CPE history detail 해석과 범위 병합

`--update-llm-parsed`를 사용할 때는 다음 항목도 필요하다.

- `utils/update_nvd_llm_parsed.py`: 기존 parsed 결과와 현재 입력을 비교하고 증분 입력을 준비한 뒤 결과를 병합
- `scripts/infer_nvd_cve_bindings.py`: 학습된 Qwen LoRA adapter를 이용한 CVE description 추론
- 기본 adapter 디렉터리 `models/qwen3-merged800-20260723-155213`
- CUDA 지원 PyTorch, `transformers`, `peft`, `bitsandbytes` 등 추론 코드의 Python 의존성
- 2개 이상의 GPU 프로세스를 사용할 때 `torchrun` 또는 `TORCHRUN_BIN`으로 지정한 명령

LLM 기능이 활성화되면 update/inference 스크립트의 가독성, adapter 디렉터리의 존재, GPU 프로세스 수와 batch/token 설정을 실제 추론 전에 검사한다. 세부 모델 요구사항과 독립 추론 방법은 `guide_book/01-2_llm_trainingNinference.md`를 참고한다.

History 갱신이 활성화돼 있으면 `NVD_API_KEY`가 비어 있는 경우 다운로드를 시작하기 전에 종료한다. `--history-api-key-env`를 사용하면 다른 환경 변수 이름을 지정할 수 있다.

## 4. 기본 입력과 출력

| 구분 | 기본 경로 | 의미 |
|---|---|---|
| Feed 디렉터리 | `nvd-json-2.0/` | 압축 해제된 연도별·modified·recent JSON과 metadata |
| 병합 JSONL | `data/nvd-cves.jsonl` | 모든 설치된 feed의 CVE 레코드 |
| 병합 source manifest | `data/nvd-cves.jsonl.sources.manifest` | 병합에 사용한 feed 이름·SHA-256·크기·수정 시각 |
| History 디렉터리 | `data/nvd-cve-history/` | 페이지, manifest, 최종 history JSONL gzip |
| History 결과 | `data/nvd-cve-history/nvd-cve-history.jsonl.gz` | Change History 전체 이벤트 |
| Current JSONL | `data/nvd-cves.current.jsonl` | 최신성·reject·history 정책을 통과한 CVE |
| Quarantine | `data/nvd-cves.current.quarantine.jsonl` | 제외된 CVE와 제외 사유 |
| Current report | `data/nvd-cves.current.report.json` | 선택·제외·CPE replay 통계 |
| LLM 비교 입력 | `data/nvd-cves.current.jsonl` | 신규·변경 description을 찾을 기준 입력. 기본값은 Current JSONL |
| 전체 LLM parsed 결과 | `data/nvd-cves-desc_parse.jsonl` | 기존 결과와 이번 증분 결과를 반영한 전체 추론 결과 |
| LLM 실패 결과 | `data/nvd-cves-desc_parse-fail.jsonl` | `ok`가 아닌 추론 결과만 모은 점검용 JSONL |
| 동시 실행 lock | `workspace/update_nvd_data.lock` | 중복 실행 직렬화용 lock 파일 |

병합기는 기본적으로 완전 동일 레코드의 중복 발생 내역과 그룹별 개수도 병합 출력 파일 옆에 기록한다.

## 5. 주요 옵션

### Feed 관련

| 옵션 | 의미 |
|---|---|
| `--feed-dir DIR` | feed JSON 및 metadata 저장 위치 변경 |
| `--output FILE` | 병합 JSONL 위치 변경 |
| `--base-url URL` | NVD feed 기준 URL 변경. 주로 테스트용 |
| `--start-year YYYY` | 확인할 첫 연도. 기본값 `2002` |
| `--end-year YYYY` | 확인할 마지막 연도. 기본값 현재 UTC 연도 |
| `--force-download` | local metadata가 같아도 모든 선택 feed 재다운로드 |
| `--force-merge` | source manifest가 같아도 JSONL 재생성 |
| `--no-merge` | 병합과 current 생성을 건너뜀 |

### Change History 관련

| 옵션 | 의미 |
|---|---|
| `--history-dir DIR` | history 페이지와 결과 디렉터리 변경 |
| `--history-api-key-env NAME` | API 키를 읽을 환경 변수 이름 변경 |
| `--history-page-size N` | 요청당 이벤트 수. `1`~`5000` |
| `--history-request-delay SEC` | 요청 시작 간 최소 대기 시간 |
| `--verify-history` | 기존 페이지도 압축 해제·검증한 후 재개 |
| `--no-history` | API 호출 없이 기존 history 결과 사용 |

### Current snapshot 관련

| 옵션 | 의미 |
|---|---|
| `--no-current` | current, quarantine, report 생성을 건너뜀 |
| `--current-output FILE` | current JSONL 경로 변경 |
| `--current-report FILE` | report 경로 변경 |
| `--current-quarantine FILE` | quarantine 경로 변경 |
| `--current-input FILE` | 추가 최신 CVE JSONL 입력. 여러 번 지정 가능 |
| `--snapshot-as-of TS` | feed/API snapshot이 모든 변경을 반영한 기준 시각 |

### LLM 증분 추론 관련

| 옵션 | 기본값 | 의미 |
|---|---|---|
| `--update-llm-parsed` | 비활성 | current 처리 뒤 LLM 증분 갱신 실행 |
| `--llm-input FILE` | `--current-output` 값 | 비교 및 추론 대상 NVD JSONL 변경 |
| `--llm-parsed-output FILE` | `data/nvd-cves-desc_parse.jsonl` | 전체 parsed JSONL 경로 변경 |
| `--llm-fail-output FILE` | `data/nvd-cves-desc_parse-fail.jsonl` | non-`ok` 결과 JSONL 경로 변경 |
| `--llm-adapter DIR` | `models/qwen3-merged800-20260723-155213` | `training_manifest.json`과 LoRA 가중치가 있는 adapter 디렉터리 |
| `--llm-nproc-per-node N` | `1` | 추론 GPU 프로세스 수. `2` 이상이면 `torchrun --standalone` 사용 |
| `--llm-batch-size N` | `2` | GPU 프로세스당 추론 batch 크기 |

다음 설정은 현재 명령행 옵션이 아니라 환경 변수로 조정한다.

| 환경 변수 | 기본값 | 의미 |
|---|---:|---|
| `NVD_LLM_MAX_INPUT_TOKENS` | `4096` | description prompt의 최대 입력 token 수. 최소 `256` |
| `NVD_LLM_MAX_NEW_TOKENS` | `512` | 생성할 binding JSON의 최대 token 수. 최소 `16` |
| `NVD_LLM_UPDATE_SCRIPT` | `utils/update_nvd_llm_parsed.py` | 증분 준비·적용 스크립트 변경 |
| `NVD_LLM_INFERENCE_SCRIPT` | `scripts/infer_nvd_cve_bindings.py` | 추론 스크립트 변경 |
| `NVD_LLM_INPUT_FILE` | 비어 있음 | 비어 있으면 최종 `--current-output` 값을 사용 |
| `NVD_LLM_PARSED_FILE` | `data/nvd-cves-desc_parse.jsonl` | 전체 parsed 결과 경로 |
| `NVD_LLM_FAIL_FILE` | `data/nvd-cves-desc_parse-fail.jsonl` | 실패 결과 경로 |
| `NVD_LLM_ADAPTER` | `models/qwen3-merged800-20260723-155213` | adapter 디렉터리 |
| `NVD_LLM_NPROC_PER_NODE` | `1` | GPU 프로세스 수 |
| `NVD_LLM_BATCH_SIZE` | `2` | GPU당 batch 크기 |
| `TORCHRUN_BIN` | `torchrun` | 멀티 GPU launcher 명령 |

동일한 설정 대부분은 `NVD_*`, `PYTHON_BIN`, `CURL_BIN`, `TORCHRUN_BIN` 환경 변수로도 지정할 수 있다. 명령행 옵션이 환경 변수에서 읽은 초기값을 덮어쓴다.

## 6. 세부 처리 알고리즘

### 6.1 인자와 실행 환경 검증

연도는 정확히 네 자리 숫자여야 하며 시작 연도가 종료 연도보다 클 수 없다. History page size, request delay, API 키 환경 변수 이름도 형식 검사를 통과해야 한다. 필요한 프로그램·Python 스크립트·추가 current 입력이 모두 읽을 수 있는지도 네트워크 요청 전에 확인한다.

### 6.2 단일 실행 lock과 staging 디렉터리

`flock`으로 `workspace/update_nvd_data.lock`의 exclusive lock을 획득한다. 다른 실행이 lock을 보유 중이면 종료하지 않고 대기한다.

Feed 디렉터리의 부모에 `.nvd-update.XXXXXX` 형태의 임시 디렉터리를 만들고 다운로드와 manifest 생성에 사용한다. 정상 종료 또는 오류 발생 시 trap으로 이 staging 디렉터리를 제거한다.

### 6.3 확인할 feed 집합 생성

`START_YEAR..END_YEAR`의 모든 연도별 feed에 다음 두 feed를 추가한다.

- `nvdcve-2.0-modified`
- `nvdcve-2.0-recent`

각 feed마다 먼저 작은 `.meta` 파일만 받는다. Metadata에는 유효한 64자리 SHA-256, 양수인 압축 해제 크기, `lastModifiedDate`가 모두 있어야 한다.

### 6.4 변경 여부 판단

로컬 JSON 크기가 원격 metadata의 `size`와 같고 로컬 `.meta`의 SHA-256도 같으면 해당 feed를 최신 상태로 판단해 본문 다운로드를 건너뛴다.

로컬 `.meta`가 없더라도 JSON의 실제 SHA-256이 원격 값과 같으면 JSON을 다시 받지 않고 metadata만 설치 대상으로 표시한다. `--force-download`가 지정되면 이 최적화를 사용하지 않는다.

### 6.5 다운로드와 무결성 검증

변경된 feed는 `.json.gz`를 staging 디렉터리로 다운로드한다. `curl`은 연결 실패와 일시 오류를 재시도하며, 다운로드 후 다음 검증을 순서대로 수행한다.

1. `gzip -t`로 gzip 구조 검사
2. 압축 해제된 JSON 크기와 metadata `size` 비교
3. JSON SHA-256과 metadata `sha256` 비교
4. 파일 앞부분에 NVD JSON 2.0 envelope 필드가 있는지 검사
   - `format: NVD_CVE`
   - `version: 2.0`
   - `timestamp`
   - `vulnerabilities` 배열

모든 변경 feed가 검증된 뒤에만 기존 feed 위치로 이동한다. 따라서 중간 다운로드 실패로 기존 정상 JSON이 먼저 덮어써지는 것을 막는다.

### 6.6 source manifest와 병합 판단

설치된 `nvdcve-2.0-*.json` 전체를 정렬해 임시 source manifest를 만든다. 각 행에는 feed 이름, SHA-256, 크기, 수정 시각이 들어간다.

다음 중 하나이면 병합 JSONL을 다시 만든다.

- `--force-merge` 사용
- 병합 JSONL이 없음
- 이전 source manifest가 없음
- 새 manifest와 이전 manifest가 다름

그 외에는 기존 `data/nvd-cves.jsonl`을 유지한다.

병합기는 JSON 전체를 메모리에 올리지 않고 `vulnerabilities` 배열을 스트리밍한다. 각 vulnerability 객체를 key 정렬 canonical JSON으로 만든 뒤 SHA-256 서명을 계산한다. 객체 전체 내용이 동일한 경우에만 중복으로 처리하므로, CVE ID가 같아도 내용이 다른 revision은 이 단계에서 임의로 합쳐지지 않는다. 중복 판정용 임시 SQLite를 사용하고 최종 JSONL은 기본적으로 CVE ID 순으로 출력한다.

### 6.7 Change History 다운로드와 안전한 재개

History downloader는 API 결과를 `pages/page-XXXXXXXXXXXX.json.gz` 단위로 저장한다. 완성된 페이지는 재실행 시 재사용하고 누락되거나 불완전한 페이지부터 이어받는다. `totalResults`가 증가하면 기존 완성 데이터 뒤에 새 페이지를 추가한다.

요청은 최소 delay를 지키며, 403·429·5xx 등 일시 오류에는 `Retry-After`, exponential backoff, 작은 random jitter를 적용한다. 모든 페이지가 검증된 후 한 줄에 하나의 `cveChanges` 항목을 갖는 `nvd-cve-history.jsonl.gz`를 원자적으로 만든다.

### 6.8 snapshot 기준 시각 계산

`--snapshot-as-of`가 없으면 source manifest에 있는 모든 feed의 `lastModifiedDate` 중 가장 이른 시각을 사용한다. 여러 feed 중 가장 오래된 coverage를 기준으로 해야 “이 시각 이전의 변경은 모든 feed에 반영됐다”고 보수적으로 말할 수 있기 때문이다.

어떤 feed라도 수정 시각이 없거나 형식이 잘못되면 자동 기준 시각을 만들지 않는다. 이 경우 current 유지기는 더 보수적으로 stale 여부를 판단한다.

### 6.9 current CVE 선택과 history 재생

Current 유지기는 기본 병합 JSONL과 반복 지정된 `--current-input`을 함께 읽는다.

동일 CVE ID의 후보가 여러 개면:

1. `lastModified`가 가장 큰 행 선택
2. 시간이 같으면 뒤에 지정한 input 우선
3. 같은 input이면 뒤쪽 행 우선

선택된 레코드는 다음 조건에서 quarantine으로 제외된다.

- 현재 `vulnStatus`가 `Rejected`
- 마지막 terminal history event가 `CVE Rejected`
- 최신 history가 로컬 본문과 snapshot coverage보다 새로워 본문이 낡음

`CVE Unrejected`가 뒤에 있으면 이전 terminal reject는 취소된다.

일반 description, CWE, CVSS를 history 문자열로 추정해 patch하지는 않는다. 다만 NVD가 완전한 CPE와 범위를 제공하는 `CPE Configuration` detail은 현재 레코드의 `lastModified` 이후 이벤트를 시간순으로 재생한다.

범위 병합 규칙은 다음과 같다.

- 같은 CPE identity의 새 범위가 기존 범위와 겹치면 최신 범위로 교체
- 분리된 범위면 기존 범위를 유지하고 새 범위를 추가
- `Removed`는 oldValue와 일치하는 범위만 제거
- `Changed`와 `CPE Deprecation Remap`은 oldValue 제거 후 newValue 반영
- 해석 불가능한 표현은 집계만 하고 원본 CVE는 훼손하지 않음
- non-vulnerable 플랫폼 조건과 vulnerable 제품 범위를 섞지 않음
- 더 최신인 구조화 `Affected` 범위가 같은 제품의 CPE 범위와 겹치면 최신 `Affected` 범위로 교체하고, 분리돼 있으면 추가

### 6.10 선택적 LLM 증분 추론과 결과 적용

`--update-llm-parsed`를 지정한 경우에만 current 처리 다음에 LLM 단계를 실행한다. `--llm-input`을 생략하면 옵션 해석이 끝난 시점의 `--current-output` 경로를 입력으로 사용한다.

LLM 단계는 동일한 전체 입력을 매번 다시 추론하지 않는다.

1. `utils/update_nvd_llm_parsed.py prepare`가 LLM 입력과 기존 parsed JSONL을 비교한다.
2. 새 CVE와 description이 변경된 CVE를 staging의 `nvd-cves.llm-pending.jsonl`에 기록하고, 이번 갱신 계약을 manifest에 기록한다.
3. pending 레코드가 있으면 `scripts/infer_nvd_cve_bindings.py`를 실행해 증분 결과를 만든다.
4. pending이 0건이면 모델을 로드하지 않고 빈 증분 파일을 만든다.
5. `utils/update_nvd_llm_parsed.py apply`가 입력, 기존 parsed 결과, pending manifest, 새 추론 결과를 검증·병합한다.
6. 전체 결과를 `--llm-parsed-output`에, `_meta.status`가 `ok`가 아닌 결과를 `--llm-fail-output`에 원자적으로 게시한다.

단일 GPU 프로세스에서는 다음 형태로 추론한다.

```text
python -u scripts/infer_nvd_cve_bindings.py ...
```

`--llm-nproc-per-node`가 2 이상이면 다음 형태로 각 GPU rank에 작업을 분배한다.

```text
torchrun --standalone --nproc-per-node=N scripts/infer_nvd_cve_bindings.py ...
```

추론기에 전달되는 값은 input, adapter, staging output, GPU당 batch 크기, 최대 입력 token, 최대 생성 token이다. 추론 결과의 `bindings: []`는 취약 제품이 없다는 정상 예측이고, `bindings: null`과 non-`ok` status는 입력 또는 추론 실패이므로 fail JSONL에서 점검해야 한다.

증분 임시 파일과 GPU별 shard는 feed staging 디렉터리에 만들어지며 스크립트 종료 시 제거된다. 따라서 이 통합 실행은 독립 추론 CLI의 `--resume`을 사용하지 않는다. 추론 도중 실패하면 기존 parsed 결과는 적용 전 상태로 남지만, 다음 실행에서는 이번 pending 건을 처음부터 다시 추론한다.

### 6.11 결과 게시

Current JSONL은 임시 파일 작성, flush/`fsync`, 원자 교체 순서로 게시한다. 실패하면 이전 정상 output이 유지된다. 제외 레코드는 quarantine에, 선택·제외·CPE history replay 통계는 report에 기록한다.

LLM 출력도 `apply` 단계에서 완전한 결과를 만든 뒤 원자 교체한다. update lock은 feed 갱신부터 LLM 적용 종료까지 유지되므로, 장시간 GPU 추론 중에도 동일 updater의 다른 실행은 lock에서 대기한다.

## 7. 옵션 조합 시 주의점

- `--no-merge`를 사용하면 current 생성도 자동으로 건너뛴다. 다만 History 갱신은 별도로 비활성화하지 않았으므로 계속 실행된다.
- `--no-history`는 API 호출만 생략한다. current 생성이 활성화돼 있으면 기존 history gzip이 반드시 있어야 한다.
- `--no-current`를 사용해도 feed 병합과 History 갱신은 실행된다.
- `--snapshot-as-of`에 파일 복사 시각이나 임의의 현재 시각을 넣으면 안 된다. NVD feed metadata 또는 API snapshot coverage 시각을 사용해야 한다.
- `--current-input`은 누락된 최신 CVE API 응답 등을 보충하는 용도다. 여러 번 지정할 수 있다.
- LLM 갱신은 기본 비활성이다. `--update-llm-parsed`가 없으면 `[llm] skipped` 로그만 출력한다.
- `--llm-input` 기본값은 `--current-output`의 최종 값이다. `--current-output`을 바꾸면 LLM 기본 입력도 함께 바뀐다.
- `--no-current` 또는 `--no-merge`를 사용해도 `--update-llm-parsed`까지 자동으로 꺼지지는 않는다. 이 조합에서는 디스크에 이미 있는 LLM 입력을 사용하므로, 의도한 snapshot인지 확인하거나 `--llm-input`을 명시해야 한다.
- 전체 병합 JSONL을 직접 LLM 입력으로 쓰려면 `--llm-input data/nvd-cves.jsonl`처럼 지정한다.
- parsed output과 fail output의 부모 디렉터리는 LLM 기능이 활성화되면 자동 생성된다.
- `NVD_LLM_MAX_INPUT_TOKENS`, `NVD_LLM_MAX_NEW_TOKENS`에는 각각 최소 `256`, `16` 이상의 정수를 넣어야 한다.
- 멀티 GPU 프로세스 수와 batch 크기는 양의 정수여야 한다. 프로세스 수가 2 이상일 때만 `torchrun` 존재 여부를 wrapper가 검사한다.

## 8. 실패와 재실행 특성

스크립트는 `set -Eeuo pipefail`로 실행되므로 실패한 명령, 정의되지 않은 변수, pipeline 내부 오류에서 즉시 중단한다.

- Feed 다운로드는 staging에서 검증한 뒤 설치한다.
- History는 페이지 단위라 중단 후 재개할 수 있다.
- 병합 manifest가 같으면 불필요한 재병합을 피한다.
- Current 결과는 원자 교체한다.
- LLM 추론 실패 시 `apply`가 실행되지 않으므로 기존 parsed/fail 결과는 유지된다.
- LLM 적용은 완전한 결과를 검증한 뒤 parsed/fail 파일을 갱신한다.
- LLM 증분 추론의 중간 shard는 staging에 있으므로 pipeline 재실행 간에는 보존되지 않는다.
- lock으로 동시에 두 updater가 같은 파일을 변경하는 것을 막는다.

따라서 일시적인 네트워크 오류가 해결된 뒤 같은 명령을 다시 실행하는 것이 기본 복구 방법이다.

## 9. 다음 단계

업데이트가 성공하면 기본 current 입력으로 정규화 DB를 만든다.

```bash
./02-1_run_build_db.sh
```

History 전후 및 LLM 사용 전후 비교가 필요하면:

```bash
./02-2_run_benchmark_builds.sh
```
