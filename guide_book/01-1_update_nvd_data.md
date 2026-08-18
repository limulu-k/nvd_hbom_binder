# `01-1_update_nvd_data.sh` 사용 및 처리 로직

## 1. 목적

`01-1_update_nvd_data.sh`는 NVD 원본 데이터를 내려받는 작업부터 정규화 DB의 입력으로 사용할 current-only JSONL을 만드는 작업까지 한 번에 수행한다.

전체 흐름은 다음과 같다.

```text
NVD JSON 2.0 연도별/최근/수정 feed 확인
→ 변경된 feed만 다운로드·검증
→ 전체 feed를 하나의 JSONL로 병합
→ NVD CVE Change History 전체 데이터 갱신
→ 최신 CVE 본문과 Change History를 조합
→ current JSONL + quarantine + report 게시
```

이 스크립트는 항상 자신의 위치, 즉 프로젝트 루트로 이동한 뒤 상대 경로를 해석한다. 어느 디렉터리에서 호출해도 기본 파일 위치는 프로젝트 루트 기준이다.

## 2. 기본 사용법

Change History API를 갱신하려면 NVD API 키가 필요하다.

```bash
cd ~/korea_univ/cve_binder
export NVD_API_KEY='발급받은_API_키'
./01-1_update_nvd_data.sh
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

동일한 설정 대부분은 `NVD_*`, `PYTHON_BIN`, `CURL_BIN` 환경 변수로도 지정할 수 있다. 명령행 옵션이 환경 변수에서 읽은 초기값을 덮어쓴다.

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

### 6.10 결과 게시

Current JSONL은 임시 파일 작성, flush/`fsync`, 원자 교체 순서로 게시한다. 실패하면 이전 정상 output이 유지된다. 제외 레코드는 quarantine에, 선택·제외·CPE history replay 통계는 report에 기록한다.

## 7. 옵션 조합 시 주의점

- `--no-merge`를 사용하면 current 생성도 자동으로 건너뛴다. 다만 History 갱신은 별도로 비활성화하지 않았으므로 계속 실행된다.
- `--no-history`는 API 호출만 생략한다. current 생성이 활성화돼 있으면 기존 history gzip이 반드시 있어야 한다.
- `--no-current`를 사용해도 feed 병합과 History 갱신은 실행된다.
- `--snapshot-as-of`에 파일 복사 시각이나 임의의 현재 시각을 넣으면 안 된다. NVD feed metadata 또는 API snapshot coverage 시각을 사용해야 한다.
- `--current-input`은 누락된 최신 CVE API 응답 등을 보충하는 용도다. 여러 번 지정할 수 있다.

## 8. 실패와 재실행 특성

스크립트는 `set -Eeuo pipefail`로 실행되므로 실패한 명령, 정의되지 않은 변수, pipeline 내부 오류에서 즉시 중단한다.

- Feed 다운로드는 staging에서 검증한 뒤 설치한다.
- History는 페이지 단위라 중단 후 재개할 수 있다.
- 병합 manifest가 같으면 불필요한 재병합을 피한다.
- Current 결과는 원자 교체한다.
- lock으로 동시에 두 updater가 같은 파일을 변경하는 것을 막는다.

따라서 일시적인 네트워크 오류가 해결된 뒤 같은 명령을 다시 실행하는 것이 기본 복구 방법이다.

## 9. 다음 단계

업데이트가 성공하면 기본 current 입력으로 정규화 DB를 만든다.

```bash
./02-1_run_build_db.sh
```

History 전후 및 LLM 사용 전후 비교가 필요하면:

```bash
./03_run_benchmark_builds.sh
```
