# `02-1_run_build_db.sh` 사용 및 처리 로직

## 1. 목적

`02-1_run_build_db.sh`는 history가 반영된 NVD current JSONL과 미리 생성된 LLM description 분석 결과를 하나의 NVD applicability SQLite DB로 컴파일하는 고정 실행 래퍼다.

```text
data/nvd-cves.current.jsonl
+ data/nvd-cves-desc_parse.jsonl
+ data/nvd-cves-desc_parse-fail.jsonl
→ NVD/CNA/LLM claim 정규화
→ 제품 identity 및 version assertion 구성
→ audit·integrity 검사
→ workspace/nvd_applicability.sqlite 원자 교체
```

이 스크립트는 DB를 질의하지 않는다. 이후 질의와 Git repository 매핑에서 사용할 정규화 DB를 생성하는 역할만 한다.

## 2. 기본 사용법

먼저 NVD current 입력을 준비한다.

```bash
cd ~/korea_univ/nvd_hbom_binder
export NVD_API_KEY='발급받은_API_키'
./01-1_update_nvd_data.sh
./02-1_run_build_db.sh
```

다른 current JSONL을 사용하려면 환경 변수로 지정한다.

```bash
NVD_BUILD_INPUT=data/nvd-cves.current.custom.jsonl ./02-1_run_build_db.sh
```

이 래퍼는 명령행 옵션을 해석하지 않는다. 입력 변경은 `NVD_BUILD_INPUT`으로만 가능하고, LLM 파일·출력 DB·progress 간격을 바꾸려면 `python -m scripts.nvd_normalization build`를 직접 실행해야 한다.

## 3. 고정 입력과 출력

| 구분 | 경로/값 | 설명 |
|---|---|---|
| NVD 입력 | `${NVD_BUILD_INPUT:-data/nvd-cves.current.jsonl}` | history 유지가 끝난 current CVE JSONL |
| LLM 성공 입력 | `data/nvd-cves-desc_parse.jsonl` | CVE description에서 추출한 구조화 binding |
| LLM 실패 입력 | `data/nvd-cves-desc_parse-fail.jsonl` | 실패·미완료 추출 정보 |
| 출력 DB | `workspace/nvd_applicability.sqlite` | 게시되는 applicability DB |
| 로그 | `logs/execute_YYYYMMDD_HHMMSS.log` | stdout/stderr 통합 timestamp 로그 |
| progress 간격 | `1000` | 1000 CVE마다 ingest 진행 상황 출력 |

실제 실행 명령은 다음과 같다.

```bash
python -u -m scripts.nvd_normalization build \
  --input data/nvd-cves.current.jsonl \
  --llm data/nvd-cves-desc_parse.jsonl \
  --llm-fail data/nvd-cves-desc_parse-fail.jsonl \
  --db workspace/nvd_applicability.sqlite \
  --replace \
  --progress-every 1000
```

`-u`는 Python 출력을 버퍼링하지 않아 로그에 진행 상황이 즉시 나타나게 한다.

## 4. 사전 조건

- `NVD_BUILD_INPUT` 파일이 읽을 수 있어야 한다.
- `python` 명령으로 프로젝트의 `scripts` 패키지를 import할 수 있어야 한다.
- LLM 성공/실패 JSONL이 기본 경로에 있어야 한다.
- `workspace/`와 `logs/`에 쓸 수 있어야 한다.

NVD 입력이 없으면 updater 실행 또는 `NVD_BUILD_INPUT` 지정 안내를 출력하고 exit code `2`로 종료한다. LLM 파일은 래퍼에서 미리 검사하지 않지만 Python 빌더가 시작 시 검사한다.

## 5. 래퍼의 실행 제어 로직

### 5.1 작업 디렉터리와 디렉터리 준비

스크립트 자신의 디렉터리로 이동한 뒤 `logs/`, `workspace/`를 만든다. 따라서 호출한 shell의 현재 디렉터리에 영향을 받지 않는다.

### 5.2 로그 pipeline

Python 빌드의 stdout과 stderr를 하나로 합치고, 모든 줄 앞에 `[YYYY-MM-DD HH:MM:SS]`를 붙인 뒤 화면과 로그 파일에 동시에 쓴다.

`tee`가 pipeline 마지막에 있어도 Python의 실제 exit code를 잃지 않도록 `PIPESTATUS[0]`을 읽어 최종 exit code로 사용한다. 빌드가 실패하면 로그 작성이 성공했더라도 스크립트 전체가 성공으로 보이지 않는다.

### 5.3 기존 DB 교체

항상 `--replace`를 전달한다. 단, 기존 DB를 먼저 지우는 방식이 아니다. Python 빌더가 같은 디렉터리에 임시 DB를 완성하고 audit과 integrity 검사를 모두 통과한 뒤 `os.replace`로 대상 DB를 교체한다.

## 6. 정규화 DB의 세부 처리 알고리즘

### 6.1 입력 pre-pass와 중복 revision 선택

JSONL을 본격적으로 처리하기 전에 CVE ID 중복을 찾는다. 같은 CVE가 여러 행에 있으면 `lastModified`가 가장 큰 revision을 선택하고, 시간이 같으면 뒤쪽 source index를 선택한다.

대부분의 행은 앞부분에서 CVE ID만 빠르게 읽고, 실제 중복 후보만 완전 JSON parse하여 대용량 입력의 비용을 줄인다. 중복 제거 사실과 예시는 DB의 normalization issue에 기록한다.

### 6.2 임시 DB와 build provenance 생성

최종 DB 옆에 PID가 포함된 임시 DB를 만들고 schema를 초기화한다. 입력 경로·크기·mtime·rule/framework/LLM schema를 바탕으로 snapshot, pipeline run, binding revision 식별자를 만든다.

LLM 입력을 사용하면 LLM extraction run도 기록한다. 제공된 legacy LLM JSONL에는 model revision, prompt hash, self-consistency metadata가 없으므로 해당 claim은 엄격한 확정 근거가 아니라 provisional 근거로 제한된다.

### 6.3 CVE raw ingest

각 JSONL 행을 순차 처리하면서 다음 정보를 보존한다.

- CVE ID, source identifier, `vulnStatus`
- published/lastModified
- primary description과 원문 description들
- 원본 byte offset, 길이, SHA-256
- CPE/CNA/LLM 근거 존재 여부
- enrichment class와 admission status

JSON parse 오류는 전체 빌드를 즉시 버리기보다 issue로 기록하고 해당 행을 제외한다. NVD status가 `Rejected`인 CVE는 raw provenance에는 남지만 applicability claim 생성 대상에서는 제외된다.

### 6.4 CNA product와 version claim 구성

CNA `affected` 구조에서 vendor/product를 정규화해 product entity와 raw alias를 만든다. Version 항목의 status, `lessThan`, `lessThanOrEqual`, default status를 읽어 version expression과 segment로 컴파일한다.

Placeholder, malformed, 해석 불가능한 범위는 확정 assertion으로 사용하지 않고 quarantine/review 상태와 issue로 남긴다. CNA의 `version=0` lower bound와 upper bound처럼 NVD에서 흔히 사용하는 표현도 보수적인 규칙으로 실제 범위에 anchoring한다.

### 6.5 NVD CPE configuration 구성

NVD configuration graph의 논리 구조와 각 CPE match를 보존한다. CPE 2.3의 vendor, product, part, version 및 시작/종료 포함·제외 경계를 축별 scope와 version segment로 컴파일한다.

직접 CNA 제품과 일치하는 CPE는 직접 upstream 역할을 얻을 수 있고, OS·hardware·platform 조건은 별도 role/scope로 유지한다. Placeholder CPE나 malformed claim은 binding에 무리하게 포함하지 않고 quarantine 또는 manual review 상태로 보존한다.

### 6.6 LLM 결과 결합

LLM 결과는 JSONL 행 번호가 아니라 `cve_id`로 결합한다. 현재 CVE의 primary description과 LLM 레코드의 description이 정확히 일치하고 status와 binding 구조가 정상일 때만 claim을 materialize한다.

CVE ID는 같지만 description이 바뀐 결과, 실패 파일의 결과, join되지 않은 행은 감사 정보로 집계하되 strict positive를 만들지 않는다. LLM만으로 생긴 product binding은 `provisional_llm_identity`로 표시된다.

### 6.7 Assertion reconciliation과 binding 생성

같은 CVE/product에 여러 source claim이 있으면 evidence 우선순위, version 범위의 포함 관계, polarity, source 독립성을 비교한다.

- 같은 의미의 근거는 corroborating으로 축약
- 낮은 우선순위의 중복·포함 범위는 suppress
- 서로 모순되며 자동 결정할 수 없으면 `conflict_review`
- parse되지 않은 범위는 `unparsed_review`

최종적으로 active 또는 conflict-review assertion만 binding의 활성 member가 된다. unresolved role이나 conflict가 남으면 `manual_review_required`가 설정된다.

### 6.8 Identity key·edge·cluster materialization

Ingest가 끝난 뒤 product entity 자체를 합치지 않고 별도의 identity 계층을 만든다.

```text
raw product spelling
→ safe/separator/legal-root/org-root/acronym/digit-signature key
→ evidence가 있는 identity edge
→ accepted strict edge의 identity cluster
```

Separator collision, part 불일치, 숫자 signature, hard-distinct 규칙을 통과한 근거만 strict alias가 될 수 있다. Acronym, 조직 suffix, CNA×CPE 동시 출현 같은 약한 근거는 candidate/provisional로 제한한다.

### 6.9 Alias 기반 role 재분류

Identity cluster가 완성되기 전에는 unresolved CPE를 섣불리 직접 제품으로 승격하지 않는다. Materialization이 끝난 뒤 strict accepted cluster만 사용해 CNA 제품과 연결되는 unresolved CPE role을 다시 판정한다.

이 재분류로 확실한 alias 경로가 생기면 불필요한 manual-review flag를 해제할 수 있지만, provisional edge로 strict role을 새로 만들지는 않는다.

### 6.10 Publish audit

게시 전에 assertion/source claim 연결, active binding, version expression, identity cluster, alias role, foreign-key 관계 등 semantic invariant를 검사한다. 하나라도 critical count가 0이 아니면 publish를 중단하고 임시 DB를 삭제한다.

LLM을 사용한 정상 빌드는 LLM provenance 부족 때문에 `publish_health=degraded_llm_provisional`로 표시될 수 있다. 이는 DB 생성 실패가 아니라 LLM 근거를 strict로 승격하지 않았다는 의미다.

### 6.11 Index와 integrity 검사 후 원자 교체

Ingest용 임시 index를 제거하고 조회용 permanent index를 생성한다. SQLite foreign-key check와 quick/integrity 검사를 통과하면 임시 DB를 `workspace/nvd_applicability.sqlite`로 원자 교체한다.

입력 파일의 size나 mtime이 빌드 도중 변한 경우에도 실패 처리한다. 실패 시 임시 DB만 제거되고 기존 게시 DB는 유지된다.

## 7. 진행 로그 읽는 법

일반 진행 행에는 처리 CVE 수, 현재 CVE ID, claim/assertion/binding 누적 수가 표시된다. 후처리 단계는 JSON 형태의 stage event로 기록된다.

대표 stage:

1. `source_ingest`
2. `post_ingest_indexes`
3. `identity_materialization`
4. `alias_role_reclassification`
5. `publish_audit`
6. `permanent_indexes`
7. `integrity_check`

마지막에 `종료 코드: 0`이면 원자 교체까지 완료된 것이다.

## 8. 다른 형태의 빌드

LLM 없이 smoke build:

```bash
python -u -m scripts.nvd_normalization build \
  --input data/nvd-cves.current.jsonl \
  --without-llm \
  --db workspace/nvd_applicability_smoke.sqlite \
  --replace \
  --limit 1000
```

Progress event를 끄려면:

```bash
python -u -m scripts.nvd_normalization build \
  --input data/nvd-cves.current.jsonl \
  --llm data/nvd-cves-desc_parse.jsonl \
  --llm-fail data/nvd-cves-desc_parse-fail.jsonl \
  --db workspace/nvd_applicability.sqlite \
  --replace \
  --progress-every 0
```

## 9. 생성 후 확인

DB의 semantic audit를 다시 실행하려면:

```bash
python -m scripts.nvd_normalization audit \
  --db workspace/nvd_applicability.sqlite \
  --full-integrity
```

제품/version 질의 예:

```bash
python -m scripts.nvd_normalization query \
  --db workspace/nvd_applicability.sqlite \
  --vendor openssl \
  --product openssl \
  --version 3.0.12 \
  --all-states --trace --format json
```

Git repository→CVE DB를 만들려면 이 DB가 `scripts/build_git_repo_cve_mapping.py`의 기본 입력이 된다.
