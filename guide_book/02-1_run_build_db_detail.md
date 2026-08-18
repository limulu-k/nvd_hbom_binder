# `02-1_run_build_db.sh` 상세 알고리즘 가이드

## 1. 문서 범위

이 문서는 `02-1_run_build_db.sh`를 실행했을 때 내부적으로 수행되는 NVD applicability DB 구축 과정을 설명한다. 파일에 `run_build_db.py`라는 이름의 진입점은 없으며, 실제 실행 구조는 다음과 같다.

```text
02-1_run_build_db.sh
  └─ python -m scripts.nvd_normalization build
       └─ Python 정규화·DB 구축 파이프라인
```

따라서 여기서는 Python 함수의 호출 목록이나 코드 문법을 나열하지 않고, 입력 데이터가 어떤 판정과 변환을 거쳐 최종 SQLite DB가 되는지를 설명한다.

현재 빌더의 주요 버전은 다음과 같다.

| 구분 | 값 |
|---|---|
| 프레임워크 | `nvd-applicability-3.3.3-llm-safe-admission` |
| 규칙 버전 | `3.3.3-llm-safe-admission.1` |
| DB 스키마 | `5` |
| 프로파일 버전 | `1.0.0` |
| 실패 분류 체계 | `1.1` |

---

## 2. 실제 실행 명령과 입출력

`02-1_run_build_db.sh`는 프로젝트 루트 기준으로 사실상 아래 명령을 고정 실행한다.

```bash
python -u -m scripts.nvd_normalization build \
  --input data/nvd-cves.current.jsonl \
  --llm data/nvd-cves-desc_parse.jsonl \
  --llm-fail data/nvd-cves-desc_parse-fail.jsonl \
  --db workspace/nvd_applicability.sqlite \
  --replace \
  --progress-every 1000
```

기본 NVD 입력만 환경 변수로 바꿀 수 있다.

```bash
NVD_BUILD_INPUT=/path/to/another.jsonl bash 02-1_run_build_db.sh
```

| 용도 | 경로 |
|---|---|
| 기본 NVD 입력 | `data/nvd-cves.current.jsonl` |
| LLM 성공 결과 | `data/nvd-cves-desc_parse.jsonl` |
| LLM 실패 결과 | `data/nvd-cves-desc_parse-fail.jsonl` |
| 최종 DB | `workspace/nvd_applicability.sqlite` |
| 실행 로그 | `logs/execute_YYYYMMDD_HHMMSS.log` |

`--replace`가 항상 전달되므로 기존 DB가 있더라도 새 DB가 성공적으로 완성되면 교체한다. 다만 기존 파일 위에서 직접 수정하지는 않는다. 임시 DB를 따로 만든 뒤 모든 검증에 통과한 경우에만 원자적으로 교체한다.

---

## 3. 전체 흐름 한눈에 보기

```text
입력 파일 검증
  ↓
중복 CVE 사전 스캔
  ├─ lastModified가 가장 최신인 행 선택
  └─ 같으면 뒤쪽 source index 선택
  ↓
임시 SQLite DB 생성 및 메타데이터 고정
  ↓
CVE별 원본·설명 저장
  ↓
CNA affected + NVD configurations 파싱
  ↓
제품 식별자 정규화
  ↓
버전 표현식 → 의미가 명확한 구간(segment)으로 컴파일
  ↓
출처 주장(source claim) + 적용성 assertion 생성
  ↓
LLM 결과 안전 수용
  ├─ 원문 grounding 확인
  ├─ 구조화 근거가 있으면 LLM 결정은 제외
  └─ 수용하더라도 provisional/potentially_affected로 제한
  ↓
제품별 assertion 조정(reconciliation)
  ├─ 중복 근거 정리
  ├─ 상반된 affected/unaffected 비교
  └─ 자동 해결 불가 시 conflict_review
  ↓
CVE-product binding 구성
  ↓
제품 동일성(identity) 그래프와 클러스터 생성
  ↓
엄격한 alias 경로로 unresolved NVD 역할 재분류
  ↓
전체 스냅샷 감사(audit)
  ↓
영구 인덱스·통계·무결성 검사
  ↓
임시 DB를 최종 DB로 원자적 교체
```

핵심은 “파싱된 모든 값을 곧바로 affected로 넣는 것”이 아니다. 원본 근거를 보존하면서 제품, 범위, 출처의 신뢰도를 분리하고, 안전하게 사용할 수 있는 assertion만 활성화 및 인덱싱한다.

---

## 4. 빌더가 만드는 논리적 데이터 계층

한 CVE가 최종 DB에 들어갈 때 데이터는 다음 계층으로 나뉜다.

1. **원본 계층**: CVE 행, 설명, 원본 위치, 해시를 보존한다.
2. **제품 계층**: CNA/NVD/LLM에 등장한 vendor-product를 정규화하되 원래 엔티티를 강제로 합치지 않는다.
3. **근거 계층**: 각 출처가 무엇을 주장했는지 `source_claim`으로 남긴다.
4. **버전 계층**: 문자열 범위를 비교 가능한 `version_expression`과 `version_segment`로 변환한다.
5. **적용성 계층**: 제품·스코프·버전·극성(affected/unaffected)을 assertion으로 표현한다.
6. **조정 계층**: 중복 및 충돌을 판정하고 assertion 상태를 정한다.
7. **바인딩 계층**: CVE와 제품의 현재 적용성 묶음을 만든다.
8. **동일성 계층**: 표기만 다른 vendor/product 후보를 그래프로 연결하고 안전한 클러스터를 만든다.
9. **배포 계층**: 감사에 통과한 revision만 `published`로 전환한다.

이 분리 덕분에 “원본에는 있었지만 안전한 질의에는 쓰면 안 되는 값”도 삭제하지 않고 추적할 수 있다.

---

## 5. 단계 0: 실행 환경과 입력 스냅샷 고정

### 5.1 셸 실행 안전성

스크립트는 `set -Eeuo pipefail`을 사용한다. 명령 실패, 선언되지 않은 변수 사용, 파이프 내부 Python 실패를 정상 종료로 오인하지 않는다. 로그 파이프 뒤에서도 Python의 종료 코드를 `PIPESTATUS[0]`으로 보존한다.

Python 표준 출력과 오류 출력은 합쳐지고, 각 줄에 시각을 붙여 로그와 터미널에 동시에 기록된다. 진행 로그는 기본적으로 입력 **1,000행마다** 출력된다. 이 값은 판정 임계값이 아니라 관측용 성능 설정이다.

### 5.2 파일 유효성 및 불변성

빌드 시작 시 NVD 입력, LLM 성공 파일, LLM 실패 파일을 확인한다. NVD 입력은 빌드 중 다른 프로세스가 교체하거나 수정하면 안 된다.

빌더는 시작 시 입력 파일의 크기와 수정 시각을 저장하고 종료 전 다시 확인한다. 둘 중 하나라도 바뀌면 빌드를 실패시킨다. 즉 한 DB 안에 서로 다른 시점의 스냅샷이 섞이는 것을 막는다.

### 5.3 임시 DB 전략

목표가 다음이라면:

```text
workspace/nvd_applicability.sqlite
```

실제 구축은 다음 형식의 별도 파일에서 진행한다.

```text
workspace/nvd_applicability.sqlite.tmp.<PID>
```

예외, 감사 실패, 무결성 실패가 발생하면 임시 DB를 닫고 제거한다. 기존 최종 DB는 그대로 남는다. 최종 성공 시에만 `os.replace` 의미의 원자적 교체를 수행한다.

---

## 6. 단계 1: 중복 CVE 사전 스캔

전체 변환 전에 JSONL을 한 번 훑어 동일 CVE가 여러 번 등장하는지 확인한다.

### 6.1 CVE ID 빠른 추출

각 줄 전체를 무조건 JSON 파싱하지 않고, 줄의 앞부분 **최대 512바이트**에서 정규식으로 CVE ID를 먼저 찾는다. 이는 사전 스캔 비용을 낮추기 위한 최적화이며 판정 정책은 아니다.

### 6.2 승자 선택 순서

동일한 CVE ID가 여러 행에 있으면 다음 우선순위로 하나만 채택한다.

1. `lastModified`가 더 최신인 행
2. `lastModified`가 같으면 source index가 더 큰 행, 즉 파일에서 뒤에 있는 행

탈락 행의 인덱스도 기록하여 본 처리 단계에서 건너뛴다. 중복 사례는 normalization issue에 남기되 예시는 **최대 20개**까지만 저장한다.

`--limit`를 사용할 경우 제한은 고유 CVE 개수가 아니라 **원본의 처음 N개 행**에 적용된다. 중복 제거 후 결과 행 수는 N보다 작을 수 있다.

---

## 7. 단계 2: DB 초기화와 구축 상태 기록

임시 DB에 스키마를 만들고 다음 종류의 메타데이터를 먼저 고정한다.

- 프레임워크·규칙·스키마 버전
- 정규화 정책과 임계값
- identity registry 버전과 SHA
- 입력 스냅샷 정보
- pipeline run과 binding revision

초기 revision의 publish health는 `blocked_incomplete_materialization`이다. 따라서 빌드 도중 생성된 파일을 실수로 정상 DB처럼 해석할 수 없다.

대량 적재 중에는 성능을 위해 SQLite를 다음과 같이 운용한다.

| 설정 | 값 | 의미 |
|---|---:|---|
| `foreign_keys` | `OFF` | 적재 중 행 단위 FK 검사를 미루고 마지막에 전체 검사 |
| `journal_mode` | `OFF` | 임시 DB 구축 속도 우선 |
| `synchronous` | `OFF` | 임시 산출물이므로 디스크 동기화 비용 축소 |
| `temp_store` | `MEMORY` | 임시 구조를 메모리에 우선 저장 |
| `cache_size` | `-262144` | 약 262,144 KiB, 즉 약 256 MiB 캐시 |
| 트랜잭션 | `BEGIN IMMEDIATE` | 구축 단위를 하나의 명확한 쓰기 트랜잭션으로 관리 |

이 설정은 최종 DB의 의미를 바꾸는 threshold가 아니라, 실패 시 버릴 수 있는 임시 DB를 빠르게 만드는 성능 정책이다.

---

## 8. 단계 3: CVE 원본 적재와 데이터 출처 분류

각 채택 CVE 행에 대해 원본 추적 정보를 먼저 저장한다.

- CVE ID
- 원본 파일 offset과 length
- 원본 행 SHA
- source identifier
- 취약점 상태와 생성·수정 시각
- 대표 설명
- CPE/CNA/LLM 데이터 존재 여부
- enrichment 분류

enrichment는 다음과 같이 분류한다.

| 조건 | 분류 |
|---|---|
| upstream에서 rejected | `rejected` |
| NVD CPE/configuration 존재 | `nvd_enriched` |
| CNA affected만 존재 | `cna_only` |
| 둘 다 없음 | `unenriched` |

상태가 `Rejected`인 CVE도 원본 provenance와 `rejected_upstream` 상태는 남긴다. 그러나 제품 claim, assertion, binding은 만들지 않는다.

JSON 파싱 자체가 실패하면 issue를 기록하고 그 행의 정규화 처리는 건너뛴다. 설명은 모두 보존하면서 대표 설명 하나를 선택해 이후 LLM grounding의 기준 텍스트로 사용한다.

---

## 9. 단계 4: 제품 식별자 정규화

### 9.1 정규화 규칙

vendor/product 비교용 key는 다음 순서로 만든다.

```text
Unicode NFKC
  → casefold
  → 앞뒤 공백 제거
  → 단어가 아닌 구분자들을 `_`로 접기
  → 양끝 `_` 제거
```

이 단계는 대소문자나 구분자 차이를 안정적으로 비교하기 위한 것이다. 편집 거리 기반 fuzzy merge는 여기서 수행하지 않는다.

다음 값은 의미 있는 식별자가 아닌 placeholder로 취급한다.

```text
빈 문자열, *, -, n/a, na, none, null, unknown, unspecified
```

### 9.2 출처별 제품 생성

#### CNA 제품

- product가 placeholder면 제품 엔티티를 만들지 않는다.
- vendor가 placeholder면 product를 canonical vendor 대체값으로 사용한다.
- part는 `unknown`이다.
- label priority는 `1`이며 authoritative 입력으로 취급한다.

#### NVD CPE 제품

- CPE의 vendor, product, part를 사용한다.
- label priority는 `4`이다.
- CPE가 제공하는 구조화된 제품 좌표를 보존한다.

#### LLM 제품

- part는 `unknown`이다.
- label priority는 `6`이다.
- 언제나 provisional이며 기존 구조화 제품을 덮어쓰지 않는다.

원본 `product_entity`들은 이 시점에 서로 병합되지 않는다. 나중 identity graph가 “같을 가능성”을 별도 계층에 표현한다.

---

## 10. 단계 5: NVD CPE의 역할과 스코프 판정

NVD configuration의 CPE 하나가 등장했다고 해서 모두 취약 소프트웨어로 간주하지 않는다. 먼저 CPE의 `vulnerable` 값과 제품 역할을 판정한다.

### 10.1 `vulnerable=false`

`vulnerable=false`인 CPE는 affected assertion을 만들지 않는다.

- part가 `h`이면 `REQUIRED_HARDWARE`
- 그 외에는 `REQUIRED_PLATFORM`

즉 “취약 제품”이 아니라 취약점이 성립하기 위한 환경 조건으로 보존한다. 원본 claim과 configuration 조건 자체는 사라지지 않는다.

### 10.2 `vulnerable=true` 역할 분류 순서

다음 순서로 역할을 결정한다.

1. vendor와 product가 명시적 배포판 registry에 있으면 `DOWNSTREAM_DISTRIBUTION`
2. 같은 CVE의 CNA direct product와 정규화 identity가 정확히 같으면 `DIRECT_UPSTREAM`
3. 명백한 패키지 배포판 vendor 규칙에 맞으면 `DOWNSTREAM_PACKAGE`
4. 나머지는 `UNRESOLVED`

초기 스트리밍 단계에는 아직 alias cluster가 완성되지 않았으므로 alias를 이용해 direct upstream이라고 단정하지 않는다. 뒤의 strict alias 재분류 단계에서만 안전하게 승격한다.

### 10.3 스코프 축

CPE 조건은 단순 vendor/product 외에도 다음 축으로 표현한다.

```text
part, distribution, edition, component, update,
language, sw_edition, target_sw, target_hw, other
```

각 축의 상태는 `ANY`, `UNKNOWN`, `EXACT`, `SET`, `NOT_APPLICABLE` 중 하나다.

- 하나라도 `UNKNOWN`이면 scope는 unresolved이다.
- specificity는 구체적인 `EXACT`, `SET`, `NOT_APPLICABLE` 축 수로 계산한다.
- 다만 evidence tuple에 들어가는 scope specificity는 **최대 3**으로 제한한다.

### 10.4 버전 인덱스 허용 조건

NVD assertion이 버전 질의용 인덱스에 들어가려면 모두 만족해야 한다.

- 역할이 `DIRECT_UPSTREAM` 또는 `DIRECT_ALTERNATIVE_PRODUCT`
- 버전 파싱 성공
- scope resolved
- version class가 `EXACT`, `BOUNDED_RANGE`, `UNBOUNDED_RANGE`, `BRANCH_RANGE`

역할이 downstream/unresolved이거나 version class가 `CPE_ANY`, `UNSPECIFIED`, `UNPARSED`이면 `use_for_version_index=false`이다. 이런 assertion의 판정 상한은 `potentially_affected`로 제한된다.

---

## 11. 단계 6: 버전 문자열을 구간으로 컴파일

빌더는 버전 문자열을 그대로 비교하지 않는다. 먼저 제품에 맞는 비교 프로파일을 선택하고, 표현식을 0개 이상의 명확한 segment로 변환한다.

### 11.1 비교 프로파일 선택

기본 프로파일은 `semver`, `deb`, `dotted_numeric`, `opaque` 계열이다.

- 제품 이름에 `openssl`이 있으면 OpenSSL 전용 프로파일
- 제품 이름에 `imagemagick`이 있으면 ImageMagick 전용 프로파일
- 구체 버전들이 모두 점으로 구분된 숫자면 `dotted_numeric`
- 의미 있는 비교 규칙을 안전하게 선택할 수 없으면 `opaque`

버전 비교 보조 결과는 **65,536개** LRU cache를 사용한다. 이는 성능 한도이며 의미 판정 threshold가 아니다.

### 11.2 NVD 범위 컴파일

NVD CPE의 시작/끝 경계 필드를 기준으로 분류한다.

| 입력 형태 | 결과 class |
|---|---|
| 시작과 끝이 모두 있음 | `BOUNDED_RANGE` |
| 한쪽 경계만 있음 | `UNBOUNDED_RANGE` |
| 범위 없이 구체 버전 | `EXACT` |
| 범위 없이 `*` | `CPE_ANY_UNCORROBORATED` |
| `-` 또는 `n/a` | `NOT_APPLICABLE` |
| 빈 값 | `UNSPECIFIED` |

같은 시작점에 inclusive와 excluding이 동시에 있거나, 같은 끝점에 둘이 동시에 있으면 의미가 충돌하므로 `UNPARSED`와 `conflicting_nvd_bounds` issue가 된다.

### 11.3 CNA 범위 컴파일

CNA의 `versions[]`는 구조가 더 다양하므로 다음 규칙을 적용한다.

#### 전체 버전 표현

`all`, `all versions`, 또는 상한 없는 `*`는 `EXPLICIT_ALL`이다.

#### 비교 연산자

`<`, `<=`, `>`, `>=`, `=`만 단순하고 모호하지 않은 형태에서 허용한다.

다음은 자동 해석하지 않고 `UNPARSED`로 보낸다.

- `!=`
- 같은 방향 경계가 여러 개 있는 식
- exact와 range가 한 식에 혼합된 경우
- 중첩되거나 문법이 불완전한 comparator
- 구조화 필드와 문자열 comparator가 서로 충돌하는 경우

`lessThan`은 `<`, `lessThanOrEqual`은 `<=` 의미여야 한다. 양쪽 필드가 충돌하거나 서로 다른 끝점을 주장하면 자동 선택하지 않는다.

#### 구조화 상한과 시작점

`lessThan*`가 있을 때 `version`이 정확히 `0` 또는 placeholder이면 시작 경계가 없는 것으로 취급한다. 그 외에는 `version`을 inclusive lower bound로 사용한다.

#### branch 표현

`N.x`, `N.*` 형태는 `BRANCH_RANGE`로 변환한다. 반면 명시적 endpoint인 `<=4.2`의 `4.2`는 `4.2.x`가 아니라 문자 그대로의 정확한 끝점이다.

#### 기본 분류

- 양쪽 경계가 있으면 `BOUNDED_RANGE`
- 한쪽만 있으면 `UNBOUNDED_RANGE`
- 구체 단일 값이면 `EXACT`
- not-applicable 값이면 `NOT_APPLICABLE`
- 값이 없으면 `UNSPECIFIED`

### 11.4 CNA `changes[]` 처리

`changes[]`는 특정 버전 지점에서 affected 상태가 바뀌는 transition으로 해석한다.

1. 각 `at` 지점을 버전 프로파일로 정렬 가능한지 확인한다.
2. 각 change의 status가 유효한지 확인한다.
3. 초기 범위 아래의 transition, 역순 transition, 해석 불가능한 transition을 거부한다.
4. 유효한 transition 지점을 기준으로 원래 범위를 여러 segment로 분할한다.
5. 원래 upper bound 바깥의 transition은 결과 구간에서 제외한다.

감사 단계에서는 `changes_outside_upper_bound` 결함이 남지 않아야 한다. 허용되지 않은 형태가 조용히 정상 assertion으로 들어가는 것을 막기 위한 조건이다.

### 11.5 CNA zero-lower anchoring

CNA가 `version: "0"`과 상한만 제공할 때, `0`을 실제 제품의 최소 버전이라고 성급히 확정하지 않는다. NVD의 더 구체적인 하한을 빌려올 수 있는지 다음 조건으로 확인한다.

1. 원본 version이 정확히 `0`
2. status가 affected
3. 파싱 성공
4. 비교 프로파일이 opaque가 아님
5. 같은 제품 identity에서 서로 다른 zero-lower upper endpoint가 **최소 2개** 존재
6. 같은 upper endpoint와 inclusivity를 가진 NVD 후보가 존재
7. NVD 후보가 unbounded가 아니고, 유효한 lower candidate가 **정확히 1개**

모두 만족하면 NVD lower bound를 CNA segment에 복사하여 `BOUNDED_RANGE`로 구체화할 수 있다. 후보가 0개, 2개 이상이거나 NVD 쪽도 unbounded라면 anchor하지 않는다.

### 11.6 `defaultStatus`

- `defaultStatus`가 없으면 effective status는 unknown이며 inferred 상태로 기록하고 default assertion은 만들지 않는다.
- 명시적 `affected` 또는 `unaffected`이면 명시 version segment 외의 전체 branch를 덮는 closure assertion을 만든다.
- `versions`와 `defaultStatus`가 모두 없으면 malformed로 격리하고 high severity issue를 남긴다.
- 개별 version의 version/status가 빠져도 high severity issue를 남기고 해당 항목을 건너뛴다.

최종적으로 한 입력 표현식이 transition과 default closure에 의해 여러 assertion segment로 나뉠 수 있다.

---

## 12. 단계 7: assertion의 신뢰도 계산

각 assertion은 단일 점수 하나가 아니라 다음 7차원 evidence tuple을 갖는다.

```text
(authority,
 structuredness,
 scope_specificity,
 version_specificity,
 directness,
 freshness,
 corroboration)
```

### 12.1 차원별 값

#### Authority

| 출처 | 값 |
|---|---:|
| CNA, manual | 3 |
| OSV, GHSA | 2 |
| NVD | 1 |
| LLM, rule | 0 |

#### Structuredness

| 출처 | 값 |
|---|---:|
| CNA, manual, OSV, GHSA, NVD | 2 |
| LLM, rule | 1 |
| 일반 advisory | 0 |

#### Version specificity

| version class | 값 |
|---|---:|
| `EXACT` | 4 |
| `BOUNDED_RANGE`, `BRANCH_RANGE` | 3 |
| `UNBOUNDED_RANGE` | 2 |
| `EXPLICIT_ALL` | 1 |
| `CPE_ANY`, `UNSPECIFIED`, `UNPARSED`, `NOT_APPLICABLE` | 0 |

#### Directness

| 역할 | 값 |
|---|---:|
| direct upstream | 2 |
| direct alternative | 1 |
| 그 외 | 0 |

scope specificity는 최대 **3**, freshness와 corroboration은 각각 최대 **2**로 제한한다.

### 12.2 비교 순서와 예외 규칙

기본 비교는 tuple의 앞 차원부터 사전식으로 비교한다. 단 두 가지 안전성 우선 규칙이 있다.

1. **Version specificity override**: 구체 버전 specificity가 0보다 크면 specificity 0인 근거를 이긴다.
2. **Directness override**: direct upstream 값 2는 non-direct 값 0을 이긴다.

즉 출처 권위만 높다고 해서 버전이 전혀 없는 주장이나 간접 배포판 주장이 구체적인 직접 제품 근거를 무조건 누르지 못한다.

---

## 13. 단계 8: LLM 결과의 안전 수용

LLM 파일은 NVD 행 번호가 아니라 `cve_id`로 결합한다. 그리고 현재 CVE의 대표 description이 LLM 처리 당시 description과 **정확히 같아야** 한다. 설명이 달라졌다면 오래된 추출 결과로 간주한다.

### 13.1 grounding 조건

LLM 결과를 검토할 때 다음을 확인한다.

- result status가 `ok`
- binding 목록이 존재
- vendor/product 문자열이 현재 description에 실제로 등장
- range endpoint 문자열이 현재 description에 실제로 등장

문자열 검색은 먼저 대소문자를 구분해 확인하고, 실패하면 대소문자를 무시한 확인을 수행한다. 한 binding이 grounded이려면 vendor claim과 product claim이 모두 grounded이고, grounded range가 **최소 1개** 있어야 한다.

구형 LLM range 형식은 시작점과 끝점이 모두 있고, 두 inclusivity boolean도 모두 있어야 안전한 범위로 인정한다. 하나라도 빠지면 거부한다.

### 13.2 구조화 근거 우선

resolved product에 대해 CNA/NVD 등 비-LLM 구조화 근거가 이미 parsed affected/unaffected 결정을 제공하면, LLM assertion은 만들지 않는다. 다만 LLM claim 자체는 provenance로 보존할 수 있다.

수용된 LLM assertion도 다음 제한을 항상 받는다.

- provisional
- 결과 상한은 `potentially_affected`
- `use_for_version_index=false`
- LLM run과 claim 연결 필수

### 13.3 LLM identity 합의 threshold

LLM이 vendor/product alias를 identity edge로 확정하려면 정책상 다음 두 기준이 모두 필요하다.

| 항목 | 최소값 |
|---|---:|
| self-consistency agreement ratio | `0.8` 이상 |
| self-consistency 반복 수 `k` | `5` 이상 |

현재 legacy LLM run은 `k=1`이며 prompt/model 메타데이터도 완전하지 않다. 따라서 identity claim은 `below_agreement`로 처리되고 accepted identity edge가 될 수 없다.

한 CVE에서 grounded vendor가 정확히 1개이고 product도 정확히 1개라면 separator 후보 review issue를 남길 수 있지만 low severity일 뿐이며 자동 병합하지 않는다. 이런 후보 예시는 **최대 10개**로 제한한다.

성공적으로 LLM 입력까지 사용한 빌드의 publish health는 `degraded_llm_provisional`이다. LLM 없이 구조화 데이터만 쓴 성공 빌드는 `healthy`가 될 수 있다. `degraded`는 빌드 실패가 아니라 LLM 근거가 최종 확정 근거가 아님을 나타낸다.

---

## 14. 단계 9: assertion reconciliation

제품별로 여러 출처의 assertion을 모은 뒤 다음 순서로 조정한다.

### 14.1 의미상 중복 제거

다음 키가 같은 assertion을 한 그룹으로 묶는다.

```text
(scope_id, semantic_fingerprint, polarity, is_default)
```

그룹에서 가장 강한 근거를 대표로 선택하되, 가능하면 non-LLM assertion을 선택한다. 나머지는 삭제하지 않고 `corroborating` 상태로 남긴다.

### 14.2 CPE any 억제

같은 제품에 구체적인 CNA assertion이 있으면 NVD의 `CPE_ANY_UNCORROBORATED`는 활성 결정에서 억제한다. 구체 범위를 가진 근거가 단순 wildcard보다 우선한다.

### 14.3 정반대 극성 충돌

동일 scope, 동일 constraint, 동일 default 성격에서 affected와 unaffected가 맞서면:

1. 한쪽이 LLM이고 다른 쪽이 구조화 근거면 LLM이 진다.
2. 그 외에는 evidence 비교에서 강한 쪽이 약한 쪽을 suppress한다.
3. 어느 쪽도 명백히 이기지 못하면 둘 다 `conflict_review`로 남긴다.

### 14.4 파싱 불가

`UNPARSED` assertion은 자동 affected 결론으로 쓰지 않고 `unparsed_review` 상태로 시작한다.

### 14.5 binding 생성

최종 CVE-product binding에는 `active` 또는 `conflict_review` 멤버만 연결한다.

- 활성 멤버 중 역할이 `UNRESOLVED`이면 manual review
- `conflict_review`가 있으면 manual review
- LLM assertion이 하나라도 있으면 LLM run link 저장
- LLM 근거만으로 이루어진 binding은 provisional

---

## 15. 단계 10: 제품 identity 그래프와 클러스터

제품 이름이 비슷하다고 `product_entity`를 직접 합치지 않는다. 대신 별도의 identity node, key, alias edge, cluster를 구성한다. 이 계층은 어떤 근거로 두 표기를 같은 identity로 보았는지 추적 가능하게 만든다.

### 15.1 파생 key

canonical label과 원본 alias 각각에서 다음 key를 만든다.

- safe key
- separator-normalized key
- legal-root key
- organization-root key
- acronym
- digit signature
- token multiset

### 15.2 alias class와 tier

| alias class | 의미 |
|---|---|
| `A1_SEPARATOR` | 공백, `_`, `-` 등 구분자 차이 |
| `A2_LEGAL_SUFFIX` | 법인 접미사 차이 |
| `A3_ORG_SUFFIX` | 조직형 접미사 차이 |
| `B1_ACRONYM` | 약어 관계 |
| `B2_BRAND_ALIAS` | 브랜드/제품명 관계 |
| `B3_TYPO` | 제한된 오타 관계 |

| tier | 의미 |
|---|---|
| `T0` | exact |
| `T1` | format |
| `T2` | registry |
| `T3` | provisional |
| `T4` | unresolved |

edge의 근거 예시는 **최대 32개** 저장한다. 전체 개수와 truncation 여부는 envelope에 별도로 보존한다. edge insert는 **2,000개 단위**, 진행 로그는 **25,000개 단위**로 처리한다. 이는 성능 설정이다.

### 15.3 collision과 cluster 안전 한도

- 하나의 collision bucket이 **64개 초과**이면 빌드 전체를 실패시킨다.
- accepted edge를 union-find로 묶었을 때 cluster member가 **8개 초과**이면 review cluster다.
- cluster 안에 hard-distinct 쌍이 있어도 review다.
- 공통 anchor 없이 여러 semantic edge가 연쇄되면 review다.
- review가 없고 accepted edge가 모두 strict eligible일 때만 strict cluster다.

64 초과 collision은 결과를 잘라서 진행하지 않고 atomic failure로 처리한다. 8 초과 cluster는 존재할 수 있지만 `review_state=ok`일 수 없다.

### 15.4 separator identity

separator key 길이는 **최소 3자**여야 한다.

- 같은 key에 node가 정확히 2개이고 compatibility/hard-distinct 검사를 통과하면 accepted strict 후보
- 3개 이상이면 모호성이 커지므로 provisional

### 15.5 legal/org/acronym

법인 접미사 제거, 조직 접미사 제거, acronym 유사성은 일반적으로 review 후보만 만든다. 이 휴리스틱 하나만으로 accepted identity를 만들지 않는다.

명시적 identity registry는 registry에 기록된 허용 조건과 strict flag에 따라 accepted edge를 만들 수 있다. registry 내용은 버전과 해시로 빌드 규칙에 고정된다.

### 15.6 self-brand bridge

vendor 이름과 product 이름을 연결하는 self-brand bridge는 다음을 모두 요구한다.

- product separator compact 길이 **5 이상**
- bucket 크기 **2 이상, 8 이하**
- generic anchor가 아님
- NVD에서 self-brand application anchor가 정확히 1개이며 part=`a`
- 대상은 다른 vendor이고 part=`unknown`
- 대상에 CNA 근거는 있고 NVD 근거는 없음
- 배포판 제품이 아님
- 양쪽이 공유하는 구체 version token이 **3개 이상**
- semantic chaining 없음
- hard-distinct 없음
- 결과 cluster 크기 8 이하

모두 만족할 때만 `B2_BRAND_ALIAS` accepted strict edge가 된다.

### 15.7 vendor typo 정책

공통 typo 조건은 다음과 같다.

- 삽입, 삭제, 치환 중 정확히 **1회** 차이
- 전치(transposition)는 offline build에서 허용하지 않음
- digit signature 동일
- component match가 상호 유일
- semantic chaining 없음
- 결과 cluster 크기 8 이하

vendor typo는 추가로 다음을 요구한다.

| 항목 | threshold |
|---|---:|
| compact 문자열 길이 | 6 이상 |
| bigram Jaccard | 0.60 이상 |
| LCS / 최대 길이 | 0.83 이상 |
| 공유 non-generic product identity | 3개 이상 |

### 15.8 product typo 정책

product typo는 다음을 추가로 요구한다.

| 항목 | threshold |
|---|---:|
| compact 문자열 길이 | 8 이상 |
| bigram Jaccard | 0.75 이상 |
| LCS / 최대 길이 | 0.90 이상 |
| 함께 관찰된 서로 다른 CVE | 3개 이상 |

또한 다음 구조 조건도 전부 만족해야 한다.

- part는 `a` 또는 `unknown`만 존재하고, 최소 한쪽은 `a`
- token 수가 같음
- 달라진 token이 정확히 1개
- 달라진 token에 숫자가 없음
- 한쪽은 CNA-only, 다른 쪽은 NVD-CPE-only

### 15.9 같은 CVE에서 CNA와 CPE가 같이 등장한 경우

단순 co-occurrence는 identity의 충분한 증거가 아니다. 같은 CVE에 CNA 제품과 CPE 제품이 함께 있었다는 사실은 `B2` candidate 근거로만 누적하며, 그것만으로 accepted edge를 만들지 않는다.

LLM identity도 현재 정책에서는 cluster를 변경하지 않는다.

---

## 16. 단계 11: strict alias 기반 NVD 역할 재분류

identity cluster가 만들어진 다음, 초기에 `UNRESOLVED`였던 NVD assertion을 다시 살핀다.

1. 같은 CVE의 CNA 제품과 NVD 제품이 같은 strict cluster에 있는지 본다.
2. provisional edge를 포함하지 않는 경로만 탐색한다.
3. tier `T3` 경로는 제외한다.
4. 가장 안전한 tier의 strict 경로가 있을 때만 승격한다.
5. NVD scope를 복제하여 역할을 `DIRECT_UPSTREAM`으로 바꾼다.
6. evidence의 directness를 `2`로 재계산한다.
7. 결과 상한과 version index eligibility를 다시 계산한다.

검사 진행 로그는 **10,000 pair마다** 기록한다. 이 수치는 관측용 설정이다.

재분류 후 manual review는 다른 활성 unresolved/conflict/unparsed 근거가 하나도 없을 때만 해제한다. 이 단계가 새로운 review 문제를 만들어서는 안 된다.

---

## 17. 단계 12: 전체 스냅샷 감사

행 단위 파싱이 끝났다고 DB를 배포하지 않는다. 완성된 스냅샷 전체에 대해 불변식을 다시 계산한다. 각 감사 쿼리의 위반 건수는 **정확히 0건**이어야 한다.

대표적인 0건 조건은 다음과 같다.

- assertion 없는 binding
- 실제 멤버 상태와 어긋난 manual-review flag
- 결과 상한 또는 index 금지 규칙을 위반한 활성 LLM assertion
- LLM run/claim 연결이 없는 활성 LLM assertion
- index에 들어간 `CPE_ANY`
- `potentially_affected` 상한이 없는 `CPE_ANY`
- downstream/unresolved/unspecified assertion의 index 사용
- `vulnerable=false` CPE가 affected assertion으로 변환된 경우
- unknown default status로 만든 default assertion
- comparator 문자가 정규화된 bound/exact 값에 그대로 남은 경우
- hard-distinct node가 같은 identity cluster에 포함된 경우
- LLM alias가 accepted identity edge가 된 경우
- accepted가 아닌 edge가 정상 cluster 근거로 사용된 경우
- 허용되지 않은 changes가 upper bound 밖에 남은 경우

### 17.1 집계 품질 threshold

모든 개별 불변식 외에 전체 비율도 검사한다.

| 항목 | 통과 조건 |
|---|---:|
| CNA scope resolved ratio | **95% 이상** |
| 활성 NVD CPE 중 unresolved role ratio | **90% 이하** |

정확히 95%인 CNA resolved ratio는 통과하고, 95% 미만이면 실패한다. 정확히 90%인 NVD unresolved ratio는 통과하고, 90%를 초과하면 실패한다.

추가로 다음도 확인한다.

- resolved structured direct assertion 중 index eligible한 것이 존재하면 실제 index 사용 assertion도 최소 1개 있어야 한다.
- member가 8개를 초과하는 cluster는 `review_state=ok`일 수 없다.
- identity evidence example limit 메타데이터는 32여야 하고 실제 example 배열도 32개 이하여야 한다.

하나라도 실패하면 publish하지 않고 임시 DB를 폐기한다.

---

## 18. 단계 13: 인덱스, 무결성, publish

### 18.1 적재 중 임시 인덱스

전체 행 적재 후 identity/reconciliation/materialization 작업에 필요한 임시 work index 3개를 만들고 `ANALYZE`한다. 이 인덱스는 구축 과정의 조인을 빠르게 하기 위한 것이다.

materialization이 끝나면 work index를 제거하고 schema v5의 영구 인덱스를 만든 뒤 다시 `ANALYZE`, `PRAGMA optimize`를 수행한다.

### 18.2 DB 무결성

마지막에는 `foreign_keys=ON`으로 전환하고 다음을 검사한다.

- `PRAGMA foreign_key_check` 결과가 0행
- `PRAGMA quick_check` 결과가 정확히 `ok`

### 18.3 publish 상태 전환

감사와 무결성 검사를 모두 통과하면:

- binding revision 상태를 `published`로 전환
- pipeline run을 `complete`로 전환
- publish health 확정
- summary, counter, issue count 기록
- 임시 DB를 최종 경로로 원자적 교체

LLM을 포함한 현재 기본 실행에서는 정상 완료하더라도 health가 보통 `degraded_llm_provisional`이다. 이는 DB가 불완전하다는 의미가 아니라, LLM-derived assertion이 의도적으로 잠정 상태라는 의미다.

---

## 19. 최종 DB의 주요 테이블과 뷰

### 19.1 실행·메타데이터

```text
metadata
rule_configuration
source_snapshot_manifest
pipeline_run
binding_revision
```

어떤 입력과 어떤 정책으로 DB를 만들었는지 재현하기 위한 계층이다.

### 19.2 원본과 제품

```text
raw_cve
description
product_entity
product_alias
```

원본 provenance와 출처별 제품 엔티티를 보존한다.

### 19.3 identity

```text
identity_node
identity_key
identity_alias_edge
identity_hard_distinct
identity_cluster
identity_cluster_member
identity_cluster_edge
product_relation
```

제품 표기 사이의 동일성 근거, 금지 관계, cluster 결과를 저장한다.

### 19.4 설정·버전·assertion

```text
configuration
source_claim
version_expression
version_segment
applicability_scope
scope_subsumption_edge
applicability_assertion
assertion_reconciliation
```

원본 조건이 어떤 버전 구간과 적용성 결론으로 변환됐는지를 저장한다.

### 19.5 CVE-product binding

```text
cve_applicability_binding
binding_assertion_member
```

현재 CVE와 제품의 적용성 판단 단위를 나타낸다.

### 19.6 LLM과 결함 기록

```text
llm_extraction_run
llm_result
llm_claim
normalization_issue
source_defect
```

LLM provenance와 자동 처리하지 못한 문제를 추적한다.

### 19.7 주요 뷰

- `current_binding`: published revision에 속한 현재 binding만 제공
- `active_assertion`: 상태가 `active` 또는 `conflict_review`인 assertion 제공

일반 소비자는 raw table 전체를 직접 조합하기보다 이 뷰를 시작점으로 삼는 것이 안전하다. `conflict_review`, `manual_review`, provisional, result ceiling을 무시하면 빌더의 안전장치를 우회하게 된다.

---

## 20. threshold 요약

### 20.1 의미와 안전성에 영향을 주는 정책 threshold

| 영역 | threshold |
|---|---:|
| CNA scope resolved ratio | 95% 이상 |
| NVD unresolved active role ratio | 90% 이하 |
| LLM identity agreement | 0.8 이상 |
| LLM identity self-consistency `k` | 5 이상 |
| identity collision bucket | 최대 64, 초과 시 빌드 실패 |
| 정상 identity cluster | 최대 8 members |
| separator key 길이 | 최소 3 |
| self-brand compact 길이 | 최소 5 |
| self-brand bucket | 2~8 |
| self-brand 공유 version token | 최소 3 |
| vendor typo compact 길이 | 최소 6 |
| vendor typo bigram Jaccard | 0.60 이상 |
| vendor typo LCS ratio | 0.83 이상 |
| vendor typo 공유 product identity | 최소 3 |
| product typo compact 길이 | 최소 8 |
| product typo bigram Jaccard | 0.75 이상 |
| product typo LCS ratio | 0.90 이상 |
| product typo 서로 다른 CVE | 최소 3 |
| typo edit | 삽입/삭제/치환 정확히 1회 |
| evidence scope specificity | 최대 3 |
| evidence freshness | 최대 2 |
| evidence corroboration | 최대 2 |
| identity evidence examples | 최대 32 |
| duplicate examples | 최대 20 |
| LLM separator candidate examples | 최대 10 |

### 20.2 결과 의미를 바꾸지 않는 성능·관측 한도

| 영역 | 값 |
|---|---:|
| shell 진행 로그 | 1,000행마다 |
| 중복 사전 스캔 CVE-ID 검색 | 행 앞 512바이트까지 |
| SQLite cache | 약 256 MiB |
| product cache clear | 100,000 entries |
| scope LRU | 250,000 entries |
| normalize-key LRU | 262,144 entries |
| version helper LRU | 65,536 entries |
| identity edge insert batch | 2,000개 |
| identity progress | 25,000개마다 |
| alias reclassification progress | 10,000 pair마다 |

scope LRU가 250,000개를 넘으면 정확성을 포기하지 않고 DB의 UNIQUE lookup으로 되돌아간다. 따라서 cache limit은 결과를 자르는 threshold가 아니다.

---

## 21. 빌드 단계와 질의 단계의 threshold 구분

이 문서의 typo, cluster, grounding threshold는 DB를 구축할 때 실제 identity와 assertion 생성 여부를 결정한다.

반면 런타임 검색에서 사용하는 fuzzy candidate 수, 검색 점수 가중치, score margin 같은 값은 **query-time ranking 정책**이며 DB에 어떤 사실을 넣을지 결정하지 않는다. 예를 들어 검색기의 candidate limit이나 product/vendor 가중치는 검색 결과 순서에 영향을 주지만, 이 빌더의 accepted identity cluster를 만들지는 않는다.

따라서 “DB가 왜 두 제품을 같은 identity로 묶었는가”를 분석할 때 query-time fuzzy 점수를 근거로 사용하면 안 된다. `identity_alias_edge`, cluster edge, registry version, normalization issue를 확인해야 한다.

---

## 22. 실패했을 때 확인할 순서

1. `logs/execute_*.log`에서 최초 error와 audit 이름을 확인한다.
2. NVD 입력이 빌드 중 변경됐는지 확인한다.
3. JSON parse issue인지, version `UNPARSED` 증가인지 확인한다.
4. CNA scope resolved ratio가 95% 아래인지 확인한다.
5. NVD unresolved active role ratio가 90%를 넘었는지 확인한다.
6. identity collision bucket 64 초과 또는 cluster 안전 조건 위반인지 확인한다.
7. `foreign_key_check` 또는 `quick_check` 실패인지 확인한다.

실패 시 임시 DB는 최종 파일로 승격되지 않는다. 따라서 최종 경로에 기존 DB가 남아 있다면 그것은 직전 성공 빌드이며, 실패한 새 결과와 섞인 파일이 아니다.

---

## 23. 최종적으로 DB가 의미하는 것

완성된 `nvd_applicability.sqlite`는 단순히 NVD JSON을 테이블로 옮긴 파일이 아니다. 다음 조건을 만족한 정규화된 판단 스냅샷이다.

- 한 CVE의 중복 입력 중 최신 행만 선택됨
- 원본과 변환 결과가 provenance로 연결됨
- 환경 CPE와 취약 제품 CPE가 구분됨
- 제품 역할과 scope가 명시됨
- 버전 문자열이 비교 가능한 segment로 변환됨
- CNA/NVD/LLM의 권위와 구체성이 분리 평가됨
- 상반된 근거는 억지로 하나로 합치지 않고 review 상태로 보존됨
- LLM 근거는 원문 grounding과 보수적 결과 상한을 통과해야 함
- 제품 alias는 정량 threshold와 hard-distinct 검사를 통과해야 strict identity가 됨
- 전체 데이터 품질 threshold와 관계 무결성 검사를 통과한 revision만 published됨

즉 최종 DB의 핵심 산출물은 “CVE가 어떤 제품의 어떤 버전·환경에 적용되는지, 그 결론이 어느 근거에서 왔고 자동 사용 가능한지”를 함께 질의할 수 있는 구조다.
