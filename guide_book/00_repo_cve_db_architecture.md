# `workspace/repo_cve.sqlite` DB 아키텍처

## 1. 범위

이 문서는 `workspace/repo_cve.sqlite` 자체의 논리·물리 구조를 설명한다.

- 테이블과 뷰가 표현하는 데이터의 단위(grain)
- PK, FK, UNIQUE 및 객체 간 관계
- NVD 범위와 Clovery 범위가 최종 조회 뷰로 합쳐지는 방식
- 조회 프로그램이 DB를 읽는 순서
- 감사와 장애 분석에 사용할 SQL

NVD 수집, LLM 학습, union-find 세부 알고리즘은 각 단계의 별도 가이드에서 다룬다.

## 2. DB의 역할

`repo_cve.sqlite`는 정규화 DB에서 저장소 조회에 필요한 부분을 복사한
**비정규화 read model**이자 **시점 고정 snapshot**이다.

원본 `nvd_applicability.sqlite`가 다음 내용을 담당한다.

- CNA/CPE/LLM claim 정규화
- product identity node, alias edge, cluster 계산
- assertion reconciliation
- affected/unaffected version segment 생성

`repo_cve.sqlite`는 그 결과에서 다음 내용만 가져온다.

- GitHub `owner@repo`와 product의 승인된 연결
- 해당 product에 연결된 current CVE
- 조회에 필요한 CVE metadata와 version segment
- 별도로 수집한 Clovery 결과와 effective override

따라서 이 DB에는 원본 configuration graph, 전체 assertion graph, identity graph가 없다.
대신 저장소·버전 조회를 빠르고 독립적으로 수행할 수 있다.

## 3. 논리 계층

```text
┌─────────────────────────────────────────────────────────────┐
│ Build provenance                                            │
│ build_metadata                                              │
└─────────────────────────────────────────────────────────────┘

┌────────────────────── Repository/CVE 기본 계층 ─────────────┐
│                                                             │
│ repo_product_map                                            │
│   repository 1 ───── N product mapping                      │
│            │                                                │
│            └──── mapping_id ─────┐                           │
│                                  ▼                           │
│                              repo2cve                        │
│                    repo × CVE × product bridge               │
│                         │              │                     │
│                         │              ├──── cve_info         │
│                         │              │      CVE dimension   │
│                         │              │                     │
│                         │              └──── cve_version_range│
│                         │                     range fact       │
│                         ▼                                    │
│              repo_cve / repo_cve_version / summary          │
└─────────────────────────────────────────────────────────────┘

┌──────────────────────── Clovery 계층 ───────────────────────┐
│ clovery_config                                              │
│ clovery_sync_run                                            │
│ clovery_result 1 ───── N clovery_result_range               │
│        │                                                    │
│        ├──── clovery_result_current                         │
│        └──── clovery_result_effective                       │
└─────────────────────────────────────────────────────────────┘

repo_cve_version + clovery_result_effective
                     │
                     ▼
          repo_cve_version_effective
       Clovery override 또는 NVD fallback
```

## 4. 객체 목록

현재 DB는 사용자 테이블 9개, 뷰 6개, 명시적 보조 인덱스 6개로 구성된다.

### 4.1 기본 테이블

| 이름 | Grain | PK/UNIQUE | 역할 |
|---|---|---|---|
| `build_metadata` | build metadata key 하나 | PK `key` | source 경로, build 시각, registry 및 집계 provenance |
| `repo_product_map` | 승인된 `(repo_key, product_id)` 하나 | PK `mapping_id`, UNIQUE `(repo_key,product_id)` | repository-product 연결과 채택 근거 |
| `repo2cve` | `(repo_key,cve_id,product_id)` 경로 하나 | 복합 PK | repository에 CVE가 포함된 product 경로 |
| `cve_info` | CVE 하나 | PK `cve_id` | CVE 표시용 dimension |
| `cve_version_range` | assertion의 version segment 하나 | PK `range_id`, UNIQUE `(assertion_id,ordinal)` | affected/unaffected 범위 fact |

### 4.2 Clovery 테이블

| 이름 | Grain | PK/UNIQUE | 역할 |
|---|---|---|---|
| `clovery_config` | 설정 key 하나 | PK `key` | schema version과 minimum confidence 정책 |
| `clovery_sync_run` | import 실행 한 번 | PK `sync_id` | 실행 시각과 insert/duplicate/unmapped 집계 |
| `clovery_result` | 동일 내용 hash를 가진 repo/CVE 분석 결과 하나 | PK `result_id`, UNIQUE `(repo_key,cve_id,result_sha256)` | append-only Clovery 감사 이력 |
| `clovery_result_range` | Clovery result의 range 하나 | 복합 PK `(result_id,ordinal)` | introduced/last affected/fixed 구간 |

### 4.3 뷰

| 이름 | 출력 Grain | 역할 |
|---|---|---|
| `repo_cve` | `(repo_key,cve_id)` | 여러 product 경로를 CVE 후보 하나로 집계 |
| `repo_cve_version` | repo/product/CVE/version segment | 원본 NVD/CNA/LLM 범위를 저장소 관점으로 투영 |
| `repo_cve_version_summary` | `(repo_key,cve_id,product_id)` | range 수와 bounded affected 존재 여부 요약 |
| `clovery_result_current` | `(repo_key,cve_id)`의 최신 결과 | mtime과 result ID로 최신 Clovery 이력 선택 |
| `clovery_result_effective` | confidence를 통과한 current 결과 | override 가능한 Clovery 결과만 제공 |
| `repo_cve_version_effective` | 최종 repo/product/CVE/version segment | Clovery가 있으면 Clovery, 없으면 원본 범위 제공 |

## 5. 테이블 상세

### 5.1 `build_metadata`

Key-value 형태의 build provenance 테이블이다.

주요 key:

| Key | 의미 |
|---|---|
| `build_id`, `built_at`, `script_version` | build 식별자, 시각, 코드 버전 |
| `source_db`, `source_db_user_version` | 원본 normalization DB |
| `nvd_jsonl` | GitHub reference를 읽은 current NVD JSONL |
| `git_dir`, `corpus_repo_count` | repository corpus 위치와 규모 |
| `accepted_method_counts` | match method별 승인 수 |
| `rejected_candidate_count` | 거절된 mapping 후보 수 |
| `reference_scan` | NVD GitHub reference scan 통계 |
| `identity_registry*` | 사용한 repository identity registry provenance |
| `audit_dir` | mapping audit 산출물 위치 |

절대 경로는 build 당시 환경의 provenance다. 현재 파일의 실행 경로 설정으로 사용하면
안 된다.

### 5.2 `repo_product_map`

Repository와 normalization DB product 사이의 승인된 연결을 저장한다.

```text
grain: repository × product
PK:    mapping_id
UK:    repo_key + product_id
```

컬럼 그룹:

| 그룹 | 컬럼 | 의미 |
|---|---|---|
| Repository 원문 | `repo_key`, `owner`, `repo`, `languages` | 사용자에게 보이는 저장소 정보 |
| Repository 비교 key | `owner_key`, `repo_name_key` | Unicode/case/separator 정규화 결과 |
| Product identity | `product_id`, `vendor_key`, `product_key`, `part` | 원본 normalization product 식별자 |
| Product 표시 | `canonical_vendor`, `canonical_product` | 사람이 읽는 vendor/product |
| 채택 근거 | `match_method`, `match_priority`, `reason` | 왜 연결됐는지 |
| Identity provenance | `anchor_product_id`, `identity_cluster_id`, `vendor_identity_basis` | 원본 DB의 anchor/cluster 근거 |
| Reference provenance | `reference_cve_count`, `reference_cves_json`, `reference_urls_json` | NVD GitHub reference 근거 |

`product_id`, `anchor_product_id`, `identity_cluster_id`는 원본 applicability DB의 ID를
복사한 provenance다. 이 DB에는 별도의 `product_entity`나 `identity_cluster` 테이블이
없으므로 로컬 FK가 아니다.

### 5.3 `cve_info`

CVE 한 건당 한 행인 dimension이다.

```text
grain/PK: cve_id
```

- `source_identifier`: CNA/source 식별자
- `vuln_status`: NVD 상태
- `published`, `last_modified`: CVE 시간 정보
- `primary_description`: 대표 설명
- `enrichment_class`, `admission_status`: 정규화·수용 결과

Repository나 product 정보는 저장하지 않는다. 여러 repository 경로에서 같은 CVE
metadata를 중복 저장하지 않기 위한 공통 dimension이다.

### 5.4 `repo2cve`

Repository-product-CVE의 다대다 관계를 product 경로별로 보존하는 bridge다.

```text
grain/PK: repo_key + cve_id + product_id
FK:       mapping_id → repo_product_map.mapping_id
FK:       cve_id     → cve_info.cve_id
```

| 컬럼 | 의미 |
|---|---|
| `mapping_id` | 해당 repository-product 연결 |
| `binding_id` | 원본 normalization DB의 current binding provenance |
| `match_method` | repository-product가 연결된 방법의 복사본 |
| `enrichment_class` | CVE-product binding의 enrichment 상태 |
| `provisional_llm_identity` | LLM 기반 잠정 identity 포함 여부 |
| `manual_review_required` | 해당 product 경로의 검토 필요 여부 |

하나의 `(repo,CVE)`가 여러 product로 뒷받침될 수 있으므로 product 경로를 제거하지
않는다. 사용자 후보 목록에서는 `repo_cve` 뷰가 이를 한 행으로 집계한다.

### 5.5 `cve_version_range`

원본 normalization assertion을 평면 version segment로 복사한 fact 테이블이다.

```text
grain: assertion_id × ordinal
PK:    range_id
UK:    assertion_id + ordinal
FK:    cve_id → cve_info.cve_id
logical join: cve_id + product_id → repo2cve
```

| 그룹 | 컬럼 | 의미 |
|---|---|---|
| 소유 관계 | `cve_id`, `product_id`, `assertion_id`, `scope_id` | 원본 CVE/product/assertion provenance |
| 극성 | `polarity` | `affected`, `unaffected`, `unknown` |
| 하한 | `lower_bound`, `lower_inclusive` | 시작 경계와 포함 여부 |
| 상한 | `upper_bound`, `upper_inclusive` | 종료 경계와 포함 여부 |
| 정확값 | `exact_value` | 단일 버전 assertion |
| 해석 상태 | `version_resolution_class`, `segment_status`, `breadth_class` | 비교 가능성과 범위 폭 |
| Closure/index | `is_default_closure`, `use_for_version_index` | defaultStatus 근사와 index 허용 여부 |
| 출처 | `source_family`, `evidence_tier`, `cpe_match_role` | CNA/CPE/LLM 및 evidence provenance |

`product_id`에 대한 물리 FK는 없다. `product_id`는 원본 DB identifier이고, 실제
repository 조회에서는 `(cve_id,product_id)`로 `repo2cve`와 결합한다.

### 5.6 `clovery_config`

현재 Clovery sync schema와 override 정책을 저장한다.

- `schema_version`: Clovery extension schema 버전
- `min_confidence`: `high`, `medium`, `low` 중 effective 하한

이 값은 결과 저장 여부가 아니라 NVD 범위를 덮을 수 있는지를 결정한다.

### 5.7 `clovery_sync_run`

Clovery importer 실행 한 번당 한 행이다.

- `started_at`, `completed_at`: transaction 실행 시간
- `results_root`: 입력 결과 디렉터리
- `min_confidence`: 해당 실행 정책
- `candidate_count`, `inserted_count`, `duplicate_count`
- `unmapped_count`, `skipped_file_count`

동기화가 완결됐는지와 일부 결과가 누락됐는지를 확인하는 운영 감사 테이블이다.

### 5.8 `clovery_result`

Repository/CVE 분석 결과의 append-only 이력이다.

```text
grain: repo_key + cve_id + result_sha256
PK:    result_id
UK:    repo_key + cve_id + result_sha256
FK:    cve_id → cve_info.cve_id
```

- `source_file`, `source_mtime_ns`: 원본 파일과 최신성
- `first_imported_at`, `last_observed_at`: import 관측 시각
- `state`: `verified`, `no_vulnerable_release` 등
- `confidence`: `none`, `low`, `medium`, `high`
- `changed`: 제안 범위가 기존 근거와 달라졌는지
- `tag_count`, `evaluated_tags`, `unknown_tags`: tag coverage
- `proposal_json`, `result_json`: 계산 결과와 원문 감사 payload

같은 hash는 중복 삽입하지 않고 관측 시각만 갱신한다. 내용이 바뀌면 새 result 행을
추가한다.

### 5.9 `clovery_result_range`

하나의 Clovery result가 제시한 연속 version 구간을 저장한다.

```text
grain/PK: result_id + ordinal
FK: result_id → clovery_result.result_id ON DELETE CASCADE
```

- `introduced`: 최초 affected tag
- `last_affected`: 마지막 affected tag
- `fixed`: 최초 fixed tag가 있으면 저장
- `fixed_source`: fixed 경계의 근거
- `fixed_conflict_json`: fixed 근거 충돌 감사 정보

## 6. 뷰 상세

### 6.1 `repo_cve`

`repo2cve`를 `(repo_key,cve_id)`로 집계한다.

| 출력 | 계산 | 의미 |
|---|---|---|
| `product_path_count` | `COUNT(DISTINCT product_id)` | CVE를 뒷받침하는 product 경로 수 |
| `min_manual_review_required` | `MIN(...)` | 검토 불필요 경로가 하나라도 있는지 판단 가능 |
| `any_manual_review_required` | `MAX(...)` | 검토 필요 경로가 하나라도 있는지 |
| `any_provisional_llm_identity` | `MAX(...)` | 잠정 LLM 경로가 하나라도 있는지 |

최종 조회기는 보수적으로 `any_manual_review_required`와
`any_provisional_llm_identity`를 사용한다.

### 6.2 `repo_cve_version`

`repo2cve`와 `cve_version_range`를 `(cve_id,product_id)`로 inner join한 원본 범위
projection이다.

```text
repo2cve
  JOIN cve_version_range
    ON cve_id AND product_id
```

Repository 정보와 mapping review flag를 각 원본 version segment에 붙인다.

### 6.3 `repo_cve_version_summary`

각 `(repo,CVE,product)`에 대해 다음을 계산한다.

- 전체 version range 수
- affected range 수
- concrete bound 또는 exact value가 있는 affected range 존재 여부

매핑 build 통계와 “범위가 없는 후보” 진단에 사용한다.

### 6.4 `clovery_result_current`

같은 `(repo_key,cve_id)`의 이력 중 다음 순서로 최신 행을 선택한다.

1. `source_mtime_ns`가 큰 결과
2. mtime이 같으면 `result_id`가 큰 결과

동기화 시각이 아니라 결과 파일의 수정 시각이 우선한다.

### 6.5 `clovery_result_effective`

`clovery_result_current` 중 confidence가 `clovery_config.min_confidence` 이상인 행만
남긴다.

```text
high=3, medium=2, low=1, none=0
```

현재 정책이 `high`라면 medium/low는 감사 이력에는 존재하지만 이 뷰에는 나타나지
않는다.

### 6.6 `repo_cve_version_effective`

최종 version 조회의 기준 뷰다.

```text
effective Clovery result 존재
    ├─ range 존재
    │    → Clovery range만 출력
    │      range_source='clovery'
    │
    └─ no_vulnerable_release / 빈 range
         → 범위 행을 출력하지 않음
         → NVD fallback도 억제

effective Clovery result 없음
    → repo_cve_version의 원본 범위 출력
      range_source='nvd'
```

Clovery range는 다음과 같이 projection된다.

- `introduced` → inclusive lower bound
- `last_affected` → inclusive upper bound
- polarity → `affected`
- resolution class → `clovery_derived_range`
- evidence tier → Clovery confidence

`no_vulnerable_release`는 이 뷰에서 0행이므로, 그것을 단순히 “범위 정보 없음”으로
판단하면 안 된다. 조회기는 별도로 `clovery_result_effective.state`를 읽어
`not_affected_clovery`를 반환한다.

## 7. 관계와 Cardinality

현재 snapshot의 관계 규모는 다음과 같다.

| 객체 | 행 수 | 주요 distinct 값 |
|---|---:|---|
| `repo_product_map` | 7,116 | repository 5,150 / product 7,116 |
| `repo2cve` | 58,588 | repository 5,116 / product 7,013 |
| `repo_cve` | 51,485 | distinct repo/CVE 51,485 |
| `cve_info` | 50,265 | CVE 50,265 |
| `cve_version_range` | 300,914 | CVE 50,257 / product 7,011 |
| `clovery_result` | 3,118 | 저장된 결과 이력 3,118 |
| `clovery_result_effective` | 783 | high-confidence repo/CVE 783 |
| `repo_cve_version_effective` | 299,452 | Clovery 1,111 / NVD 298,341 |

```text
repository 1 ─── N repo_product_map
mapping    1 ─── N repo2cve
CVE        1 ─── N repo2cve
CVE/product 1 ── N cve_version_range
Clovery result 1 ── N clovery_result_range
```

`repo_product_map`의 product가 모두 고유한 것은 build 정책이 하나의 product를 최종
하나의 repository에만 할당하도록 충돌을 해결했기 때문이다. 일반적인 관계 모델의
필수 조건으로 가정하지 말고 현재 builder 정책으로 이해해야 한다.

## 8. 조회기의 DB 읽기 경로

`scripts/query_repo_cve.py`는 다음 순서로 읽는다.

```text
1. repo_product_map
   입력 owner@repo를 exact 또는 normalized key로 해결

2. repo_cve JOIN cve_info
   해당 repository의 CVE 후보와 review metadata 선택

3. repo_cve_version_effective
   후보별 effective version segment 로드

4. clovery_result_effective
   no_vulnerable_release와 confidence metadata 로드

5. 입력 version 비교
   affected/unaffected/exact/bounded/default closure 평가

6. 최종 상태 계산
   affected / potentially_affected / conflict_review / not_affected_*
```

`inclusive`와 `strict`는 DB 뷰나 range 계산을 바꾸지 않는다. 계산된 최종 상태 중
어떤 상태를 positive로 집계할지만 바꾼다.

## 9. 인덱스

| 인덱스 | 컬럼 | 최적화 대상 |
|---|---|---|
| `repo_product_product_idx` | `repo_product_map(product_id)` | product에서 mapping 역조회 |
| `repo2cve_repo_idx` | `repo2cve(repo_key,cve_id)` | repository의 CVE 후보 조회 |
| `repo2cve_cve_idx` | `repo2cve(cve_id,repo_key)` | CVE의 repository 역조회 |
| `cve_version_range_cve_idx` | `cve_version_range(cve_id,product_id)` | repo2cve와 범위 join |
| `cve_version_range_product_idx` | `cve_version_range(product_id)` | product 범위 조회 |
| `clovery_result_repo_cve_idx` | `(repo_key,cve_id,source_mtime_ns DESC,result_id DESC)` | 최신 Clovery 결과 선택 |

PK와 UNIQUE 제약이 만든 SQLite autoindex도 별도로 존재한다.

## 10. 무결성 설계

### 10.1 선언된 FK

- `repo2cve.mapping_id → repo_product_map.mapping_id`
- `repo2cve.cve_id → cve_info.cve_id`
- `cve_version_range.cve_id → cve_info.cve_id`
- `clovery_result.cve_id → cve_info.cve_id`
- `clovery_result_range.result_id → clovery_result.result_id ON DELETE CASCADE`

현재 read-only 연결에서 `PRAGMA foreign_keys`의 기본값은 `0`이었다. SQLite는 연결별로
FK enforcement를 켜야 하므로, DB에 쓰는 프로그램은 `PRAGMA foreign_keys=ON`을
설정하거나 transaction 전 자체 검증을 수행해야 한다.

현재 snapshot을 검사한 결과 선언된 관계의 orphan은 모두 0건이며,
`cve_version_range` 중 대응하는 `(cve_id,product_id)` repo 경로가 없는 행도 0건이다.

### 10.2 버전 표기

- SQLite `PRAGMA user_version`: `0`
- `clovery_config.schema_version`: `1`
- 원본 DB schema provenance: `build_metadata.source_db_user_version`

즉 base mapping schema는 `user_version`으로 버전 관리되지 않고, Clovery extension만
설정 테이블에서 별도 버전을 가진다. 소비자는 객체 존재와 필수 컬럼을 함께 확인하는
것이 안전하다.

### 10.3 중복 방지

- repository-product 중복: UNIQUE `(repo_key,product_id)`
- repository-CVE-product 중복: `repo2cve` 복합 PK
- assertion segment 중복: UNIQUE `(assertion_id,ordinal)`
- 같은 Clovery payload 중복: UNIQUE `(repo_key,cve_id,result_sha256)`
- Clovery range 중복: `(result_id,ordinal)` 복합 PK

## 11. 자주 사용하는 감사 SQL

### 11.1 Repository가 연결된 product

```sql
SELECT mapping_id,repo_key,product_id,
       canonical_vendor,canonical_product,part,
       match_method,match_priority,reason
FROM repo_product_map
WHERE repo_key='HDFGroup@hdf5'
ORDER BY match_priority DESC,product_id;
```

### 11.2 CVE가 들어온 product 경로

```sql
SELECT r.repo_key,r.cve_id,r.product_id,r.mapping_id,
       r.match_method,r.manual_review_required,
       r.provisional_llm_identity,
       p.canonical_vendor,p.canonical_product,p.part
FROM repo2cve r
JOIN repo_product_map p USING(mapping_id)
WHERE r.repo_key='HDFGroup@hdf5'
  AND r.cve_id='CVE-2016-4330';
```

### 11.3 원본 범위와 effective 범위 비교

```sql
SELECT 'original' AS layer,cve_id,product_id,polarity,
       lower_bound,upper_bound,exact_value,
       source_family,NULL AS range_source
FROM repo_cve_version
WHERE repo_key='HDFGroup@hdf5'
  AND cve_id='CVE-2016-4330'
UNION ALL
SELECT 'effective',cve_id,product_id,polarity,
       lower_bound,upper_bound,exact_value,
       source_family,range_source
FROM repo_cve_version_effective
WHERE repo_key='HDFGroup@hdf5'
  AND cve_id='CVE-2016-4330';
```

### 11.4 Effective Clovery 상태와 범위

```sql
SELECT c.repo_key,c.cve_id,c.state,c.confidence,c.changed,
       r.ordinal,r.introduced,r.last_affected,r.fixed,r.fixed_source
FROM clovery_result_effective c
LEFT JOIN clovery_result_range r USING(result_id)
WHERE c.repo_key='HDFGroup@hdf5'
ORDER BY c.cve_id,r.ordinal;
```

### 11.5 무결성과 최신 sync

```sql
PRAGMA quick_check;

SELECT *
FROM clovery_sync_run
ORDER BY sync_id DESC
LIMIT 5;
```

## 12. 설계상 제한

1. 원본 product/assertion/configuration/identity 테이블 전체가 없는 평면 projection이다.
2. `product_id`, `binding_id`, `assertion_id`, `scope_id`, `identity_cluster_id`는 원본 DB
   provenance이며 일부는 로컬 FK로 역참조할 수 없다.
3. claim group이 복사되지 않아 default closure는 product/source 단위로 근사한다.
4. 원본 applicability DB를 갱신해도 이 snapshot은 자동 갱신되지 않는다.
5. mapping DB를 다시 build하면 Clovery extension 객체가 사라지므로 결과를 다시
   import해야 한다.
6. `repo_cve_version_effective`의 0행은 범위 부재와
   `no_vulnerable_release`를 구분하지 못한다. 반드시 `clovery_result_effective`를 함께
   읽어야 한다.
7. JSON 컬럼은 감사와 provenance 보존용이다. 빈번한 조건 검색이 필요하면 별도
   정규화 테이블이나 generated/indexed projection을 추가해야 한다.
