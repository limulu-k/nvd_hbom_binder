# utils/analysis

CVE 레코드 내부의 정보 불일치를 전수 계측하는 스크립트 모음.

## cross_cve_identifier_cases.py

정규화 DB의 `identity_alias_edge`, `identity_hard_distinct`,
`product_relation`을 이용해 CVE 간 vendor/product 식별자 불일치를 통합 분류로
집계한다.

```bash
python3 utils/analysis/cross_cve_identifier_cases.py \
    --db workspace/nvd_applicability_v10.sqlite \
    --classification-policy inclusive \
    --json-out data/cross_cve_identifier_cases.json \
    --csv-out data/cross_cve_identifier_cases.csv \
    --pairs-out data/cross_cve_identifier_pairs.jsonl
```

기본 CVE 수는 각 분류 pair의 **한쪽 식별자라도 affected claim에서 사용한 고유
CVE의 합집합**이다. CVE 간 표기 차이는 반드시 동일 CVE 안에 양쪽 표기가 함께
나타나는 것이 아니므로 이 값을 보고서의 `CVE 수`로 사용한다. 양쪽 식별자가 같은
CVE에 함께 등장한 검증 표본 수도 필요하면 `--with-cooccurrence`를 추가한다.

분모는 `raw_cve`의 전체 current CVE 수다. 하나의 CVE가 여러 식별자 pair 또는
vendor/product 분류에 동시에 들어갈 수 있으므로 유형별 CVE 수의 합은 전체 고유
CVE 수와 같지 않을 수 있다.

기본 `--classification-policy inclusive`는 파이프라인의 병합 승인 여부와 불일치
유형을 분리한다. `candidate/provisional`은 strict alias로 승격하지 않지만,
`alias_class`가 명시한 유형에는 포함한다.

| 근거 | 분류 |
| --- | --- |
| separator/legal suffix/typo alias | `V1` 또는 `P1` |
| product acronym alias | `P5` |
| brand/self-brand alias | `V2` 또는 `P1` |
| 명시적 배포 vendor/관계 | `V3` |
| plugin/component 관계 | `V4`, `P2` |
| edition/commercial variant 관계 | `P3` |
| hard-distinct | `V5`, `P4` |
| 유형 근거가 없는 unresolved | `V0`, `P0` |

`V0/P0`는 alias class가 없거나 registry가 문맥 의존으로 명시한 경우를 위한 review
분류다. 기존처럼 accepted edge만 유형화하려면
`--classification-policy strict`를 사용한다. 소유권
이전, GitHub owner, 플러그인 관계처럼 문자열만으로 확정할 수 없는 사실은
`identifier_case_registry_v1.json`에 근거와 함께 추가한다. Registry가 자동 규칙보다
우선하며, DB에 존재하지 않아 해석하지 못한 항목은 JSON 보고서의
`unresolved_registry_entries`에 남는다.

## cve_cpe_conflicts.py

`data/nvd-cves.jsonl` 전체를 훑어 **CNA가 신고한 `affected[]`** 와 **NVD가 부여한
`configurations[].cpeMatch[]`** 사이의 두 가지 conflict를 센다.

```bash
python3 utils/analysis/cve_cpe_conflicts.py                    # 전체 (8 프로세스, 약 40초)
python3 utils/analysis/cve_cpe_conflicts.py --limit 20000      # 앞부분만
python3 utils/analysis/cve_cpe_conflicts.py \
    --json-out data/cve_cpe_conflicts.report.json \
    --details  data/cve_cpe_conflicts.details.jsonl            # CVE 단위 판정 덤프
```

기본 실행은 동일 CVE가 연도별/modified/recent feed에 서로 다른 revision으로
남아 있어도 `lastModified`가 가장 큰 한 행만 센다. 원본 JSONL 행을 그대로 세어야
하는 진단 상황에서만 `--include-duplicate-revisions`를 사용한다.

버전 비교는 파이프라인과 동일한 컴파일러(`scripts.nvd_normalization.versioning`의
`compile_cna` / `compile_nvd` / `compare_versions`)를 그대로 쓰므로, 여기서 나온
숫자와 본 파이프라인의 판정 근거가 어긋나지 않는다.

### 비교 대상 (comparable)

CNA 쪽에 placeholder(`n/a`, `-` 등)가 아닌 product가 하나 이상 있고, 동시에
`vulnerable: true` 인 cpeMatch가 하나 이상 있는 레코드만 센다. 한쪽이 비어 있으면
불일치가 아니라 **부재**이므로 `skipped` 로 따로 집계한다.

### 1. 식별자(identity) conflict

CNA `(vendor, product)` 를 CPE criteria의 `(vendor, product)` 와 대조하고, 가장
강한 단계를 그 product entry의 판정으로 삼는다.

| level | 의미 |
| --- | --- |
| `exact` | vendor, product 둘 다 정규화 후 일치 |
| `product_only` | product만 일치 → vendor 불일치 (예: `n/a` : `Spring Framework` ↔ `vmware:spring_framework`) |
| `vendor_only` | vendor만 일치 → product 불일치 |
| `loose` | 토큰 포함 관계로만 일치 (예: `Apache Software Foundation` : `Apache HTTP Server` ↔ `apache:http_server`) |
| `none` | 대응되는 CPE 자체가 없음 (예: `Red Hat` : `RHEL 8` ↔ `tukaani:xz`) |

CVE 단위에서는 각 product entry의 결과를 vendor/product 축으로 다시 투영해 다음
상호 배타적 분류를 함께 센다.

| class | 의미 |
| --- | --- |
| `none` | vendor와 product 모두 일치 |
| `vendor_only` | vendor만 불일치 |
| `product_only` | product만 불일치 |
| `vendor_and_product` | vendor와 product가 모두 불일치 |

`loose`와 `none` match level은 두 축이 모두 exact하지 않으므로
`vendor_and_product` conflict로 집계한다. 버전 범위는 identity가 exact 또는
부분적으로라도 연결된 pair에 대해서만 비교하며, `none` pair와는 비교하지 않는다.

### 2. 버전 범위(version range) conflict

identity가 붙은 pair에 대해서만 비교한다. 서로 다른 제품의 범위를 비교하는 것은
의미가 없기 때문이다. 양쪽을 구간 집합으로 만들어 병합한 뒤 포함 관계를 본다.

| verdict | 의미 |
| --- | --- |
| `equal` | 두 구간 집합의 커버리지가 동일 |
| `cpe_broader` | CNA 범위가 CPE 범위에 포함, CPE가 더 넓음 |
| `cna_broader` | 그 반대 (예: CVE-2021-39212 — CNA는 `< 6.9.12-22`, CPE는 `6.9.12-0` 이상만) |
| `partial_overlap` | 겹치지만 어느 쪽도 상대를 포함하지 않음 |
| `disjoint` | 전혀 겹치지 않음 |
| `scheme_mismatch` | 겹치지 않지만 애초에 버전 체계가 다름 (예: `10.0.0 ≤ v < 10.0.19042.1706` ↔ `20h2`) |

`equal` 이 아닌 것을 conflict로, 그중 `partial_overlap` / `disjoint` /
`scheme_mismatch` 를 **hard conflict** (한쪽이 다른 쪽을 확장한 것으로 설명되지
않는 진짜 모순) 로 센다.

### 교집합

최종 출력은 다음 교집합을 CVE 단위로 제공한다.

- 버전 conflict ∩ 임의의 식별자 conflict
- 버전 conflict ∩ vendor-only conflict
- 버전 conflict ∩ product-only conflict
- 버전 conflict ∩ vendor conflict ∩ product conflict

JSON 보고서의 `summary.conflicts`와 `summary.intersections`에는 각 항목의 count,
유효 비교 분모 기준 비율, 전체 current CVE 기준 비율이 함께 저장된다. 터미널의
`report-ready totals`는 문서 표에 바로 옮길 수 있도록 전체 current CVE를 분모로
사용한다. `counters.conflict_matrix`는 버전 비교 불가까지 포함한 전체 조합을
보존한다.

### undecidable — 비교를 포기하는 경우

version 필드에 자유 서술이 들어오는 경우가 많아, 그대로 비교하면 없는 conflict가
만들어진다. 아래에 해당하면 그 pair 전체를 `undecidable` 로 빼고 사유를 집계한다.
한 entry라도 못 읽으면 그 product entry 전체를 뺀다 — 일부만 읽은 범위 집합은
실제보다 좁아 보여서 `cna_broader` 같은 오판을 낳기 때문이다.

| 사유 | 예 |
| --- | --- |
| `cna_unsupported_version_token` | `"before 1.5.20-7"`, `"5.3.X prior to 5.3.18+"` 같은 자유 서술 |
| `cna_inverted_bounds` | `lessThan: "publication"` (Microsoft), `lessThan: "15.1F5*"` (Juniper) |
| `cna_degenerate_empty_range` | `version == lessThan` (Google CNA 관례) → 빈 구간 |
| `cna_inverted_default_status` | `defaultStatus: affected` — 나열된 구간이 affected 전체를 표현하지 않음 |
| `cna_not_applicable` / `cna_no_affected_versions` | 버전 축 자체가 없음 |
| `cpe_not_applicable` | CPE version이 `-` (주로 하드웨어) |

## 테스트

```bash
python3 -m pytest utils/analysis/test_cve_cpe_conflicts.py -q
```
