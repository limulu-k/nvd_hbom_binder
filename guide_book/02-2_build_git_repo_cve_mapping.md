# `02-2_build_git_repo_cve_mapping.sh` 사용 및 처리 로직

## 1. 목적

`02-2_build_git_repo_cve_mapping.sh`는 `scripts/build_git_repo_cve_mapping.py`를 실행해 GitHub의 `owner@repo`와 정규화 DB의 NVD product entity를 보수적으로 연결하고, 해당 product의 current CVE를 조회할 수 있는 독립 SQLite DB를 만든다. 하위 명령을 생략하면 `build`를 기본으로 실행한다.

이 프로그램은 두 문제를 분리한다.

1. NVD/CNA/LLM을 product와 version assertion으로 정규화하는 일은 `workspace/nvd_applicability.sqlite`가 담당한다.
2. GitHub repository와 정규화된 product를 연결하는 일만 이 프로그램이 담당한다.

Corpus 전체에 fuzzy/Jaccard/LCS 검색을 수행하지 않는다. 이름이 비슷하다는 이유만으로 repository를 product에 연결하지 않고, exact identity, 해당 CVE의 NVD GitHub reference, strict identity cluster, 검증된 vendor identity를 단계적으로 사용한다.

## 2. 전체 사용 순서

먼저 applicability DB를 만든다.

```bash
cd ~/korea_univ/cve_binder
./02-1_run_build_db.sh
```

Repository→CVE DB 생성:

```bash
./02-2_build_git_repo_cve_mapping.sh build \
  --db workspace/nvd_applicability.sqlite \
  --git-dir git \
  --output-db workspace/repo_cve.sqlite
```

Repository 조회:

```bash
./02-2_build_git_repo_cve_mapping.sh query \
  --mapping-db workspace/repo_cve.sqlite \
  mongodb@mongo
```

Manual-review와 provisional LLM identity 경로를 제외한 결과만 조회:

```bash
./02-2_build_git_repo_cve_mapping.sh query \
  --mapping-db workspace/repo_cve.sqlite \
  --strict-only \
  --limit 200 \
  mongodb@mongo
```

전체 통계:

```bash
./02-2_build_git_repo_cve_mapping.sh stats \
  --mapping-db workspace/repo_cve.sqlite
```

## 3. CLI 명령과 옵션

### `build`

| 옵션 | 기본값 | 의미 |
|---|---|---|
| `--db` | `workspace/nvd_applicability.sqlite` | source normalization DB |
| `--git-dir` | `git` | 언어별 repository corpus `.txt` 디렉터리 |
| `--nvd-jsonl` | DB manifest에서 자동 발견 | GitHub reference를 읽을 NVD JSONL override |
| `--identity-registry` | 스크립트 옆 `repo_identity_registry_v1.json` | vendor/repository identity 규칙 JSON |
| `--output-db` | `workspace/repo_cve.sqlite` | 결과 SQLite DB |
| `--audit-dir` | `<output stem>_audit` | accepted/rejected 근거 출력 위치 |

현재 프로젝트에 외부 `repo_identity_registry_v1.json`이 없으면 프로그램에 내장된 보수적 seed registry만 사용한다. 명시한 registry 파일이 존재하면 built-in seed 위에 병합한다.

### `query`

| 인자/옵션 | 의미 |
|---|---|
| `repo_key` | 조회할 `owner@repo` |
| `--mapping-db` | 결과 DB 위치 |
| `--strict-only` | manual review 또는 provisional LLM identity가 있는 repo-CVE 경로 제외 |
| `--limit` | 반환할 CVE 행 수. 기본 `100` |

### `stats`

`--mapping-db`만 받으며 repository/product/CVE/range 수와 match method 분포를 JSON으로 출력한다.

## 4. 입력 데이터 계약

### 4.1 Normalization DB

Source DB에는 최소한 다음 object가 있어야 한다.

- `raw_cve`
- `product_entity`
- `current_binding`
- `source_snapshot_manifest`

Identity cluster, hard-distinct, product relation, raw alias table은 존재할 때 추가 안전 근거로 사용한다. Source DB는 read-only URI로 연다.

### 4.2 Git repository corpus

`git/*.txt`의 빈 줄과 `#` 주석을 제외한 각 행은 정확히 다음 형식이어야 한다.

```text
owner@repository
```

예:

```text
mongodb@mongo
apache@httpd
openssl@openssl
```

파일 이름에서 언어를 추론한다. 예를 들어 `python_git.txt`, `sample_go_git.txt`는 각각 `python`, `go` language tag가 된다. 같은 repository가 여러 파일에 있으면 하나로 합치고 language set만 누적한다.

Owner와 repository 이름은 Unicode NFKC, case-fold, separator folding을 적용해 비교 key를 만든다. 원래 표기는 출력 DB에 함께 보존한다.

### 4.3 NVD JSONL

`--nvd-jsonl`을 생략하면 source DB의 최신 `source_snapshot_manifest.source_path`를 사용한다. DB 생성 후 JSONL을 이동했다면 반드시 새 경로를 지정해야 한다.

## 5. 고수준 알고리즘

```text
repository corpus 정규화
→ NVD JSONL에서 corpus GitHub reference 수집
→ reference CVE의 current_binding을 product evidence로 변환
→ exact/reference/strict-cluster/vendor-bridge 후보 생성
→ blocker와 repository 간 충돌 제거
→ 선택된 product의 current CVE 및 version assertion 복사
→ audit 작성
→ 결과 DB 원자 교체
```

## 6. 세부 매핑 알고리즘

### 6.1 GitHub URL 스캔

NVD JSONL을 binary line 단위로 읽고 GitHub marker가 없는 행은 JSON parse조차 하지 않는다. 다음 host만 repository reference로 인정한다.

- `github.com`
- `www.github.com`
- `api.github.com`
- `raw.githubusercontent.com`
- `codeload.github.com`

JSON 전체의 임의 URL을 사용하지 않고 `references`라는 key 아래의 URL/href만 순회한다. URL에서 owner/repo 두 segment를 추출하고 `.git` suffix를 제거한다. GitHub의 `about`, `issues`, `marketplace`, `users` 같은 비-repository root는 제외한다.

추출한 repository가 `git/*.txt` corpus에 있을 때만 evidence로 채택한다. CVE ID도 source DB의 `raw_cve`에 존재해야 한다. 각 `(CVE, repo)`의 URL 예시는 최대 5개, 이후 `(repo, product)` evidence에는 최대 10개를 보존한다.

### 6.2 Reference를 product evidence로 변환

Source DB의 `current_binding(cve_id, product_id)`와 앞에서 찾은 `CVE→repo`를 결합한다. 그 결과 같은 current CVE에서 repository reference와 product binding이 함께 나타난 `(repo, product)`만 direct reference evidence가 된다.

단순히 어떤 CVE에 GitHub URL이 있다는 사실만으로 모든 product를 연결하지 않고, normalization DB의 current binding을 경유해 현재 게시된 product만 사용한다.

### 6.3 Identity와 blocker 로딩

Source DB에서 다음 보조 근거를 읽는다.

- Review state가 `ok`이고 strict eligible인 product identity cluster
- 가능한 경우 strict vendor-scope cluster
- `identity_hard_distinct`의 절대 분리 product pair
- component/plugin/driver/fork 등 관계를 나타내는 `product_relation` blocker
- 동일 product entity에서 관측된 raw vendor/product alias
- built-in 및 외부 curated registry

Registry는 세 종류의 규칙을 제공한다.

- 특정 product에서만 허용하는 vendor alias
- 특정 repository와 vendor/product의 명시적 연결
- 알려진 오탐 repository/product 차단

### 6.4 후보 생성 1단계: exact pair

정규화된 다음 값이 정확히 같으면 가장 강한 anchor로 추가한다.

```text
repository owner_key == product vendor_key
repository name_key  == product product_key
```

Match method는 `exact_pair`, 우선순위는 `100`이다. NVD reference가 없어도 exact pair 자체로 후보가 될 수 있다.

### 6.5 후보 생성 2단계: direct NVD-reference anchor

동일 current CVE에서 repository와 product가 함께 관측된 pair에 대해서만 이름 관계를 검사한다.

지원하는 보수적 match method와 우선순위:

| Method | 우선순위 | 핵심 조건 |
|---|---:|---|
| `reference_exact_product` | 95 | repo name과 product key 정확 일치 |
| `reference_separator_alias` | 92 | separator 제거 후 일치 + vendor 호환 |
| `reference_owner_product_composition` | 88 | owner/vendor prefix + product 형태의 공식 repo 이름 |
| `reference_acronym` | 85 | product acronym + vendor identity |
| `reference_curated_product_alias` | 84 | registry 명시 연결 |
| `reference_product_variant` | 83 | `portable`, `source`, `src` 같은 제한된 variant |
| `reference_prefix_abbreviation` | 82 | 길이·비율 조건을 만족하는 prefix 축약 + vendor identity |

Exact product name은 direct NVD reference가 이미 있으므로 owner와 NVD vendor namespace가 달라도 anchor가 될 수 있다. 그러나 그 경우 vendor identity가 독립적으로 증명된 것은 아니므로 이후 vendor 전파의 seed로 무제한 사용하지 않는다.

같은 product가 여러 name-compatible corpus repository에서 reference됐으면 CVE reference 개수가 유일하게 가장 큰 repository만 유지한다. 최상위 evidence 수가 동률이면 모두 ambiguity로 거부한다.

### 6.6 Artifact-role 차단

이름이 비슷해도 별도 deliverable이면 연결하지 않는다.

대표 role token:

- driver, binding, SDK, plugin, module
- operator, agent, proxy, connector
- library, toolkit, CLI, shell
- mobile, desktop, frontend, backend

Repository와 product가 서로 다른 artifact role을 명시하거나, repository만 driver/SDK 같은 별도 role을 명시하는 경우 차단한다. Language별 driver/binding의 언어 token이 서로 다를 때도 차단한다.

### 6.7 후보 생성 3단계: strict cluster 확장

이미 채택된 anchor product가 strict·review-clean identity cluster에 속하면 같은 cluster의 다른 product로 확장할 수 있다. 단 다음 조건을 모두 만족해야 한다.

1. 해당 repository가 그 cluster member 중 하나에 대한 direct NVD reference를 가짐
2. 두 product가 hard-distinct 또는 blocking relation pair가 아님
3. CPE part가 호환됨
4. Artifact-role conflict가 없음

Match method는 `strict_cluster_expansion`, 우선순위는 `75`다. Reference evidence 없이 alias cluster만으로 corpus 전체를 확장하지 않는다.

### 6.8 CPE part 호환성

동일 part는 호환된다. Application의 `a`, wildcard, unknown은 제한적으로 연결할 수 있지만 unknown application identity를 OS(`o`)나 hardware(`h`)로 연결하지 않는다. Hardware와 OS는 각각 같은 concrete part 또는 제한된 wildcard 관계에서만 허용한다.

이 규칙은 예를 들어 application repository가 같은 이름의 Android OS product를 상속하는 것을 막는다.

### 6.9 후보 생성 4단계: vendor identity + 같은 product key

같은 `product_key`를 가진 다른 vendor product로 전파할 때 product 이름 일치만으로는 부족하다.

먼저 해당 product key를 anchor한 repository가 정확히 하나여야 하며, product key 길이가 4 이상이어야 한다. 대상 product가 다른 corpus repository를 직접 reference하면 fallback 전파를 거부한다.

그 다음 anchor vendor 또는 repository owner와 대상 vendor 사이에 다음 중 하나가 있어야 한다.

- vendor exact 또는 separator variant
- strict vendor cluster
- 같은 product entity에서 관측된 raw vendor alias
- product-scoped curated vendor alias
- 보수적인 legal/organisation suffix variant

`reader`, `android`, `sdk`, `server`, `client`, `java`처럼 충돌이 많은 generic product key는 curated alias, strict vendor cluster 또는 product alias vendor 수준의 더 강한 근거가 필요하다.

Match method는 `vendor_identity_product_key_bridge`, 우선순위는 `65`이며 `vendor_identity_basis`가 비어 있으면 최종 검증에서 build 자체를 실패시킨다.

### 6.10 Repository 간 product claim 충돌 해소

하나의 `product_id`는 최종적으로 하나의 repository만 소유하도록 보수적으로 제한한다. 후보를 match priority, reference CVE 수, repo key 순으로 정렬한다.

- 최고 priority와 evidence 수가 유일하면 해당 repository 채택
- 최고 두 후보가 priority와 evidence 수 모두 같으면 해당 product의 모든 claim 거부
- 낮은 후보는 `superseded_by:<repo>:<method>` 사유로 audit에 기록

따라서 애매한 product를 임의의 repository에 할당하지 않는다.

## 7. 결과 DB 구성

### 핵심 테이블

| 테이블 | 역할 |
|---|---|
| `build_metadata` | source 경로, 버전, registry, reference scan 통계 |
| `repo_product_map` | repository가 어떤 product에 왜 연결됐는지 보존 |
| `repo2cve` | repository/product 경로별 current CVE binding |
| `cve_info` | 결과에 필요한 CVE 기본 정보 |
| `cve_version_range` | 선택 product의 active/conflict-review version segment |

`repo_product_map`은 감사 가능성의 핵심이다. 한 CVE가 repository에 들어온 이유를 product mapping 단위로 역추적할 수 있다.

### View

| View | 역할 |
|---|---|
| `repo_cve` | 같은 repo/CVE의 여러 product 경로를 하나로 집계 |
| `repo_cve_version` | repo 관점으로 affected/unaffected version segment 투영 |
| `repo_cve_version_summary` | bounded affected range 존재 여부 요약 |

Version range는 repository 자체가 아니라 `(CVE, product, assertion, ordinal)` grain으로 저장한다. 같은 product를 여러 repository가 공유할 가능성과 version 의미가 product에 속한다는 점을 보존하기 위해서다.

Affected와 unaffected segment를 모두 복사한다. Default-status closure를 해석하려면 양쪽 polarity가 모두 필요하기 때문이다. Reconciliation status가 `active` 또는 `conflict_review`인 assertion만 복사한다.

## 8. DB 적재와 원자적 교체

선택된 repository/product mapping을 먼저 저장한 뒤 source DB의 `current_binding`을 통해 CVE를 가져온다. CVE 본문 정보는 `cve_info`에 한 번만 넣고 각 product 경로는 `repo2cve`에 보존한다.

대량 적재는 batch로 수행하며 마지막에 `ANALYZE`와 commit을 실행한다. 출력은 `<output>.tmp` DB에 완성한 뒤 기존 결과에 `os.replace`로 원자 교체한다.

## 9. Audit 결과

기본 audit 디렉터리는 `workspace/repo_cve_audit/`이다.

```text
accepted_repo_product.jsonl
rejected_repo_product.jsonl
summary.json
audit_manifest.json
```

Accepted 행에는 match method, priority, anchor product, cluster, vendor identity 근거, reference CVE/URL이 들어간다. Rejected 행에는 reference anchor, cluster 확장, vendor bridge, cross-repo conflict 중 어느 단계에서 어떤 사유로 제외됐는지가 들어간다.

Audit는 임시 디렉터리에 전부 작성하고 행 수를 검증한 뒤 기존 audit 디렉터리를 fresh directory로 교체한다.

## 10. `query` 결과의 의미

`query`는 입력 `owner@repo`를 raw key 또는 normalized owner/name으로 해석한다. 출력에는 다음이 포함된다.

- 요청 key와 실제 해결된 repo key
- repository→product mapping 목록과 근거
- distinct CVE 수와 반환 수
- CVE status, published/modified, description, enrichment
- version range 개수와 bounded affected range 존재 여부
- 사람이 읽을 수 있는 affected interval 목록

중요: 이 결과는 **제품 수준 CVE 후보 집합**이다. `affected_versions`를 붙여 주지만 사용자가 입력한 구체적 버전을 평가하는 명령은 아니다. `--strict-only`도 manual-review/provisional 경로를 거를 뿐 version, platform, configuration graph 전체를 판정하지 않는다.

정확한 vendor/product/version applicability는 normalization query engine을 사용한다.

```bash
python -m scripts.nvd_normalization query \
  --db workspace/nvd_applicability.sqlite \
  --vendor mongodb \
  --product mongodb \
  --version 7.0.5 \
  --all-states --trace --format json
```

Repository query 결과에 bounded affected range가 없으면 모든 버전을 후보로 취급하고 위 query engine으로 최종 판정해야 한다.

## 11. `stats` 해석

`stats`는 다음을 보여준다.

- repository/product mapping 수
- mapping된 distinct repository 수
- repo/product/CVE 경로 수와 distinct repo/CVE 수
- strict 경로 수
- manual-review 및 provisional LLM 경로 수
- distinct CVE 수
- 복사된 version range 수
- bounded affected range가 있는 repo/CVE/product 수
- match method별 mapping 수

Mapping 품질을 볼 때 전체 행 수만 보지 말고 `methods`, `manual_review_repo2cve`, `provisional_llm_repo2cve`, audit rejected 사유를 함께 확인해야 한다.

## 12. 종료 코드와 실패 조건

- 정상 build/query/stats: `0`
- Query 대상의 mapping이 없음: JSON 결과를 출력한 뒤 `2`
- 잘못된 옵션, source DB/schema/파일 오류, SQLite/OS 오류: argparse error와 함께 `2`

대표 build 실패 조건:

- source DB 또는 git corpus가 없음
- corpus 행이 정확한 `owner@repo` 형식이 아님
- source DB 필수 object가 없음
- 자동 발견한 NVD JSONL이 이동/삭제됨
- 외부 identity registry JSON이 잘못됨
- vendor bridge가 identity 근거 없이 최종 채택됨

## 13. 권장 운영 순서

```text
01-1_update_nvd_data.sh
→ 02-1_run_build_db.sh
→ 02-2_build_git_repo_cve_mapping.sh build
→ stats로 전체 분포 확인
→ audit rejected/accepted 표본 검토
→ query로 repository 후보 확인
→ normalization query engine으로 구체 버전 최종 판정
```

NVD current JSONL이나 normalization DB가 바뀌면 repository mapping DB도 다시 빌드해야 한다. 결과 DB는 source DB의 current binding을 복사한 self-contained snapshot이므로 source DB 변경이 자동 반영되지는 않는다.
