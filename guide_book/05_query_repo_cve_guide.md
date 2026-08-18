# query_repo_cve.py 사용 및 알고리즘 가이드

## 1. 목적

[query_repo_cve.py](../scripts/query_repo_cve.py)는 Clovery 결과가 반영된 repo_cve.sqlite를 대상으로 특정 Git 저장소의 특정 릴리스 버전에 적용되는 CVE를 조회한다.

단순 SQL 조회와 달리 다음 처리를 함께 수행한다.

- owner@repo 저장소 식별자 정규화
- 숫자·날짜·배포판 형식을 고려한 버전 비교
- affected/unaffected 구간과 inclusive/exclusive 경계 평가
- Clovery 범위와 NVD fallback을 합친 effective view 사용
- 불확실한 결과를 음성으로 단정하지 않는 inclusive 정책
- provisional identity와 manual-review 상태 반영

기본 출력은 취약하거나 취약 가능성이 있는 CVE만 보여준다. --all-states를 사용하면 음성 결과도 함께 확인할 수 있다.

## 2. 전체 실행 흐름에서의 위치

~~~text
nvd_applicability.sqlite
  → 02-2_build_git_repo_cve_mapping.sh build
  → repo_cve.sqlite
  → clovery_cycle.py plan/run
  → workspace/clovery/results/*/version_ranges.json
  → apply_clovery_results.py
  → repo_cve_version_effective
  → query_repo_cve.py
~~~

권장 실행 순서는 다음과 같다.

~~~bash
./02-2_build_git_repo_cve_mapping.sh build \
  --db workspace/nvd_applicability_v10.sqlite \
  --git-dir git \
  --output-db workspace/repo_cve.sqlite \
  --audit-dir workspace/repo_cve_audit

python scripts/clovery/clovery_cycle.py plan \
  --db workspace/nvd_applicability_v10.sqlite \
  --source-jsonl /home/flba/korea_univ/cve_binder_llm/data/nvd-cves.current.jsonl \
  --osv-dir /home/flba/korea_univ/cve_binder_llm/data/osv

python scripts/clovery/clovery_cycle.py run \
  --step-timeout 21600 \
  --full-clone \
  --max-cpg-pairs 5000

python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high \
  --report workspace/clovery/repo_cve_sync_report.json

python scripts/query_repo_cve.py HDFGroup@hdf5 --version 1.8.10
~~~

repo_cve.sqlite를 다시 build하면 Clovery 테이블과 effective view가 사라진다. 새 DB에는 apply_clovery_results.py를 다시 실행해야 한다. 기존 Clovery 결과 파일이 보존되어 있다면 clovery_cycle.py 자체를 다시 돌릴 필요는 없다.

## 3. 사용법

### 기본 조회

~~~bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.8.10
~~~

기본 inclusive 정책에서 positive인 결과만 표로 출력한다.

### 음성 결과까지 조회

~~~bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.14.6 \
  --all-states
~~~

--all-states는 판정을 바꾸지 않고 출력 범위만 넓힌다.

### 특정 CVE만 조회

~~~bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.8.10 \
  --cve CVE-2016-4330 \
  --cve CVE-2016-4331 \
  --all-states
~~~

--cve는 반복할 수 있다. 지정한 CVE가 해당 저장소에 매핑되어 있지 않으면 새 관계를 추론하지 않고 후보 0개를 반환한다.

### JSON 출력

~~~bash
python scripts/query_repo_cve.py \
  wolfSSL@wolfssl \
  --version 5.7.0 \
  --format json
~~~

자동화에서는 JSON을 권장한다. JSON도 기본적으로 positive 결과만 포함하므로 전체 판정이 필요하면 --all-states를 같이 사용한다.

### 다른 DB 조회

~~~bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.8.10 \
  --db workspace/repo_cve.experimental.sqlite
~~~

## 4. CLI 옵션

| 인자/옵션 | 기본값 | 의미 |
|---|---|---|
| repo_key | 필수 | owner@repo 형식의 저장소 식별자 |
| --version | 필수 | 판정할 구체적인 릴리스 버전 |
| --db | workspace/repo_cve.sqlite | 조회할 Clovery 반영 DB |
| --policy | inclusive | positive 정책: inclusive 또는 strict |
| --cve | 없음 | 특정 CVE로 제한. 여러 번 지정 가능 |
| --all-states | off | negative 상태도 출력 |
| --format | table | table 또는 json |

버전에는 *, -, n/a, unknown을 사용할 수 없다. 실제 비교가 불가능한 값이므로 오류로 처리한다.

## 5. 필요한 DB 객체

프로그램은 DB를 read-only로 열고 다음 객체를 확인한다.

| 객체 | 역할 |
|---|---|
| repo_product_map | 저장소-product 연결과 정규화된 owner/repo key |
| repo_cve | 저장소별 CVE 후보와 매핑 품질 요약 |
| cve_info | CVE 상태, 설명, 갱신 시각 |
| repo_cve_version_effective | Clovery override와 NVD fallback을 합친 범위 |
| clovery_result_effective | confidence 정책을 통과한 최신 Clovery 결과 |

마지막 두 객체가 없으면 apply_clovery_results.py를 먼저 실행하라는 오류로 종료한다.

## 6. 상세 알고리즘

### 6.1 저장소 식별자 해석

입력은 정확히 하나의 @를 포함해야 한다. 먼저 repo_product_map.repo_key와 정확히 같은 행을 찾는다. 없으면 owner와 repository를 Unicode, 대소문자, 구분자 정규화한 owner_key와 repo_name_key로 다시 찾는다.

이름 유사도만으로 등록되지 않은 저장소를 새로 연결하지 않는다. 찾지 못하면 repository not mapped 오류가 발생한다.

### 6.2 CVE 후보 선택

해석된 repo_key로 repo_cve와 cve_info를 결합한다. 후보는 전체 NVD CVE가 아니라 scripts/build_git_repo_cve_mapping.py가 해당 저장소에 승인한 CVE만 포함한다.

함께 읽는 품질 정보는 다음과 같다.

- product_path_count: 저장소-CVE를 뒷받침하는 product 경로 수
- any_manual_review_required: 수동 검토 경로 존재 여부
- any_provisional_llm_identity: provisional identity 경로 존재 여부

### 6.3 Effective 범위 선택

원본 cve_version_range가 아니라 repo_cve_version_effective를 읽는다.

~~~text
confidence 하한을 통과한 최신 Clovery 결과 존재
  → Clovery 범위 사용
그렇지 않음
  → NVD 정규화 범위 사용
~~~

예를 들어 importer를 --min-confidence high로 실행하면 medium/low 결과는 감사 이력에는 저장되지만 조회 범위를 덮지 않는다.

### 6.4 버전 비교

입력 버전과 경계를 보고 normalization engine의 비교 프로필을 선택한다. 따라서 1.10.0과 1.9.0을 문자열 사전순으로 비교하지 않는다.

평가 정보는 lower_bound, upper_bound, inclusive 여부, exact_value, version_resolution_class와 product별 버전 규칙이다.

| resolution class | 처리 |
|---|---|
| EXPLICIT_ALL | 모든 구체 버전에 일치 |
| CPE_ANY_UNCORROBORATED | 근거 없는 전체 범위이므로 unknown |
| UNSPECIFIED | 범위를 확정할 수 없어 unknown |
| UNPARSED | 파싱할 수 없어 unknown |
| NOT_APPLICABLE | 일치하지 않음 |
| BRANCH_RANGE | 1.2.* 또는 1.2.x branch prefix 비교 |
| exact value | 비교 결과가 같을 때만 일치 |
| bounded range | 상·하한과 포함 여부 평가 |

불완전한 범위를 안전으로 바꾸지 않고 unknown으로 유지하는 것이 핵심이다.

### 6.5 Polarity와 default closure

각 segment의 affected, unaffected polarity를 입력 버전과 대조한다. 명시적 affected와 unaffected가 동시에 일치하면 충돌 상태가 된다.

Default closure는 product/source 단위로 근사한다. 명시적 범위가 이미 입력 버전을 포함하면 같은 그룹의 default closure가 중복 판정을 만들지 않도록 억제한다. repo_cve.sqlite에는 원본 applicability DB의 전체 claim/configuration graph가 없기 때문에 이 부분은 보수적인 평면 projection이다.

### 6.6 Clovery 취약 릴리스 없음

Effective Clovery state가 no_vulnerable_release이면 범위 평가보다 우선해 not_affected_clovery가 된다. Confidence 하한을 통과하지 못한 결과는 NVD fallback을 무효화하지 않는다.

### 6.7 최종 상태

| 상태 | 의미 |
|---|---|
| affected | affected 범위가 일치하고 매핑 검토 표시가 없음 |
| potentially_affected | 범위가 불확실하거나 매핑이 provisional/manual-review이거나 범위가 없음 |
| conflict_review | affected와 unaffected가 동시에 일치 |
| not_affected_asserted | 명시적인 unaffected 범위가 일치 |
| not_affected_out_of_range | 평가 가능한 affected 범위 밖 |
| not_affected_clovery | 유효한 Clovery 결과가 취약 릴리스 없음으로 판정 |

Manual review 또는 provisional identity가 있으면 범위가 일치해도 affected가 아니라 potentially_affected로 낮춘다. 버전 일치가 저장소 identity까지 확정하지는 않기 때문이다.

## 7. Inclusive와 strict 정책

정책은 상태 계산법이 아니라 positive로 집계할 상태를 결정한다.

| 상태 | inclusive | strict |
|---|---:|---:|
| affected | positive | positive |
| potentially_affected | positive | negative |
| conflict_review | positive | negative |
| not_affected_asserted | negative | negative |
| not_affected_out_of_range | negative | negative |
| not_affected_clovery | negative | negative |

기본 inclusive는 불완전하거나 충돌하는 CVE의 false negative를 줄인다. 확정 affected만 필요한 자동화에서는 strict를 사용할 수 있다.

~~~bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.8.10 \
  --policy strict \
  --format json
~~~

Strict에서 negative라는 것은 안전 확정이 아니다. 불확실 상태를 positive 집계에서 제외했을 뿐이다.

## 8. 출력 해석

| Table 열 | 의미 |
|---|---|
| CVE | CVE ID |
| STATE | 최종 상태 |
| SOURCE | 실제 범위 출처: nvd 또는 clovery |
| CONF | effective Clovery confidence, 없으면 - |
| MATCHED RANGE | 일치한 주요 polarity와 범위 |
| REVIEW | 저장소-product 매핑의 수동 검토 여부 |

candidate_count는 평가한 전체 CVE 수이고 positive_count는 선택한 정책의 positive 수다. 기본 화면은 positive 행만 표시하므로 표시 행 수와 candidate_count가 다를 수 있다.

JSON 자동화에서는 state만 보지 말고 positive, reason_codes, manual_review_required, provisional_identity와 matched_ranges를 함께 확인한다.

## 9. 오류 점검

### database not found

~~~bash
ls -lh workspace/repo_cve.sqlite
~~~

### database is missing Clovery sync objects

DB를 다시 build한 뒤 importer가 아직 실행되지 않은 상태다.

~~~bash
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high
~~~

### repository not mapped

Git corpus에 저장소가 있다는 사실만으로는 충분하지 않다. repo_product_map에 승인된 저장소-product 연결이 있어야 한다.

~~~bash
sqlite3 -header -column workspace/repo_cve.sqlite "
SELECT *
FROM repo_product_map
WHERE repo_key='cracklib@cracklib';
"
~~~

### 결과가 0개

다음을 구분한다.

1. 저장소가 매핑되지 않음: 오류
2. 저장소는 매핑됐지만 연결 CVE가 없음: 후보 0개
3. 후보는 있지만 모두 negative: 기본 화면에는 행이 없고 요약에는 후보 수가 표시됨
4. --cve가 해당 저장소에 연결되지 않음: 후보 0개

원인 확인에는 다음 명령이 유용하다.

~~~bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.14.6 \
  --all-states \
  --format json
~~~

## 10. 종료 코드

| 코드 | 의미 |
|---:|---|
| 0 | 조회 성공. positive가 0개여도 성공 |
| 2 | 인자, DB, 스키마, 저장소 또는 버전 오류 |

Positive 존재 여부를 종료 코드로 판단해서는 안 된다. JSON의 positive_count 또는 결과별 positive 값을 사용한다.

## 11. 제한 사항

- 조회 대상은 repo_cve.sqlite에 승인된 저장소-CVE 관계로 제한된다.
- DB는 전체 NVD configuration graph가 아닌 repository/product/version 평면 projection이다.
- Claim group이 없으므로 default closure는 product/source 단위로 근사한다.
- Strict 정책에서 제외된 불확실 결과는 안전 판정이 아니다.
- Clovery 결과도 importer confidence 하한을 통과하지 못하면 NVD 범위를 덮지 않는다.
- --all-states는 출력만 바꾸며 DB 내용이나 판정 정책을 바꾸지 않는다.
