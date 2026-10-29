# 05_query_repo_cve.sh 사용 가이드

[`05_query_repo_cve.sh`](../05_query_repo_cve.sh)는 `owner@repo`와 구체적인 릴리스 버전을 받아 해당 저장소의 CVE를 조회한다. 내부에서 [`scripts/query_repo_cve.py`](../scripts/query_repo_cve.py)를 호출하므로 셸과 Python의 판정 로직은 동일하다. Python 직접 실행, 자동화 및 세부 판정 알고리즘은 [Python 가이드](05_query_repo_cve_python_guide.md)를 참고한다.

## 1. 준비 및 기본 조회

프로젝트 디렉터리에서 실행한다. 기본 DB는 `workspace/repo_cve.sqlite`다. 셸 래퍼는 자신의 위치로 이동하므로 다른 작업 디렉터리에서 스크립트 경로를 지정해 실행해도 된다.

```bash
cd ~/korea_univ/summer/nvd_hbom_binder
./05_query_repo_cve.sh 'libexif@libexif' '0.6.15'
```

형식:

```text
./05_query_repo_cve.sh <owner@repo> <version> [Python 조회 옵션...]
```

저장소는 `owner@repo` 형식이어야 한다. 버전은 구체적인 릴리스 버전이어야 하며 `*`, `-`, `n/a`, `unknown`은 허용되지 않는다. 등록된 저장소가 없으면 `repository not mapped` 오류가 발생한다.

## 2. 자주 쓰는 조회

```bash
# 특정 CVE만 조회. --cve는 여러 번 지정할 수 있다.
./05_query_repo_cve.sh 'libexif@libexif' '0.6.15' \
  --cve CVE-2006-4168 --all-states

# 해당 저장소의 부정 판정까지 표시
./05_query_repo_cve.sh 'HDFGroup@hdf5' '1.14.6' --all-states

# 확정 affected만 positive로 집계
./05_query_repo_cve.sh 'libexif@libexif' '0.6.15' --policy strict

# JSON 형식으로 표시
./05_query_repo_cve.sh 'libexif@libexif' '0.6.15' --format json --all-states

# 래퍼 도움말
./05_query_repo_cve.sh --help
```

`--all-states`는 결과 표시 범위만 넓히며 판정을 바꾸지 않는다. `--cve`로 지정한 CVE가 해당 저장소에 연결되어 있지 않으면 후보가 0개다.

> 셸 래퍼는 표준 출력에 `실행 명령: ...`을 먼저 출력한다. 따라서 `--format json`의 전체 표준 출력은 순수 JSON이 아니다. JSON 파일 저장이나 파이프에는 [Python 직접 실행](05_query_repo_cve_python_guide.md#json-출력)을 사용한다.

## 3. 옵션과 환경변수

| 항목 | 기본값 | 설명 |
|---|---|---|
| 첫 번째 인자 | 필수 | 저장소 `owner@repo` |
| 두 번째 인자 | 필수 | 구체적인 버전 |
| `--cve CVE-...` | 전체 후보 | 특정 CVE로 제한. 반복 가능 |
| `--all-states` | 꺼짐 | positive 이외의 상태도 출력 |
| `--policy inclusive` | 기본값 | `affected`, `potentially_affected`, `conflict_review`를 positive로 집계 |
| `--policy strict` | 없음 | `affected`만 positive로 집계 |
| `--format table` / `json` | `table` | 출력 형식 |
| `REPO_CVE_DB` | `workspace/repo_cve.sqlite` | 래퍼가 조회할 DB 경로 |
| `PYTHON_BIN` | `python` | 사용할 Python 실행 파일 |

```bash
REPO_CVE_DB=/path/to/repo_cve.sqlite \
PYTHON_BIN=python3 \
  ./05_query_repo_cve.sh 'libexif@libexif' '0.6.15'
```

## 4. 출력 읽기

현재 스냅샷에서 다음 명령으로 확인한 예시다. 데이터와 분석 결과가 갱신되면 출력은 달라질 수 있다.

```bash
./05_query_repo_cve.sh 'libexif@libexif' '0.6.15' \
  --cve CVE-2006-4168 --all-states
```

```text
CVE            STATE                 SOURCE   CONF  MATCHED RANGE            REVIEW
CVE-2006-4168  potentially_affected  clovery  high  affected:[0.5.7,0.6.15]  yes
```

| 열 | 의미 |
|---|---|
| `CVE` | CVE 식별자 |
| `STATE` | 버전 적용성과 매핑 검토 상태를 반영한 판정 |
| `SOURCE` | 해당 CVE의 effective 범위 출처 목록. `nvd`, `clovery`, `none` 등이 표시된다. |
| `CONF` | 유효 Clovery 결과의 confidence. 없으면 `-` |
| `MATCHED RANGE` | 입력 버전에 일치한 주요 구간. 자세한 근거는 Python JSON의 `matched_ranges` 참고 |
| `REVIEW` | 저장소·제품 매핑에 수동 검토가 필요한지 여부 |

위 예시는 Clovery 범위가 일치하지만 매핑 검토가 필요해 `potentially_affected`다. 이를 확정 취약 판정으로 해석하지 않는다.

| 상태 | 의미 |
|---|---|
| `affected` | 영향 범위가 일치하고 관련 매핑 검토 표시가 없음 |
| `potentially_affected` | 범위 불확실, 유효 범위 부재 또는 매핑 검토 필요 |
| `conflict_review` | affected와 unaffected 범위가 동시에 일치 |
| `not_affected_asserted` | unaffected 범위가 일치 |
| `not_affected_out_of_range` | 선택된 범위가 있으나 일치하는 affected/unaffected 판정이 없음 |
| `not_affected_clovery` | 기준을 통과한 Clovery 결과가 취약 릴리스 없음을 나타냄 |

기본 `inclusive`와 `strict`의 차이는 positive **집계 기준**이다. `strict`에서 불확실 결과가 표시되지 않는다고 안전하다는 뜻은 아니다. 요약의 `candidates`는 평가한 후보 수, `positive`는 선택한 정책의 positive 수다.

## 5. DB와 Clovery 결과

조회기는 DB를 읽기 전용으로 열고 `repo_product_map`, `repo_cve`, `cve_info`, `repo_cve_version_effective`, `clovery_result_effective`를 확인한다. 유효 Clovery 결과가 있으면 해당 범위를 사용하고, 없으면 NVD 범위를 사용한다. NVD fallback은 Clovery 분석이 끝났다는 뜻이 아니다.

`database is missing Clovery sync objects` 오류가 나오면 기존 결과를 동기화할 수 있다. 아래 명령은 **지정한 DB를 변경**한다. 기존 결과를 사용하므로 전체 Clovery 분석을 다시 실행하는 명령은 아니다.

```bash
# 먼저 변경 없이 검사
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite --dry-run

# 결과를 DB에 반영
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite --min-confidence high
```

기본 `high` 기준에서 medium/low 결과는 보관되지만 NVD 범위를 대체하지 않는다. 동기화 보고서의 `unmapped_results`는 저장소·CVE 매핑이 없어 적용되지 않은 결과다. 저장된 결과의 신선도와 범위는 별도로 확인해야 한다.

## 6. 오류와 제한

- `DB를 찾을 수 없습니다`: `REPO_CVE_DB` 또는 기본 DB 경로를 확인한다.
- `repository not mapped`: 해당 저장소가 `repo_product_map`에 등록되어 있는지 확인한다.
- 표시 행이 0개: 후보 자체가 0개인지, 후보는 있으나 정책상 positive가 없는지 요약과 `--all-states`로 구분한다.
- 종료 코드 `0`은 조회 성공이며 positive가 0개여도 `0`이다. 오류 시 일반적으로 `2`를 반환한다.
- DB는 전체 NVD configuration graph가 아닌 평면 projection이며 default closure를 product/source 단위로 근사한다. 판정은 DB에 존재하는 저장소·CVE 관계에 한정된다.
