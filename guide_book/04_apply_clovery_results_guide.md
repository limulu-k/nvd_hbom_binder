# `apply_clovery_results.py` 사용 및 알고리즘 가이드

## 1. 목적

[`utils/apply_clovery_results.py`](../utils/apply_clovery_results.py)는 `clovery_cycle.py`가 만든 `version_ranges.json`을 `repo_cve.sqlite`에 이력 형태로 적재하고, 신뢰도 정책을 통과한 결과만 기존 NVD 범위 대신 조회하게 만드는 동기화 프로그램이다.

원본 테이블 `cve_version_range`는 수정하지 않는다. Clovery 결과는 별도 감사 테이블에 append-only로 저장하고, 실제 병합 결과는 `repo_cve_version_effective` 뷰로 제공한다.

```text
version_ranges.json 검색
  → 파일 안정성 및 schema 검증
  → repo_key/CVE가 repo2cve에 존재하는지 확인
  → 결과 hash로 중복 제거하며 감사 테이블에 적재
  → 저장소/CVE별 최신 결과 선택
  → confidence 하한 적용
  → 통과한 Clovery 범위 또는 NVD fallback을 effective view로 공개
```

## 2. 실행 순서에서의 위치

`repo_cve.sqlite` 기본 build가 먼저고 Clovery sync가 나중이다.

```text
nvd_applicability DB
  → 03_build_git_repo_cve_mapping.sh build
  → repo_cve.sqlite 생성
  → apply_clovery_results.py
  → Clovery effective view 생성
```

기본 DB를 다시 build하면 Clovery 전용 테이블과 뷰가 없어지므로 importer를 다시 실행해야 한다.

```bash
./03_build_git_repo_cve_mapping.sh build \
  --db workspace/nvd_applicability_v10.sqlite \
  --git-dir git \
  --output-db workspace/repo_cve.sqlite \
  --audit-dir workspace/repo_cve_audit

python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high \
  --report workspace/clovery/repo_cve_sync_report.json
```

## 3. 권장 사용법

### 3.1 쓰기 전 점검

```bash
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high \
  --dry-run
```

Dry run은 DB를 read-only로 열고 다음을 확인한다.

- 결과 파일을 정상적으로 읽을 수 있는가
- 각 entry schema가 유효한가
- 각 `repo_key/CVE`가 `repo2cve`에 존재하는가
- 예상 candidate 및 unmapped 수가 얼마인가

Dry run은 테이블을 만들거나 결과를 삽입하지 않는다. 따라서 `inserted_results`는 0이다.

### 3.2 실제 반영

```bash
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high \
  --report workspace/clovery/repo_cve_sync_report.json
```

기본 운영에서는 `--strict`를 사용하지 않는다. 일부 unmapped 결과가 있어도 매핑 가능한 나머지를 한 번에 반영하기 위해서다.

### 3.3 결과 확인

```bash
sqlite3 -header -column workspace/repo_cve.sqlite "
SELECT key,value
FROM clovery_config
ORDER BY key;

SELECT confidence,COUNT(*) AS results
FROM clovery_result_current
GROUP BY confidence;
"
```

## 4. CLI 옵션

| 옵션 | 기본값 | 의미 |
|---|---|---|
| `--results` | `workspace/clovery/results` | 저장소별 Clovery 결과 루트 |
| `--db` | `workspace/repo_cve.sqlite` | 반영 대상 DB |
| `--min-confidence` | `high` | NVD를 덮을 최소 confidence |
| `--timeout` | 30초 | SQLite lock 대기시간 |
| `--dry-run` | off | DB 쓰기 없이 검사 |
| `--strict` | off | 파일 오류 또는 unmapped가 하나라도 있으면 전체 실패/rollback |
| `--report` | 없음 | JSON 실행 보고서를 원자적으로 기록 |

`--min-confidence`는 `high`, `medium`, `low` 중 하나다. 이 값은 저장 여부가 아니라 effective override 여부를 결정한다. 모든 confidence 결과는 매핑만 가능하면 감사 테이블에 저장된다.

## 5. 입력 구조

Importer는 다음 glob만 스캔한다.

```text
workspace/clovery/results/*/version_ranges.json
```

상위 JSON은 최소한 다음 구조여야 한다.

```json
{
  "repo": "HDFGroup@hdf5",
  "results": [
    {
      "cve": "CVE-2025-2308",
      "repo": "HDFGroup@hdf5",
      "state": "verified",
      "tag_count": 100,
      "evaluated_tags": 100,
      "unknown_tags": 0,
      "proposal": {
        "confidence": "high",
        "changed": true,
        "ranges": [
          {
            "introduced": "1.10",
            "last_affected": "1.10",
            "fixed": "1.10.4",
            "fixed_source": "clovery+patch_commit"
          }
        ]
      }
    }
  ]
}
```

`results: []`인 완료 파일은 유효하지만 삽입할 candidate가 없다. `no_vulnerable_release` 결과는 entry는 존재하지만 `proposal.ranges`가 빈 배열일 수 있다.

## 6. 상세 알고리즘

### 6.1 안정된 파일만 읽기

Cycle이 JSON을 쓰는 도중 importer가 동시에 실행될 수 있다. 이를 위해 읽기 전후의 다음 속성을 비교한다.

- device
- inode
- size
- nanosecond mtime
- 실제 읽은 byte 수

읽는 동안 하나라도 바뀌면 `changed while being read`로 이번 sync에서 건너뛴다. 부분 JSON을 영구 오류로 취급하지 않으며 다음 sync에서 다시 읽는다.

UTF-8/JSON parsing 실패, top-level object 아님 등의 오류도 파일별 skipped 사유로 기록한다.

### 6.2 Entry schema 검증

각 result에 대해 다음을 확인한다.

- CVE가 `CVE-`로 시작하는 문자열인가
- entry의 repo와 상위 repo가 같은가
- `proposal`이 object인가
- confidence가 `none/low/medium/high` 중 하나인가
- `proposal.ranges`가 배열인가
- 각 범위의 `introduced`, `last_affected`가 문자열인가
- `fixed`, `fixed_source`가 있으면 문자열인가
- tag count가 음수가 아닌 정수인가
- `changed`가 boolean인가

한 entry가 잘못되면 해당 `version_ranges.json` 전체를 skipped file로 처리한다. 정상 entry 일부만 넣어 파일 내부 일관성을 깨지 않는다.

### 6.3 Canonical hash 생성

Entry JSON의 key를 정렬하고 공백을 제거한 canonical JSON을 만든 뒤 SHA-256을 계산한다.

```text
(repo_key, CVE, canonical result SHA-256)
```

이 조합은 `clovery_result`의 UNIQUE key다. 같은 결과를 반복 import해도 새 evidence row가 생기지 않는다.

파일 경로나 JSON pretty-print가 달라도 의미가 같은 canonical result라면 같은 hash가 된다.

### 6.4 목적 DB 검증

대상 DB에 다음 기본 테이블이 있어야 한다.

- `repo2cve`
- `cve_info`
- `cve_version_range`

하나라도 없으면 `repo_cve.sqlite`가 아닌 것으로 보고 중단한다.

각 candidate는 `repo2cve`에서 동일한 `repo_key/CVE`가 존재해야 한다. 매핑이 없으면 Clovery 분석 결과가 있더라도 어느 product path에 연결해야 할지 결정할 수 없으므로 `unmapped`로 건너뛴다.

### 6.5 단일 transaction 시작

실제 반영은 `BEGIN IMMEDIATE`로 시작한다.

이 transaction 안에서 다음이 함께 수행된다.

1. Clovery schema 생성 또는 검증
2. `min_confidence` 정책 갱신
3. sync 실행 이력 생성
4. 모든 candidate 삽입/중복 확인
5. sync 집계 갱신
6. commit

중간에 예외가 발생하면 전체 transaction을 rollback한다. schema/view만 생기고 evidence가 빠지는 부분 반영을 방지한다.

### 6.6 Evidence 이력 적재

새 hash이면 다음을 저장한다.

- 저장소/CVE identity
- source file 및 mtime
- 최초 import/최종 관찰 시각
- state, confidence, changed
- tag coverage
- proposal 원문
- result 원문
- 범위별 introduced/last affected/fixed/fixed source/conflict

같은 hash가 이미 있으면 duplicate로 계산한다. 새 파일의 mtime이 더 최신이면 source path, mtime, last observed 시각만 갱신한다.

결과 내용이 달라지면 hash도 달라지므로 새 이력 row가 추가된다. 이전 결과는 삭제하지 않는다.

### 6.7 최신 결과 선택

`clovery_result_current`는 저장소/CVE별로 다음 우선순위의 한 결과를 선택한다.

1. 가장 큰 source file mtime
2. mtime이 같으면 가장 큰 result ID

즉, 단순히 마지막 importer 실행이 아니라 실제 source 결과 파일의 최신성을 따른다. 오래된 결과 파일을 나중에 복사해도 더 새로운 결과를 덮지 못한다.

### 6.8 Confidence 정책 적용

`clovery_result_effective`는 current 결과 중 `clovery_config.min_confidence` 이상만 남긴다.

```text
none=0 < low=1 < medium=2 < high=3
```

기본 `high` 정책에서는 high만 effective가 된다. Medium/low는 감사 테이블과 current view에는 남지만 effective view에는 들어가지 않는다.

### 6.9 NVD와 Clovery 범위 병합

`repo_cve_version_effective`는 저장소/CVE 단위로 다음 규칙을 적용한다.

```text
effective Clovery 결과가 있는가?
├─ 예 → Clovery proposal range만 반환
└─ 아니요 → 기존 repo_cve_version의 NVD range 반환
```

Clovery 범위는 다음처럼 투영된다.

- polarity: `affected`
- lower: `introduced`, inclusive
- upper: `last_affected`, inclusive
- fixed 및 fixed source 보존
- `range_source='clovery'`
- confidence 보존

NVD fallback은 원래 polarity, inclusive/exclusive 경계, exact value, resolution class를 그대로 유지하고 `range_source='nvd'`를 붙인다.

### 6.10 빈 범위의 의미

Effective Clovery 결과가 `no_vulnerable_release`이고 range 배열이 비어 있으면 해당 저장소/CVE는 effective view에 0행을 만든다. 동시에 NVD fallback도 억제된다.

이는 “관찰한 release 중 취약 release 없음”을 표현하기 위한 의도적인 동작이다. 그래서 medium/low `no_vulnerable_release`를 effective로 허용하는 것은 특히 위험하다.

전체 CVE 후보 존재 여부는 `repo_cve`에서, 현재 Clovery state는 `clovery_result_effective`에서 함께 확인해야 한다.

### 6.11 Commit과 보고서

모든 candidate 처리가 끝나면 sync 통계를 갱신하고 commit한다.

`--report`는 DB commit 후 임시 파일을 같은 디렉터리에 쓰고 `fsync`한 다음 `os.replace`로 교체한다. 중단 시 반쪽 JSON report가 남지 않는다.

## 7. 생성되는 테이블과 뷰

| 이름 | 종류 | 역할 |
|---|---|---|
| `clovery_config` | 테이블 | schema version과 confidence 정책 |
| `clovery_sync_run` | 테이블 | sync 실행별 시작/완료/집계 |
| `clovery_result` | 테이블 | 저장소/CVE별 append-only 결과 이력 |
| `clovery_result_range` | 테이블 | 결과별 범위 목록 |
| `clovery_result_current` | 뷰 | 저장소/CVE별 최신 source 결과 |
| `clovery_result_effective` | 뷰 | confidence 정책을 통과한 current 결과 |
| `repo_cve_version_effective` | 뷰 | Clovery override 또는 NVD fallback |

원본 `cve_version_range`와 `repo_cve_version`은 변경하지 않는다.

## 8. Confidence별 처리 원칙

| Confidence | 근거 | 감사 테이블 저장 | 기본 effective 반영 |
|---|---|---|---|
| High | tag 경계와 patch-derived fixed 경계가 독립적으로 일치 | 예 | 예 |
| Medium | 완전한 tag coverage의 단일 신호 | 예 | 아니요 |
| Low | Unknown tag 또는 fixed 근거 충돌 | 예 | 아니요 |

Medium/low를 반영하면 안 되는 대표 이유:

- Medium은 patch commit의 독립 검증 없이 tag 관찰만으로 경계를 제안할 수 있다.
- Low는 일부 tag가 Unknown이거나 두 경계가 서로 모순된다.
- 빈 range 결과가 effective가 되면 기존 NVD 범위를 완전히 억제한다.
- 특히 “모든 관찰 tag가 Safe”라는 결론은 저장소의 모든 역사적 release가 안전하다는 뜻이 아닐 수 있다.

Inclusive query가 필요하더라도 `--min-confidence`를 낮추지 않는다. Confidence는 데이터 override 정책이고 inclusive/strict는 선택된 데이터의 query 판정 정책이다.

## 9. `--strict`의 의미

### 기본 non-strict

- invalid/변경 중인 파일은 skipped report에 남김
- unmapped repo/CVE는 건너뜀
- 나머지 정상 결과는 commit
- 반복 sync 운영에 적합

### Strict

- skipped file이 하나라도 있으면 중단
- unmapped result가 하나라도 있으면 전체 rollback
- 최종 일회성 검수에서 모든 결과가 반드시 반영되어야 할 때 사용

```bash
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high \
  --strict
```

현재처럼 known unmapped 결과가 존재하는 상태에서는 strict가 의도적으로 실패한다.

## 10. 재실행과 동시 실행 안전성

### 재실행

같은 명령을 여러 번 실행해도 결과 hash UNIQUE 제약으로 중복 삽입되지 않는다.

```bash
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high
```

새 Clovery 결과가 생기면 새 hash row가 추가되고 current view가 최신 mtime 결과를 선택한다.

### 동시 실행

SQLite busy timeout 동안 다른 writer가 끝나기를 기다린다. Lock을 획득하면 batch 전체를 하나의 immediate transaction으로 반영한다.

기본 30초가 부족하면 다음처럼 늘린다.

```bash
python utils/apply_clovery_results.py --timeout 120
```

Timeout이 지나면 부분 적용하지 않고 실패한다.

## 11. Report 해석

예시:

```json
{
  "candidate_results": 3122,
  "completed_result_files": 429,
  "inserted_results": 3118,
  "duplicate_results": 0,
  "unmapped_results": 4,
  "skipped_files": [],
  "min_confidence": "high",
  "dry_run": false
}
```

| 필드 | 의미 |
|---|---|
| `candidate_results` | 유효하게 파싱된 result entry 수 |
| `completed_result_files` | candidate를 하나 이상 제공한 파일 수 |
| `inserted_results` | 새 hash로 삽입된 수 |
| `duplicate_results` | 이미 같은 hash가 있던 수 |
| `unmapped_results` | `repo2cve` 관계가 없어 건너뛴 수 |
| `unmapped_pairs_sample` | 최대 100개 unmapped 예시 |
| `skipped_files` | 불안정/invalid result 파일과 사유 |
| `dry_run` | 실제 쓰기 여부 |

`completed_result_files`는 `results: []`인 파일을 세지 않는다. 파일이 완료됐다는 cycle 관점의 수와 importer candidate 파일 수가 다를 수 있다.

## 12. 조회 방법

### 12.1 저장소와 버전을 함께 조회

Inclusive 조회 프로그램:

```bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.14.1
```

모든 음성 상태 포함:

```bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.14.1 \
  --all-states
```

JSON 출력:

```bash
python scripts/query_repo_cve.py \
  HDFGroup@hdf5 \
  --version 1.14.1 \
  --format json \
  --all-states
```

### 12.2 Effective range SQL

```sql
SELECT
    cve_id,
    polarity,
    lower_bound,
    lower_inclusive,
    upper_bound,
    upper_inclusive,
    fixed,
    range_source,
    clovery_confidence
FROM repo_cve_version_effective
WHERE repo_key = 'HDFGroup@hdf5'
ORDER BY cve_id, lower_bound;
```

### 12.3 `no_vulnerable_release`까지 포함

```sql
SELECT
    rc.cve_id,
    COALESCE(ce.state, 'nvd_fallback') AS decision,
    ce.confidence,
    ev.lower_bound,
    ev.upper_bound,
    ev.fixed,
    ev.range_source
FROM repo_cve rc
LEFT JOIN clovery_result_effective ce
  ON ce.repo_key = rc.repo_key
 AND ce.cve_id = rc.cve_id
LEFT JOIN repo_cve_version_effective ev
  ON ev.repo_key = rc.repo_key
 AND ev.cve_id = rc.cve_id
WHERE rc.repo_key = 'HDFGroup@hdf5'
ORDER BY rc.cve_id, ev.lower_bound;
```

## 13. 운영 점검 SQL

### 현재 정책

```sql
SELECT key,value FROM clovery_config ORDER BY key;
```

### Confidence 분포

```sql
SELECT confidence,COUNT(*)
FROM clovery_result_current
GROUP BY confidence;
```

### 실제 effective 결과 수

```sql
SELECT COUNT(*) FROM clovery_result_effective;
```

### NVD/Clovery 범위 행 분포

```sql
SELECT range_source,COUNT(*)
FROM repo_cve_version_effective
GROUP BY range_source;
```

### 최근 sync

```sql
SELECT
    sync_id,
    started_at,
    completed_at,
    candidate_count,
    inserted_count,
    duplicate_count,
    unmapped_count,
    skipped_file_count
FROM clovery_sync_run
ORDER BY sync_id DESC
LIMIT 10;
```

## 14. 문제 해결

| 증상 | 원인 | 조치 |
|---|---|---|
| `destination is not repo_cve.sqlite` | 필수 기본 테이블 없음 | `03_build_git_repo_cve_mapping.sh build` 결과인지 확인 |
| `unmapped_results > 0` | 결과 repo/CVE와 현재 `repo2cve` identity 불일치 | alias/identity를 검토하거나 non-strict로 나머지 반영 |
| `skipped_files` 발생 | 쓰는 중 파일, invalid JSON/schema | cycle 완료 후 다시 실행, 파일별 reason 확인 |
| `database is locked` | 다른 SQLite writer 실행 중 | `--timeout` 상향 또는 writer 종료 대기 |
| strict rollback | invalid file 또는 unmapped 존재 | report/dry-run으로 대상 수정 후 재실행 |
| Clovery table이 사라짐 | 기본 DB를 다시 build함 | build 이후 importer 재실행 |
| 조회가 NVD만 반환 | confidence가 정책 미달 또는 sync 미실행 | `clovery_config`, `clovery_result_current/effective` 확인 |
| CVE가 effective view에서 0행 | high `no_vulnerable_release`일 수 있음 | `repo_cve`와 `clovery_result_effective.state` 함께 조회 |

## 15. 테스트

Importer와 effective view 동작은 다음으로 검증한다.

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m unittest utils.test_apply_clovery_results -v
```

Inclusive 조회 프로그램까지 함께 검증하려면:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m unittest \
  utils.test_apply_clovery_results \
  prev.scripts.test_query_repo_cve \
  -v
```
