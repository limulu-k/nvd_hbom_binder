# Clovery 결과를 repo_cve.sqlite에 반영

`apply_clovery_results.py`는 `clovery_cycle`이 만든 각 저장소의
`version_ranges.json`을 `repo_key@CVE` 단위로 `repo_cve.sqlite`에 적재한다.
진행 중인 저장소에는 아직 이 파일이 없으므로 제외되고, 쓰는 도중 읽힌 부분 JSON도
건너뛴 뒤 다음 실행에서 다시 처리한다.

원본 NVD 범위인 `cve_version_range`는 수정하지 않는다. Clovery 결과는 다음 감사
테이블에 보존하고 실제 조회는 `repo_cve_version_effective` 뷰를 사용한다.

- `clovery_result`: 저장소/CVE별 결과, 신뢰도, coverage, 원문 JSON과 SHA-256
- `clovery_result_range`: introduced / last affected / fixed 범위
- `clovery_result_current`: 파일 수정 시각 기준 최신 결과
- `clovery_result_effective`: 현재 신뢰도 정책을 통과한 최신 결과
- `repo_cve_version_effective`: 통과한 Clovery 범위가 있으면 그것을, 없으면 NVD 범위를 반환
- `clovery_sync_run`: 매 sync 실행 요약

## 실행

먼저 쓰기 없이 매핑 가능 여부를 확인한다.

```bash
python3 utils/apply_clovery_results.py --dry-run
```

기본 정책은 `high` confidence만 유효 범위로 채택한다. `medium`과 `low` 결과도
감사용 테이블에는 들어가지만 NVD 범위를 덮지 않는다.

```bash
python3 utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high \
  --report workspace/clovery/repo_cve_sync_report.json
```

동일 명령을 cron 등으로 반복해도 된다. 동일 `(repo_key, CVE, 결과 SHA-256)`은
UNIQUE 제약으로 한 번만 저장된다. 새 결과가 생기면 이력 행이 추가되고, 가장 최근
파일의 결과만 `current`가 된다. 여러 sync 프로세스가 겹치면 SQLite busy timeout
동안 기다린 뒤 전체 batch를 하나의 트랜잭션으로 커밋한다.

모든 완료 파일과 repo/CVE 매핑이 반드시 유효해야 하는 일회성 최종 반영에는
`--strict`를 추가한다. 지속 실행 중에는 부분 파일을 다음 회차로 넘길 수 있도록
`--strict`를 쓰지 않는 편이 적합하다.

신뢰도 하한을 `medium`으로 낮추면 "분석된 모든 태그가 Safe"인 medium 결과가 기존
NVD 행을 0개 범위로 대체할 수도 있다. 따라서 정책 변경은 검토 후 수행한다.

## 조회

```sql
SELECT cve_id, lower_bound, upper_bound, fixed, range_source,
       clovery_confidence
FROM repo_cve_version_effective
WHERE repo_key = 'wolfSSL@wolfssl';
```

`range_source='clovery'`이면 Clovery 범위, `nvd`이면 기존 범위다. 채택된
`no_vulnerable_release`는 의도적으로 범위 행을 만들지 않으므로 해당 repo/CVE는 이
뷰에서 0행이다. CVE 후보 자체의 존재 여부는 기존 `repo_cve` 뷰에서 확인한다.

## 테스트

```bash
python3 -m unittest utils.test_apply_clovery_results -v
```
