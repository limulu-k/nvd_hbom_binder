# CVE별 PoC 정적 근거 집계

`scripts/analyze_cve_poc_static.py`는 `repo_cve.sqlite`에 존재하는 고유 CVE를
대상으로 원본 NVD Reference와 공개 PoC 인덱스를 대조한다. CVE별 JSONL,
요약 CSV, 통계 JSON, 외부 API 근거 JSONL을 별도 디렉터리에 저장한다.
Python 표준 라이브러리만 사용하며 원본 DB는 읽기 전용이다.

## 실행

저장소 루트에서 실행한다. 기본 출력 경로는 실행 시각을 포함한다.

```bash
mkdir -p logs
python -u scripts/analyze_cve_poc_static.py \
  --db workspace/repo_cve.sqlite \
  --output-dir workspace/poc_static_my_run \
  > logs/poc_static_my_run.log 2>&1
```

이미 보고서가 있는 출력 디렉터리는 덮어쓰지 않는다. CLI 종료 코드 0은
보고서 생성 성공을 뜻하며, 모든 API 조회 성공이나 PoC 실행 성공을 뜻하지 않는다.
`summary.json`의 `missing_nvd_cves`, `index_sources`, `api_result_counts`를 함께 확인한다.
원본 NVD SHA-256이 정규화 DB의 빌드 manifest와 다르면 중단한다. manifest가
없으면 `source_snapshot_check`에 해당 상태를 기록한다.

네트워크 없이 캐시된 응답만 사용하려면 새 출력 디렉터리를 지정한다.

```bash
python -u scripts/analyze_cve_poc_static.py \
  --offline --output-dir workspace/poc_static_offline
```

성공한 HTTP 응답은 `workspace/poc_static_http_cache.sqlite`에 URL, 조회 시각,
본문 SHA-256과 함께 저장한다. 기본 유효기간은 24시간이다. 오프라인 모드에서는
기존 캐시를 사용하며 원래 조회 시각을 유지한다. 오류 응답은 캐시하지 않는다.
캐시 누락, 네트워크 오류, HTTP 오류, 예산 소진은 각각 구분한다.

## 집계 기준

모든 집계 단위는 중복 제거한 CVE ID다. 다음 플래그는 중복될 수 있다.

| 필드 | 조건 |
|---|---|
| `has_exploit_reference` | 개별 NVD Reference의 `tags`에 정확히 `Exploit`이 있음 |
| `has_github_issue_reference` | `github.com/owner/repo/issues/숫자` 링크가 있음 |
| `has_poc_index_entry` | Exploit-DB, PoC-in-GitHub, Metasploit exploit 모듈 중 하나 이상과 CVE 매칭 |
| `poc_reference_or_index_evidence` | Exploit 태그 또는 공개 인덱스 매핑 |
| `poc_static_candidate` | 위 근거 또는 GitHub Issue Reference |

`evidence_class`는 다음 우선순위를 적용하므로 서로 배타적이다.

1. `POC_INDEXED`: 공개 인덱스 매핑 있음.
2. `EXPLOIT_REFERENCE`: 인덱스 매핑 없이 Exploit 태그가 있음.
3. `ISSUE_REFERENCE_ONLY`: 위 두 근거 없이 Issue Reference만 있음.
4. `NO_EVIDENCE_FOUND`: 검사한 출처에서 위 근거를 찾지 못함.

원본 NVD에 누락된 CVE는 `SOURCE_MISSING`으로 남기고, 외부 인덱스에만
매칭되면 `INDEX_ONLY_SOURCE_MISSING`으로 표시한다. API/인덱스 오류는
음성 근거가 아니다. `all_configured_indexes_loaded`는 설정된 세 인덱스의
조회·파싱 성공 여부이며, 세상의 모든 PoC를 조사했다는 뜻이 아니다.

Issue 링크는 일반 버그 보고일 수도 있고, NVD Exploit 태그는 절차 설명만으로도
붙을 수 있다. 인덱스 등록도 자료의 완전성이나 정상 실행을 보장하지 않는다.
따라서 `poc_static_candidate`를 검증된 PoC 수라고 부르면 안 된다.
이번 분석기는 Reference·인덱스·패키지 메타데이터를 검사하며 Issue 본문이나
PoC 코드의 의미를 분석하지 않는다. payload와 oracle을 추출하지 않고 코드를
실행하지 않는다. 모든 CVE의 `execution_status`는 `NOT_RUN`이다.

## ecosystem API 보강

NVD Reference에 명시된 좌표만 조회한다. 제품명이나 저장소명에서 패키지명을
추측하지 않는다. 현재 지원하는 링크는 다음과 같다.

- npm: `npmjs.com/package/...`, `registry.npmjs.org/...`. scoped 이름을 보존한다.
- Maven: `mvnrepository.com/artifact/...`, `search.maven.org/artifact/...`,
  `central.sonatype.com/artifact/...`.

npm Registry `/{package}/latest`의 `name`, Maven Central 검색 응답의 `g`, `a`가
요청한 좌표와 정확히 일치해야 `confirmed`로 기록한다. 이 확인은
**CVE Reference와 연결된 패키지의 등록 존재 확인**이다. 해당 패키지가 CVE의
영향 대상이라는 추가적인 보증은 아니다. 명시적 좌표가 없으면 ecosystem을
`unknown`으로 남긴다. 알려진 ecosystem이 없는 것과 패키지가 없는 것은 다르다.

매핑 DB의 GitHub 저장소는 저장소 API로 이름, 언어, 기본 브랜치, 보관 상태를
조회한다. 언어와 소스 호스트는 패키지 ecosystem과 구분한다. 응답 저장소 이름이
다르면 `identity_mismatch`로 남긴다. 자동으로 리디렉션된 저장소를 동일시하지 않는다.

GitHub 새 요청 예산은 기본 45건이다. 캐시된 요청은 예산을 쓰지 않으므로
다음 온라인 실행에서 다른 저장소로 진행한다. API 제한 응답을 받으면 이후
GitHub 요청을 제한 상태로 기록한다. 인증 토큰은 기존 `GITHUB_TOKEN` 또는
`GH_TOKEN` 환경변수에서만 읽고 보고서에 저장하지 않는다. 인증과 남은 할당량을
확인한 사용자는 `--github-max-requests`를 늘릴 수 있다.

API 근거는 `api_results.jsonl`, CVE와 패키지 연결은 `cves.jsonl`에서 확인한다.
ecosystem 보강이 일부만 완료되어도 전체 CVE Reference 집계는 수행한다.

공식 API 자료:

- [npm Registry](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md)
- [Maven Central 검색](https://central.sonatype.org/search/rest-api-guide/)
- [GitHub 저장소 API](https://docs.github.com/en/rest/repos/repos#get-a-repository)

## 검증

```bash
python -m pytest utils/test_analyze_cve_poc_static.py -q
```

Reference 중복, scoped 패키지, 정확한 좌표 매칭, 누락 원본, 조회 실패,
정상 인덱스의 0건 매칭, 입력과 출력 경로 충돌 등을 검사한다.

## Exploit Reference 출처와 URL 유형 분류

```bash
python -u scripts/classify_exploit_references.py \
  --input workspace/poc_static_20261015_final/cves.jsonl \
  --output-dir workspace/exploit_reference_types_my_run \
  > logs/exploit_reference_types_my_run.log 2>&1
```

기존 분석 결과의 `references` 중 정확한 `Exploit` 태그가 있는 항목만 사용한다.
같은 CVE의 완전히 동일한 URL은 한 번만 세고 태그를 합친다. 서로 다른 CVE가
같은 URL을 참조하면 CVE–URL 쌍은 각각 세며 고유 URL 수는 한 번만 센다.
원본 URL의 쿼리·fragment는 보존하므로 Issue 본문과 특정 댓글 링크는 다른
Reference다. 그룹별 CVE 수는 중복되므로 합산하지 않는다.

- `providers.csv`: GitHub, SecurityFocus, Gitee 등 출처별 통계.
- `domains.csv`: 원래 호스트별 통계. `www.`만 제거한다.
- `github_url_types.csv`: Issue, Advisory, file, commit, PR 등 큰 분류.
- `github_url_subtypes.csv`: Issue 본문/댓글, 문서/코드 확장자/데이터/압축파일,
  PR 본문/파일 변경/커밋 목록 등 세부 분류.
- `provider_url_types.csv`: 전체 출처의 세부 유형별 통계.
- `references.csv`, `references.jsonl`: CVE, URL, 모든 분류, 원본 태그, Patch 동시 태그,
  파일명 단서, 본문 미확인 상태를 담은 전체 목록.

각 통계에 CVE–URL 쌍 수, 고유 URL 수, 고유 CVE 수, Patch 동시 태그 쌍 수와
예시 URL을 저장한다. Gist, Raw, Pages, Security Lab은 `github.com`과 별도 출처다.
GitLab 자체 호스팅과 일반 이슈 트래커는 호스트·경로 패턴으로 판정하므로
`domains.csv`와 원본 URL을 통해 확인할 수 있다.

다음 `review_action`별 CSV도 만든다. 이는 다음 조사 작업의 분류이며
PoC 유무나 신뢰도 등급이 아니다.

| 작업 | 다음 확인할 내용 |
|---|---|
| `FETCH_ARTIFACT` | 파일, 문서 파일, 첨부, Gist를 확보해 실제 내용과 CVE 연결 확인 |
| `READ_EXPLOIT_RECORD` | Exploit-DB, SecurityFocus exploit 탭, Packet Storm 항목의 본문·첨부 확인 |
| `BROWSE_REPOSITORY` | 저장소·디렉터리에서 CVE별 자료 위치 확인 |
| `READ_REPORT` | Issue·Advisory·신고·메일·기사에서 코드 또는 재현 절차 포함 여부 확인 |
| `REVIEW_CHANGE` | 커밋·PR·diff에서 수정 부분과 재현 테스트 분리 |
| `REVIEW_OTHER` | 영상·알 수 없는 경로 등의 자료 형태 추가 확인 |

`review_actions.csv`의 CVE 수는 중복된다. `cve_review_partition.csv`는 위 표의
순서대로 CVE를 첫 해당 작업에 배정하므로 합산할 수 있다. 우선순위는 작업 큐를
만들기 위한 규칙이며 같은 CVE의 다른 근거를 삭제하지 않는다.

소스코드 확장자는 내용이나 실행 가능성을 보장하지 않는다. 외부 웹페이지의
`.html`·`.htm`·`.php`·`.pl` 확장자는 소스코드 다운로드로 간주하지 않는다. 문서 파일에도
PoC가 있을 수 있고, 커밋에도 재현 테스트가 있을 수 있어 어느 유형도 자동으로
PoC가 없다고 판단하지 않는다. 모든 행의 `poc_content_status`는 `NOT_INSPECTED`다.
