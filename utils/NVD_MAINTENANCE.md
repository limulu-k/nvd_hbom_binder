# NVD current snapshot 유지보수

`maintain_nvd_cves.py`는 기존 CVE JSONL과 다운로드한 CVE Change History를 대조해
정규화 DB에 넣을 **current-only JSONL**을 만든다.

NVD 공식 설명상 Change History API는 변경 시점과 이유를 제공하는 감사 로그이며,
CVE API의 현재 레코드 전체를 대신하지 않는다. 따라서 history의 `newValue`를 기존
JSON에 부분 적용하지 않는다. 최신 CVE 본문 후보는 `--input`으로 제공해야 한다.

- CVE API: <https://nvd.nist.gov/developers/vulnerabilities#CVE-API>
- Change History API: <https://nvd.nist.gov/developers/vulnerabilities#CVE-Change-History-API>
- NVD 권장 로컬 저장소 갱신 흐름: <https://nvd.nist.gov/developers/api-workflows>

## 판정 순서

1. 모든 input에서 CVE ID가 같은 행을 모은다.
2. `lastModified`가 가장 큰 행 하나만 선택한다.
3. 동일 시각이면 뒤에 지정한 input, 뒤쪽 행을 선택한다.
4. 현재 레코드의 `vulnStatus`가 `Rejected`이면 제외한다.
5. history의 마지막 terminal event가 `CVE Rejected`이면 제외한다.
6. 이후 `CVE Unrejected`가 있으면 terminal reject를 취소한다.
7. 최신 history event가 로컬 레코드의 `lastModified` 및
   `--snapshot-as-of`보다 새로우면 로컬 본문이 낡았으므로 제외한다.

`details[].action=Removed`는 CWE, CPE, 번역 등의 **필드 제거**다. CVE 삭제로
간주하지 않으며 freshness 검사에만 사용한다. CVE 자체 tombstone은
`CVE Rejected`로 판단한다.

## 실행

```bash
python3 utils/maintain_nvd_cves.py \
  --input data/nvd-cves.jsonl \
  --history data/nvd-cve-history/nvd-cve-history.jsonl.gz \
  --snapshot-as-of '<CVE snapshot 다운로드 완료 시각>' \
  --require-history-manifest \
  --output data/nvd-cves.current.jsonl \
  --quarantine data/nvd-cves.current.quarantine.jsonl \
  --report data/nvd-cves.current.report.json
```

누락된 변경 CVE의 최신 API 응답을 별도 JSONL로 받았다면 `--input`을 반복한다.
가장 큰 `lastModified`가 자동으로 선택된다.

```bash
python3 utils/maintain_nvd_cves.py \
  --input data/nvd-cves.jsonl \
  --input data/nvd-cves.incremental.jsonl \
  --history data/nvd-cve-history/nvd-cve-history.jsonl.gz \
  --snapshot-as-of '<두 input 전체가 일관된 시점>'
```

`--snapshot-as-of`는 NVD CVE feed/API snapshot이 모든 변경을 반영했다고 확신할 수
있는 시각이다. NVD 문서에 따르면 CPE dictionary remap 같은 이벤트는 CVE의
`lastModified`를 바꾸지 않을 수 있으므로 이 값을 생략하면 보수적으로 더 많은
CVE가 `stale_after_history`로 격리될 수 있다. 파일 복사 시각이나 임의의 현재 시각을
넣으면 안 된다. NVD feed의 metadata/API response timestamp를 사용해야 한다.
서로 다른 날짜에 받은 연도별 feed를 단순 병합한 파일에는 하나의 전역 시각을
적용하면 안전하지 않다. 이 경우 값을 생략해 보수적으로 격리하고 quarantine의
`stale_after_history` CVE를 최신 CVE API 응답으로 보충한 뒤 다시 실행한다.

## DB 재빌드

기존 schema-v5 DB는 provenance 보호를 위해 append-only trigger를 사용한다. 행을
직접 삭제하지 말고 current JSONL로 새 DB를 만든 다음 감사 통과 후 원자 교체한다.

```bash
python3 scripts/nvd_normalize.py build \
  --input data/nvd-cves.current.jsonl \
  --llm data/nvd-cves-desc_parse.jsonl \
  --llm-fail data/nvd-cves-desc_parse-fail.jsonl \
  --db workspace/nvd_applicability_v10.sqlite \
  --replace
```

LLM 결과는 `_meta.source_index`가 아니라 `cve_id`로 결합하므로 기존
`nvd-cves-desc_parse.jsonl`을 history 적용 전후 NVD JSONL에 모두 사용할 수 있다.
동일 CVE 결과가 여러 개면 현재 description과 정확히 일치하는 성공 결과를 우선한다.
CVE ID만 일치하고 description이 변경된 결과는 감사 목적으로 보존하되 claim은
`description_missing_or_stale`로 격리한다.

## 출력 안전성

- 입력 파일과 같은 경로로 출력하는 것은 거부한다.
- current JSONL은 임시 파일 작성·`fsync`·원자 교체 순서로 게시한다.
- 실행 중 실패하면 기존 게시 output은 유지된다.
- 제외된 CVE와 사유는 quarantine JSONL에 남는다.
- history manifest가 있으면 `complete` 및 event count를 검사한다.
- 전체 입력을 payload째 SQLite에 복제하지 않고 metadata만 저장한 뒤 input을 두 번
  순차 읽으므로 임시 디스크 사용량을 제한한다.

## smoke test

```bash
python3 -m unittest utils.test_maintain_nvd_cves_smoke -v
```

fixture는 최신 revision 선택, rejected/unrejected, record status rejection,
field removal 이후 stale 격리, snapshot coverage 예외를 검증한다. 필터 결과로
소형 schema-v5 DB도 빌드하여 제외된 CVE가 `raw_cve`에 들어오지 않는지 확인한다.
