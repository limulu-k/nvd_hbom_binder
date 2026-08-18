# NVD-HBOM Binder

NVD의 CVE 정보를 정규화하고, 실제 GitHub Repository 및 릴리스 버전과 연결하여 **Repository / Version 단위로 적용 가능한 CVE를 조회하기 위한 파이프라인**

```text
NVD 데이터 수집
 ↓
NVD 내 식별자 불일 치 해결
 ↓
GitHub Repository ↔ Product&cve 매핑
 ↓
Clovery 기반 버전 범위 검증
 ↓
owner@repo + version → CVE 조회
```

---

# 1. Project Overview

## 왜 이 연구를 진행하는가?

SBOM/HBOM 기반의 취약점 분석에서는 특정 소프트웨어가 **어떤 CVE에 영향을 받는지 정확하게 판단하는 것**이 중요하다
하지만 NVD에 등록되어 있는 개별 식별자는 cve 제안자가 개인적인 규칙으로 올리는 경우가 존재하며 이로 인해 기존 식별자와 충돌이 나는 경우가 발생한다

예를 들어 NVD에서는 하나의 제품이 다음과 같이 표현될 수 있다

```text
vendor = imagemagick or imagemagick_project or ImageMagick , etc,,, 
product = imagemagick
```

반면 실제 소스코드는 다음과 같은 Repository로 존재한다
```text
ImageMagick@ImageMagick
```

따라서 NVD의 `vendor/product`와 실제 GitHub의 `owner/repo`를 정확하게 연결하지 못하면 Repository에 어떤 CVE가 존재하는지 판단하기 어렵다

## 왜 정확한 매핑이 중요한가?

잘못된 Product ↔ Repository 매핑은 취약점 분석 결과에 직접적인 오류를 발생시킨다

```text
잘못된 Repository 매핑
        ↓
잘못된 CVE 후보
        ↓
잘못된 affected version
        ↓
False Positive / False Negative
```

즉,
* 관련 없는 Repository에 CVE가 연결되거나
* 실제 취약한 Repository에서 CVE가 누락되거나
* 취약하지 않은 버전을 취약하다고 판단하거나
* 실제 취약 버전을 놓치는

문제가 발생할 수 있다

따라서 본 프로젝트에서는 다음 관계를 단계적으로 생성하고 검증하였다

```text
CVE
 ↓
Vendor / Product
 ↓
GitHub Repository
 ↓
Affected Version
```

## 기존 데이터의 문제점

NVD 데이터를 실제 Repository에 적용할 때는 다음과 같은 문제가 존재한다

### 1. Vendor / Product 식별자 불일치
동일한 프로젝트도 NVD, CNA, GitHub reference&repo_name에서 서로 다른 이름으로 표현될 수 있다

```text
vendor/product
        ↕
owner/repository
```

단순 문자열 유사도로 연결할 경우 서로 다른 프로젝트가 하나로 합쳐질 수 있으므로, 본 프로젝트에서는 exact identity, NVD GitHub reference, strict identity cluster 등 보수적인 근거를 이용하여 Repository를 연결한다

### 2. Version Range의 불완전성

NVD CPE, CNA affected 정보, CVE description이 서로 다른 affected version 범위를 표현하는 경우가 존재한다
따라서 단순히 NVD의 version range를 그대로 사용하는 것이 아니라 여러 source claim을 정규화하고 충돌 여부를 관리한다

### 3. CVE Description의 비정형 정보
일부 CVE는 구조화된 CPE/CNA 정보보다 description에 제품명 또는 version 정보가 더 명확하게 기술되어 있다
하지만 해당 정보는 비정형 자연어 구조를 띄고, 이를 rule base로 정형화 하기는 까다롭다
따라서 이를 보완하기 위해 Qwen 기반 LLM parser를 사용하여 description에서 아래와 같이 데이터를 구조화 하였다

```text
description
   ↓ LLM
vendor
product
version range
```

LLM 결과는 100% 정확하다고 확신 불가능하며, 결과 도출 과정이 설명 불가하기에 단독 확정 근거가 아니라 **정규화 과정의 보조 evidence**로 사용된다

### 4. CVE 정보의 변경
CVE는 공개 이후에도 Reject, Unreject, CPE Configuration 변경 등의 Change History가 발생할 수 있다
따라서 최신 feed만 사용하는 것이 아니라 NVD Change History를 함께 반영하여 current CVE snapshot을 생성한다

---

# 2. Pipeline

전체 실행 순서는 다음과 같습다
```text
[01-1] NVD 데이터 및 Change History 업데이트
              ↓
[01-2] CVE Description LLM Parsing
              ↓
[02-1] NVD Applicability DB 생성
              ↓
[03]   GitHub Repository ↔ CVE Mapping
              ↓
[04]   Clovery Version Validation
              ↓
       Clovery 결과 DB 반영
              ↓
[05]   Repository + Version CVE Query
```

`02-2_run_benchmark_builds.sh`는 위 운영 파이프라인과 별개의 **성능 비교 / 평가용 단계**이나, 현 repo에는 라벨 데이터가 없기때문에 실행 불가하다

---

# 3. Quick Start
```bash
git clone https://github.com/limulu-k/nvd_hbom_binder.git
cd nvd_hbom_binder

chmod +x *.sh
```

---

## Step 1. NVD 데이터 업데이트

NVD JSON 2.0 Feed와 CVE Change History를 수집하고 최신 CVE snapshot을 생성

```text
NVD Feed
 + Change History
        ↓
data/nvd-cves.current.jsonl
```

NVD API Key를 설정

```bash
export NVD_API_KEY='YOUR_NVD_API_KEY'
```

실행:

```bash
./01-1_update_nvd_data.sh
```

주요 결과:

```text
data/nvd-cves.jsonl
data/nvd-cve-history/
data/nvd-cves.current.jsonl
```

---

## Step 2. CVE Description LLM Parsing

CVE description에서 `vendor`, `product`, `version range`를 추출하기 위한 Qwen 모델을 학습

### 학습

```bash
./01-2_train_qwen_cve_bindings.sh \
  --data data/cve_bindings_merged-800-hardrule-v1.jsonl \
  --model Qwen/Qwen3-4B-Instruct-2507 \
  --output-dir outputs/qwen3-hardrule-v1
```

멀티 GPU를 사용하는 경우:

```bash
QWEN_NPROC_PER_NODE=7 \
./01-2_train_qwen_cve_bindings.sh \
  --data data/cve_bindings_merged-800-hardrule-v1.jsonl \
  --model Qwen/Qwen3-4B-Instruct-2507 \
  --output-dir outputs/qwen3-hardrule-v1
```

### NVD 추론

```bash
python scripts/infer_nvd_cve_bindings.py \
  --input data/nvd-cves.jsonl \
  --adapter outputs/qwen3-hardrule-v1 \
  --output data/nvd-cves-bindings.jsonl \
  --batch-size 2
```

이미 LLM parsing 결과가 준비되어 있다면 학습/추론 단계는 생략 가능

현재 DB build wrapper는 다음 LLM 입력을 사용

```text
data/nvd-cves-desc_parse.jsonl
data/nvd-cves-desc_parse-fail.jsonl
```

---

## Step 3. NVD Applicability DB 생성

NVD/CNA/LLM 정보를 하나의 정규화된 Applicability DB(적용성 DB)로 구성

```text
NVD current
 + CNA affected
 + CPE
 + LLM
     ↓
workspace/nvd_applicability.sqlite
```

실행:

```bash
./02-1_run_build_db.sh
```

결과:

```text
workspace/nvd_applicability.sqlite
```

이 DB에는 CVE, Product Identity, Version Assertion 및 각 정보의 provenance와 review 상태가 저장 됨

---

## Step 4. GitHub Repository ↔ CVE Mapping

정규화된 NVD Product와 GitHub의 `owner@repo`와 연결

```text
NVD Product
     ↕
GitHub owner@repo
     ↓
Repository ↔ CVE
```

`git/*.txt`에는 분석 대상 Repository 목록이 필요함(해당 리스트는 hbom에 소유권이 있기에 첨부하지 않았음)

```text
mongodb@mongo
apache@httpd
openssl@openssl
```

실행:

```bash
./03_build_git_repo_cve_mapping.sh build \
  --db workspace/nvd_applicability.sqlite \
  --git-dir git \
  --output-db workspace/repo_cve.sqlite
```

결과:

```text
workspace/repo_cve.sqlite
```

매핑 통계를 확인하려면:

```bash
./03_build_git_repo_cve_mapping.sh stats \
  --mapping-db workspace/repo_cve.sqlite
```

---

## Step 5. Clovery Version Validation

Repository에 연결된 CVE를 대상으로 실제 Git tag/release를 탐색하여 affected version 범위를 검증

실행 대상 확인 및 joern 서버 구동

```bash
SOURCE_JSONL="$PWD/data/nvd-cves.current.jsonl" \
OSV_DIR="$PWD/data/osv" \
CLOVERY_DB="$PWD/workspace/nvd_applicability.sqlite" \
./04_run_clovery_cycle.sh plan
```

실제 분석 수행: 전체 repo 탐색 시간(3~4일 소요)

```bash
SOURCE_JSONL="$PWD/data/nvd-cves.current.jsonl" \
OSV_DIR="$PWD/data/osv" \
CLOVERY_DB="$PWD/workspace/nvd_applicability.sqlite" \
./04_run_clovery_cycle.sh run
```

특정 Repository만 분석 가능

```bash
SOURCE_JSONL="$PWD/data/nvd-cves.current.jsonl" \
OSV_DIR="$PWD/data/osv" \
CLOVERY_DB="$PWD/workspace/nvd_applicability.sqlite" \
./04_run_clovery_cycle.sh run \
  --only HDFGroup@hdf5
```

상태 확인:

```bash
./04_run_clovery_cycle.sh status -v
```

Clovery 결과는 기본적으로 다음 위치에 생성 됨

```text
workspace/clovery/results/
```

---

## Step 6. Clovery 결과 반영

Clovery가 계산한 version range를 `repo_cve.sqlite`에 반영

```bash
python utils/apply_clovery_results.py \
  --results workspace/clovery/results \
  --db workspace/repo_cve.sqlite \
  --min-confidence high \
  --report workspace/clovery/repo_cve_sync_report.json
```

신뢰도 기준을 통과한 Clovery 결과가 존재하면 해당 범위를 사용하고, 
그렇지 않으면 기존 NVD 범위를 fallback으로 사용한다

> `repo_cve.sqlite`를 다시 build시 기존 Clovery 결과를 apply 할 수 있다. 

---

## Step 7. Repository / Version CVE 조회

최종적으로 다음 형태의 질의가 가능하다

```text
owner@repository + version
             ↓
      applicable CVEs
```

예:

```bash
./05_query_repo_cve.sh HDFGroup@hdf5 1.8.10
```

전체 판정 상태 확인:

```bash
./05_query_repo_cve.sh \
  HDFGroup@hdf5 \
  1.14.6 \
  --all-states
```

특정 CVE만 확인:

```bash
./05_query_repo_cve.sh \
  HDFGroup@hdf5 \
  1.8.10 \
  --cve CVE-2016-4330
```

JSON 출력:

```bash
./05_query_repo_cve.sh \
  wolfSSL@wolfssl \
  5.7.0 \
  --format json
```

---

# 4. Benchmark

NVD Change History와 LLM parser가 최종 Applicability DB에 미치는 영향을 비교하려면 benchmark를 실행 하면 가능하나, 현재 레포지토리에는 data 하위에 라벨링한 데이터셋이 존재하지 않아 실질적인 실행이 불가함

```bash
./02-2_run_benchmark_builds.sh
```

빠른 smoke benchmark:

```bash
BENCHMARK_LIMIT=1000 \
./02-2_run_benchmark_builds.sh
```

비교 대상은 다음 네가지 항목이며, `workspace/benchmark/` 에 저장된다

```text
Original NVD       / Without LLM
Original NVD       / With LLM
History Current NVD / Without LLM
History Current NVD / With LLM
```

---

# 5. Detailed Guides

각 단계의 세부 알고리즘과 옵션은 [`guide_book/`](./guide_book)에서 확인 가능

```text
guide_book/
├── 01-1_update_nvd_data.md
├── 01-2_llm_trainingNinference.md
├── 02-1_run_build_db.md
├── 02-1_run_build_db_detail.md
├── 02-2_run_benchmark_builds.md
├── 03_build_git_repo_cve_mapping.md
├── 04_apply_clovery_results_guide.md
└── 05_query_repo_cve_guide.md
```
