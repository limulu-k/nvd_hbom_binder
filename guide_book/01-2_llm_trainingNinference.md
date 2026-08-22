# CVE Binding LLM 학습·추론 가이드

이 문서는 다음 두 프로그램을 하나의 파이프라인으로 사용하는 방법을 설명한다.

- `01-2_train_qwen_cve_bindings.sh`: 단일·멀티 GPU 학습 실행 래퍼다.
- `scripts/train_qwen_cve_bindings.py`: CVE 설명에서 vendor, product, version range를 추출하도록 Qwen3 모델을 QLoRA로 추가 학습한다.
- `scripts/infer_nvd_cve_bindings.py`: 학습된 LoRA adapter를 사용해 NVD JSONL 전체를 파싱한다.

현재 저장소 루트에서 명령을 실행하는 것을 전제로 한다.

## 1. 전체 흐름

```text
학습 JSONL
  └─ 01-2_train_qwen_cve_bindings.sh
       └─ scripts/train_qwen_cve_bindings.py
            ├─ LoRA adapter
            ├─ tokenizer
            ├─ training_manifest.json
            └─ 평가 결과
              │
NVD JSONL ────┴─ scripts/infer_nvd_cve_bindings.py
                    ├─ GPU별 shard
                    ├─ 최종 binding JSONL
                    └─ 실행 요약 meta JSON
```

두 프로그램의 핵심 연결점은 학습 출력 디렉터리의 `training_manifest.json`이다. 추론 프로그램은 manifest에서 다음 정보를 읽는다.

- 원본 base model ID
- base model revision
- 학습에 사용된 system prompt
- tokenizer와 LoRA adapter가 들어 있는 경로

따라서 추론할 때는 `adapter_model.safetensors` 파일 하나가 아니라 **학습 출력 디렉터리 전체**를 `--adapter`로 전달해야 한다.

## 2. 사전 준비

### 2.1 실행 환경

학습과 추론 모두 CUDA GPU가 필요하다. 학습 코드가 요구하는 주요 패키지는 다음과 같다.

```text
CUDA 지원 PyTorch
transformers >= 4.51
accelerate
peft
bitsandbytes
```

CUDA 버전에 맞는 PyTorch를 먼저 설치한 뒤 나머지 패키지를 설치한다.

```bash
python -m pip install -U "transformers>=4.51" accelerate peft bitsandbytes
```

환경을 간단히 점검한다.

```bash
nvidia-smi
python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.device_count())"
```

`torch.cuda.is_available()`은 `True`여야 한다.

### 2.2 주요 경로

현재 기본 경로는 다음과 같다.

| 구분 | 경로 |
|---|---|
| 학습 실행 래퍼 | `01-2_train_qwen_cve_bindings.sh` |
| 학습 코드 | `scripts/train_qwen_cve_bindings.py` |
| 기본 학습 데이터 | `data/cve_bindings_merged-800-hardrule-v1.jsonl` |
| 기본 base model | `Qwen/Qwen3-4B-Instruct-2507` |
| 추론 코드 | `scripts/infer_nvd_cve_bindings.py` |
| 기본 NVD 입력 | `data/nvd-cves.jsonl` |

학습과 추론의 기본 output 경로는 서로 다른 시점의 기존 실험을 가리킬 수 있다. 재현성과 실수 방지를 위해 아래 예제처럼 `--output-dir`과 `--adapter`를 항상 명시하는 것을 권장한다.

학습 래퍼는 기본적으로 `PYTHON_BIN`(기본 `python`)으로 단일 프로세스를 실행한다. 멀티 GPU 학습은 `QWEN_NPROC_PER_NODE`를 2 이상으로 지정하며, 이때 `TORCHRUN_BIN`(기본 `torchrun`)을 사용한다.

## 3. 데이터 형식

### 3.1 학습 JSONL

한 줄에 하나의 JSON object가 있어야 하며, `cve_id`, `description`, `bindings`가 필수다.

```json
{"cve_id":"CVE-2002-0290","description":"Buffer overflow in Netwin WebNews CGI program 1.1 ...","bindings":[{"vendor":"Netwin","product":"WebNews","version_ranges":[{"start":"1.1","start_inclusive":true,"end":"1.1","end_inclusive":true}]}]}
```

binding의 정확한 구조는 다음과 같다.

```json
{
  "vendor": "string 또는 null",
  "product": "비어 있지 않은 string",
  "version_ranges": [
    {
      "start": "string 또는 null",
      "start_inclusive": "boolean 또는 null",
      "end": "string 또는 null",
      "end_inclusive": "boolean 또는 null"
    }
  ]
}
```

범위 표현 규칙은 다음과 같다.

- 정확한 버전: `start`와 `end`가 같고 두 inclusive 값이 모두 `true`
- 상한만 있는 범위: `start`와 `start_inclusive`가 모두 `null`
- 하한만 있는 범위: `end`와 `end_inclusive`가 모두 `null`
- 버전 정보가 없음: 네 필드가 모두 `null`
- 취약 제품이 없거나 rejected/reserved CVE: `bindings`가 빈 배열
- endpoint와 대응하는 inclusive 값은 반드시 함께 값이 있거나 함께 `null`

### 3.2 추론 입력 JSONL

추론 프로그램은 각 줄에서 다음 형식을 지원한다.

```json
{
  "cve": {
    "id": "CVE-2026-12345",
    "descriptions": [
      {"lang": "en", "value": "English CVE description"}
    ]
  }
}
```

영어 설명을 우선 선택하고, 영어 설명이 없으면 사용 가능한 첫 번째 설명을 사용한다. `cve.id` 대신 top-level `cve_id`도 인식하지만, `descriptions` 배열은 필요하다.

## 4. 빠른 시작

### 4.1 데이터만 검증

모델이나 CUDA 학습 stack을 불러오기 전에 JSONL 스키마, CVE ID 중복, split을 검사한다.

```bash
./01-2_train_qwen_cve_bindings.sh \
  --data data/cve_bindings_merged-800-hardrule-v1.jsonl \
  --validate-only
```

현재 기본 데이터에서는 다음과 같은 결과가 예상된다.

```text
전체 801건, train 721건, test 80건
검증 완료
```

### 4.2 단일 GPU 학습

```bash
./01-2_train_qwen_cve_bindings.sh \
  --data data/cve_bindings_merged-800-hardrule-v1.jsonl \
  --model Qwen/Qwen3-4B-Instruct-2507 \
  --output-dir outputs/qwen3-hardrule-single-v1
```

기본 설정은 다음과 같다.

- 9:1 train/test split
- 5 epochs
- GPU당 batch size 1
- gradient accumulation 8
- sequence length 5120
- 4-bit NF4 QLoRA
- LoRA rank 16, alpha 32, dropout 0.05
- SDPA attention
- 학습 종료 후 teacher-forced 평가와 greedy generation 평가

학습 코드는 system/user prompt token에는 loss를 주지 않고 assistant가 출력해야 하는 JSON token만 학습한다.

### 4.3 소량 추론 smoke test

학습이 끝나면 전체 NVD를 처리하기 전에 별도의 output 이름으로 소량 테스트한다.

```bash
python scripts/infer_nvd_cve_bindings.py \
  --input data/nvd-cves.jsonl \
  --adapter outputs/qwen3-hardrule-single-v1 \
  --output data/nvd-cves-bindings-smoke-v1.jsonl \
  --max-records 100 \
  --batch-size 1
```

완료 후 상태를 확인한다.

```bash
python - <<'PY'
import json
from collections import Counter
from pathlib import Path

path = Path("data/nvd-cves-bindings-smoke-v1.jsonl")
counts = Counter()
for line in path.open(encoding="utf-8"):
    record = json.loads(line)
    counts[record["_meta"]["status"]] += 1
print(counts)
PY
```

`ok`가 대부분이어야 한다. `invalid_model_output`, `generation_limit`, `input_error`, `inference_error`가 있다면 8절을 참고한다.

### 4.4 전체 추론

Smoke test가 정상일 때 새로운 output 경로로 전체 추론을 시작한다.

```bash
python scripts/infer_nvd_cve_bindings.py \
  --input data/nvd-cves.jsonl \
  --adapter outputs/qwen3-hardrule-single-v1 \
  --output data/nvd-cves-bindings-qwen3-hardrule-v1.jsonl \
  --batch-size 2
```

## 5. 멀티 GPU 실행

### 5.1 멀티 GPU 학습

GPU 7개를 사용하는 예다.

```bash
QWEN_NPROC_PER_NODE=7 ./01-2_train_qwen_cve_bindings.sh \
  --data data/cve_bindings_merged-800-hardrule-v1.jsonl \
  --model Qwen/Qwen3-4B-Instruct-2507 \
  --output-dir outputs/qwen3-hardrule-ddp-v1 \
  --gradient-accumulation-steps 1
```

DDP에서는 `--batch-size`가 GPU당 batch 크기다. 대략적인 global batch는 다음과 같다.

```text
GPU 수 × GPU당 batch size × gradient accumulation steps
```

GPU 수를 늘린 상태에서 단일 GPU와 같은 accumulation을 유지하면 global batch가 크게 바뀐다. 학습률과 함께 의도적으로 결정해야 한다.

### 5.2 멀티 GPU 추론

```bash
torchrun --standalone --nproc-per-node=7 \
  scripts/infer_nvd_cve_bindings.py \
  --input data/nvd-cves.jsonl \
  --adapter outputs/qwen3-hardrule-ddp-v1 \
  --output data/nvd-cves-bindings-qwen3-hardrule-ddp-v1.jsonl \
  --batch-size 2
```

각 rank는 `source_index % world_size == rank`인 레코드를 처리한다. 예를 들어 최종 output이 다음이라면:

```text
data/nvd-cves-bindings-qwen3-hardrule-ddp-v1.jsonl
```

중간 shard와 실행 manifest는 다음 디렉터리에 저장된다.

```text
data/nvd-cves-bindings-qwen3-hardrule-ddp-v1.jsonl.parts/
  inference_manifest.json
  rank-00000-of-00007.jsonl
  rank-00001-of-00007.jsonl
  ...
```

모든 rank가 끝나면 rank 0이 `source_index` 순서대로 shard를 병합한다. shard는 재개를 위해 병합 후에도 유지된다.

## 6. 학습 출력과 adapter 선택

### 6.1 단일 학습 출력

정상적으로 완료된 출력 디렉터리에는 일반적으로 다음 파일이 있다.

```text
outputs/qwen3-hardrule-single-v1/
  adapter_config.json
  adapter_model.safetensors
  tokenizer.json
  tokenizer_config.json
  chat_template.jinja
  trainer_state.json
  training_args.bin
  training_manifest.json
  test_predictions.jsonl
  checkpoint-*/
```

추론에 가장 중요한 계약은 다음 세 가지다.

- `adapter_model.safetensors`: 학습된 LoRA 가중치
- tokenizer 관련 파일: 학습과 동일한 chat template/tokenization
- `training_manifest.json`: base model, revision, system prompt

추론에는 출력 디렉터리를 그대로 지정한다.

```bash
--adapter outputs/qwen3-hardrule-single-v1
```

### 6.2 K-fold CV 출력

교차검증은 다음과 같이 실행한다.

```bash
QWEN_NPROC_PER_NODE=7 ./01-2_train_qwen_cve_bindings.sh \
  --data data/cve_bindings_merged-800-hardrule-v1.jsonl \
  --output-dir outputs/qwen3-hardrule-cv5-v1 \
  --cv-folds 5 \
  --gradient-accumulation-steps 1
```

출력 구조는 다음과 같다.

```text
outputs/qwen3-hardrule-cv5-v1/
  cv_manifest.json
  oof_predictions.jsonl
  fold-01/
    adapter_model.safetensors
    training_manifest.json
    ...
  fold-02/
    ...
```

주의사항:

- CV 루트에는 `training_manifest.json`과 단일 adapter가 없으므로 그 경로를 추론에 넘길 수 없다.
- 추론하려면 `--adapter outputs/qwen3-hardrule-cv5-v1/fold-01`처럼 특정 fold를 지정해야 한다.
- 각 fold adapter는 development 데이터 일부를 validation으로 제외하고 학습된 모델이다.
- CV 모드는 development에 대해서만 OOF 평가하며 locked test를 평가하지 않는다.
- 배포용 최종 모델이 필요하면 CV로 설정을 정한 뒤, 명확한 최종 학습 정책으로 별도 단일 학습을 수행하는 편이 이해하기 쉽다.

## 7. 중단된 작업 재개

### 7.1 학습 재개

단일 학습은 명시적인 checkpoint 경로에서 재개할 수 있다.

```bash
./01-2_train_qwen_cve_bindings.sh \
  --data data/cve_bindings_merged-800-hardrule-v1.jsonl \
  --model Qwen/Qwen3-4B-Instruct-2507 \
  --output-dir outputs/qwen3-hardrule-single-v1 \
  --resume-from-checkpoint outputs/qwen3-hardrule-single-v1/checkpoint-412
```

재개 시에는 최초 실행과 같은 데이터, 모델 및 학습 옵션을 사용해야 한다. `--resume-from-checkpoint`는 CV 모드에서 지원되지 않는다.

출력 디렉터리가 비어 있지 않으면 프로그램은 기본적으로 새 학습을 거부한다. 새 실험에는 새 output 경로를 사용한다. `--overwrite-output-dir`는 기존 실험 보존이 필요 없다는 것이 확실할 때만 사용한다.

### 7.2 추론 재개

중단된 전체 추론은 최초 실행과 동일한 명령에 `--resume`만 추가한다.

```bash
torchrun --standalone --nproc-per-node=7 \
  scripts/infer_nvd_cve_bindings.py \
  --input data/nvd-cves.jsonl \
  --adapter outputs/qwen3-hardrule-ddp-v1 \
  --output data/nvd-cves-bindings-qwen3-hardrule-ddp-v1.jsonl \
  --batch-size 2 \
  --resume
```

추론 재개 시 다음 값은 최초 실행과 같아야 한다.

- 입력 파일의 경로, 크기, 수정 시각
- adapter manifest hash
- GPU 수(`world_size`)
- `--max-records`
- batch size와 token 한도
- 4-bit 사용 여부
- attention implementation

하나라도 바뀌면 기존 shard를 이어 쓰지 않고 오류를 낸다. 옵션을 변경해 다시 실행하려면 새 `--output` 경로를 사용한다.

마지막 JSONL 줄만 불완전하게 기록된 경우에는 재개 과정에서 해당 불완전 줄만 잘라내고 이어서 처리한다. shard 중간이 손상된 경우에는 자동으로 무시하지 않고 중단한다.

### 7.3 shard만 만든 뒤 나중에 병합

장시간 분산 실행에서 우선 shard만 만들려면 `--skip-merge`를 사용한다.

```bash
torchrun --standalone --nproc-per-node=7 \
  scripts/infer_nvd_cve_bindings.py \
  --input data/nvd-cves.jsonl \
  --adapter outputs/qwen3-hardrule-ddp-v1 \
  --output data/nvd-cves-bindings-qwen3-hardrule-ddp-v1.jsonl \
  --batch-size 2 \
  --skip-merge
```

나중에 같은 명령에서 `--skip-merge`를 빼고 `--resume`을 추가하면 완료된 shard를 확인한 뒤 최종 병합을 수행한다.

## 8. 추론 결과 읽기

정상 결과 한 줄은 다음 형태다.

```json
{
  "cve_id": "CVE-1999-0001",
  "description": "ip_input.c in BSD-derived TCP/IP implementations ...",
  "bindings": [
    {
      "vendor": null,
      "product": "ip_input.c",
      "version_ranges": [
        {
          "start": null,
          "start_inclusive": null,
          "end": null,
          "end_inclusive": null
        }
      ]
    }
  ],
  "_meta": {
    "source_index": 0,
    "status": "ok",
    "input_truncated": false,
    "original_prompt_tokens": 256,
    "prompt_tokens": 256,
    "generated_tokens": 38
  }
}
```

`_meta.status`의 의미는 다음과 같다.

| 상태 | 의미 | 확인할 내용 |
|---|---|---|
| `ok` | JSON 생성과 스키마 검증 성공 | 정상 |
| `generation_limit` | JSON은 유효하지만 EOS 전에 생성 한도 도달 | `--max-new-tokens` 증가 검토 |
| `invalid_model_output` | 생성 문자열이 JSON이 아니거나 binding 스키마 위반 | `_meta.raw_model_output` 확인 |
| `input_error` | 입력 JSON, CVE ID, description 또는 prompt 구성 오류 | `_meta.error`와 원본 줄 확인 |
| `inference_error` | CUDA OOM 또는 모델 실행 오류 | `_meta.error`, GPU 메모리 및 환경 확인 |

오류 레코드는 누락시키지 않는다. 대신 `bindings`를 `null`로 두고 정확한 이유를 `_meta`에 기록한다. 실제로 영향받는 제품이 없는 정상 예측은 `bindings: []`이므로 `null`과 빈 배열을 구분해야 한다.

최종 병합이 끝나면 output 옆에 요약 파일이 생성된다.

```text
data/nvd-cves-bindings-qwen3-hardrule-ddp-v1.jsonl.meta.json
```

이 파일에는 전체 레코드 수, status별 건수, 입력·adapter·생성 옵션이 기록된다.

## 9. 주요 옵션 선택 기준

### 9.1 학습 옵션

| 옵션 | 기본값 | 사용 기준 |
|---|---:|---|
| `--max-seq-length` | 5120 | 정답 JSON을 포함한 전체 conversation 길이. 초과 레코드가 있으면 학습이 중단됨 |
| `--epochs` | 5 | 소규모 데이터이므로 generation 평가와 과적합을 함께 관찰 |
| `--batch-size` | 1 | GPU당 batch. OOM이면 유지하거나 줄임 |
| `--gradient-accumulation-steps` | 8 | 원하는 global batch에 맞춤 |
| `--learning-rate` | `2e-4` | LoRA 학습률 |
| `--use-4bit` | 사용 | VRAM 절약. 끄려면 `--no-use-4bit` |
| `--generation-eval` | 사용 | 실제 자유 생성 품질 확인. 빠른 실험에서는 `--no-generation-eval` 가능 |
| `--attn-implementation` | `sdpa` | Flash Attention 설치 시 `flash_attention_2` 선택 가능 |
| `--cv-folds` | 1 | 2 이상이면 grouped CV |

`--max-seq-length`를 낮춰서 정답을 자르는 동작은 하지 않는다. 한 건이라도 초과하면 필요한 최소 길이를 알려주고 중단한다.

### 9.2 추론 옵션

| 옵션 | 기본값 | 사용 기준 |
|---|---:|---|
| `--batch-size` | 2 | GPU당 생성 batch. OOM 발생 시 프로그램이 batch를 재귀적으로 반으로 나눔 |
| `--max-input-tokens` | 4096 | 긴 description은 앞·뒤를 남기고 중간을 축약 |
| `--max-new-tokens` | 512 | 긴 binding JSON에서 `generation_limit`이 나오면 증가 |
| `--max-records` | 전체 | Smoke test에 사용 |
| `--log-every` | 100 | rank별 진행 로그 주기 |
| `--flush-every` | 25 | shard flush/fsync 주기 |
| `--max-consecutive-errors` | 10 | 연속 inference 오류 시 중단하는 기준 |
| `--no-4bit` | 미사용 | 충분한 VRAM으로 비양자화 추론할 때만 지정 |

Batch OOM이 발생하면 여러 레코드 batch를 자동으로 나눠 재시도한다. 레코드 한 건도 처리하지 못하는 OOM은 `inference_error`로 기록된다.

## 10. 문제 해결

### 학습 데이터 검증 실패

먼저 다음 명령으로 모델 로딩 없이 오류 행을 확인한다.

```bash
./01-2_train_qwen_cve_bindings.sh --data path/to/train.jsonl --validate-only
```

중복 CVE ID, 누락된 키, 비어 있는 product, endpoint/inclusive 불일치가 대표적인 원인이다.

### 학습 중 CUDA OOM

다음 순서로 조정한다.

1. `--batch-size 1`인지 확인한다.
2. 4-bit 기본 설정을 유지한다.
3. gradient checkpointing 기본 설정을 유지한다.
4. 실제 데이터가 허용하는 범위에서 `--max-seq-length`를 조정한다.
5. generation 평가만 OOM이면 `--generation-batch-size 1`을 사용한다.

### `logits_to_keep` 오류

현재 모델과 Transformers 조합이 학습 코드의 memory 최적화를 지원하지 않는 경우다. Qwen3 모델인지, `transformers>=4.51`인지 확인한다.

### adapter manifest를 찾을 수 없음

`--adapter`에 checkpoint 파일이나 CV 루트가 아니라 `training_manifest.json`이 있는 실제 adapter 디렉터리를 지정한다.

```bash
test -f outputs/qwen3-hardrule-single-v1/training_manifest.json
test -f outputs/qwen3-hardrule-single-v1/adapter_model.safetensors
```

### 최종 추론 output이 이미 존재함

추론 코드는 기존 최종 결과를 자동으로 덮어쓰지 않는다.

- 중단 작업을 잇는 경우: 동일 옵션과 `--resume` 사용
- 다른 실험인 경우: 새 `--output` 경로 사용

### `--resume` manifest 불일치

최초 실행과 GPU 수 또는 옵션이 달라진 경우다. 최초 명령과 동일하게 실행하거나 새 output 경로로 시작한다.

### `invalid_model_output`가 많음

다음을 순서대로 확인한다.

1. 올바른 adapter 디렉터리를 지정했는지 확인한다.
2. `training_manifest.json`의 `base_model`과 `system_prompt`가 기대한 실험인지 확인한다.
3. 학습의 `test_predictions.jsonl` 또는 CV의 validation/OOF prediction 품질을 확인한다.
4. `generation_limit`도 많다면 `--max-new-tokens`를 늘린다.
5. 소량 결과의 `_meta.raw_model_output`을 직접 검토한다.

## 11. 권장 운영 체크리스트

학습 전:

- [ ] 올바른 CUDA 환경이 활성화되어 있다.
- [ ] `--validate-only`가 통과한다.
- [ ] 데이터 파일과 base model revision을 기록했다.
- [ ] 기존 실험과 겹치지 않는 output 디렉터리를 정했다.
- [ ] GPU 수에 맞춰 global batch를 계산했다.

학습 후:

- [ ] `adapter_model.safetensors`가 존재한다.
- [ ] `training_manifest.json`이 존재한다.
- [ ] test/generation metric을 확인했다.
- [ ] `training_manifest.json`의 데이터 hash와 CLI 옵션을 보존했다.

전체 추론 전:

- [ ] `--adapter`를 명시했다.
- [ ] `--max-records 100` smoke test가 정상이다.
- [ ] `invalid_model_output`와 `inference_error` 샘플을 검토했다.
- [ ] 전체 실행에 고유한 output 경로를 사용한다.
- [ ] 중단 후 재개할 때 같은 GPU 수와 옵션을 유지할 수 있다.

전체 추론 후:

- [ ] 최종 JSONL 레코드 수를 확인했다.
- [ ] `.meta.json`의 status count를 확인했다.
- [ ] `bindings: null` 레코드를 별도로 검토했다.
- [ ] adapter와 manifest를 결과 데이터와 함께 보관했다.

## 12. 현재 저장소의 기존 모델을 사용할 때

현재 보존된 기존 adapter는 다음 경로에 있다.

```text
outputs/qwen3-merged800-20260723-155213
```

이 모델은 `data/cve_bindings_merged-800.jsonl`로 학습된 과거 실험이다. 현재 학습 코드의 기본 데이터인 `data/cve_bindings_merged-800-hardrule-v1.jsonl`과 다르다. 기존 모델로 추론하려면 adapter를 명시한다.

```bash
python scripts/infer_nvd_cve_bindings.py \
  --input data/nvd-cves.jsonl \
  --adapter outputs/qwen3-merged800-20260723-155213 \
  --output data/nvd-cves-bindings-existing-model-smoke.jsonl \
  --max-records 100
```

새 학습 결과와 기존 모델 결과는 output 이름을 구분하고, 각 output의 `.meta.json` 및 adapter의 `training_manifest.json`을 함께 비교해야 한다.
