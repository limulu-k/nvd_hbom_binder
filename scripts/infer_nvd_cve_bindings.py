#!/usr/bin/env python3
"""Parse every NVD CVE with the trained Qwen LoRA on all available GPUs.

Each torchrun rank owns source lines where ``source_index % world_size == rank``
and appends them to an independent JSONL shard.  Rank 0 merges the sorted shards
into one JSONL after every rank finishes.  Shards are intentionally retained so
an interrupted multi-day run can continue with ``--resume``.

Seven-GPU example::

    torchrun --standalone --nproc-per-node=7 \
      scripts/infer_nvd_cve_bindings.py \
      --input data/nvd-cves.jsonl \
      --adapter models/qwen3-merged800-20260723-155213 \
      --output data/nvd-cves-parsed-bindings.jsonl \
      --batch-size 2

Each output line contains ``cve_id``, ``description``, ``bindings``, and
``_meta``.  ``bindings`` is null only when input parsing or inference failed;
the exact reason and, when useful, the raw model output are retained in
``_meta`` instead of silently converting an error into an empty binding list.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import os
import re
import sys
import time
import warnings
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


DEFAULT_INPUT = Path("data/nvd-cves.jsonl")
DEFAULT_ADAPTER = Path("models/qwen3-merged800-20260723-155213")
DEFAULT_OUTPUT = Path("data/nvd-cves-parsed-bindings.jsonl")
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
RUN_MANIFEST_NAME = "inference_manifest.json"


class InferenceConfigurationError(ValueError):
    """Raised when input, output, or resume state is unsafe or inconsistent."""


@dataclass(frozen=True)
class PendingRecord:
    source_index: int
    cve_id: str
    description: str
    prompt_ids: list[int]
    input_truncated: bool
    original_prompt_tokens: int


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def count_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            count += block.count(b"\n")
        if path.stat().st_size:
            source.seek(-1, os.SEEK_END)
            if source.read(1) != b"\n":
                count += 1
    return count


def load_training_manifest(adapter: Path) -> dict[str, Any]:
    manifest_path = adapter / "training_manifest.json"
    if not adapter.is_dir():
        raise InferenceConfigurationError(f"LoRA adapter 디렉터리를 찾을 수 없습니다: {adapter}")
    if not manifest_path.is_file():
        raise InferenceConfigurationError(
            f"학습 manifest를 찾을 수 없습니다: {manifest_path}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InferenceConfigurationError(
            f"학습 manifest를 읽을 수 없습니다: {manifest_path}: {exc}"
        ) from exc
    required = {"base_model", "system_prompt"}
    missing = required.difference(manifest)
    if missing:
        raise InferenceConfigurationError(
            f"학습 manifest 필수 키가 없습니다: {sorted(missing)}"
        )
    return manifest


def parts_directory(output: Path) -> Path:
    return output.with_name(f"{output.name}.parts")


def shard_path(parts_dir: Path, rank: int, world_size: int) -> Path:
    return parts_dir / f"rank-{rank:05d}-of-{world_size:05d}.jsonl"


def assigned_record_count(total_records: int, rank: int, world_size: int) -> int:
    if total_records <= rank:
        return 0
    return ((total_records - 1 - rank) // world_size) + 1


def build_run_manifest(
    *,
    args: argparse.Namespace,
    world_size: int,
    training_manifest: dict[str, Any],
    source_records: int,
) -> dict[str, Any]:
    input_stat = args.input.stat()
    training_manifest_path = args.adapter / "training_manifest.json"
    limited_records = (
        min(source_records, args.max_records)
        if args.max_records is not None
        else source_records
    )
    return {
        "format_version": 1,
        "created_at": utc_now(),
        "input_path": str(args.input.resolve()),
        "input_size": input_stat.st_size,
        "input_mtime_ns": input_stat.st_mtime_ns,
        "source_record_count": source_records,
        "selected_record_count": limited_records,
        "max_records": args.max_records,
        "adapter_path": str(args.adapter.resolve()),
        "adapter_manifest_sha256": sha256_file(training_manifest_path),
        "base_model": training_manifest["base_model"],
        "resolved_revision": (
            training_manifest.get("resolved_revision")
            or training_manifest.get("requested_revision")
            or "main"
        ),
        "system_prompt_sha256": hashlib.sha256(
            training_manifest["system_prompt"].encode("utf-8")
        ).hexdigest(),
        "world_size": world_size,
        "generation": {
            "max_input_tokens": args.max_input_tokens,
            "max_new_tokens": args.max_new_tokens,
            "batch_size": args.batch_size,
            "use_4bit": args.use_4bit,
            "attn_implementation": args.attn_implementation,
        },
    }


def comparable_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "created_at"}


def prepare_output_state(
    *,
    args: argparse.Namespace,
    rank: int,
    world_size: int,
    training_manifest: dict[str, Any],
) -> None:
    """Create or validate run state on rank 0 before any model is loaded."""
    if rank != 0:
        return
    if not args.input.is_file():
        raise InferenceConfigurationError(f"NVD JSONL을 찾을 수 없습니다: {args.input}")
    if args.output.resolve() == args.input.resolve():
        raise InferenceConfigurationError("입력 JSONL과 출력 JSONL은 같은 경로일 수 없습니다.")
    if args.output.exists():
        raise InferenceConfigurationError(
            f"최종 출력이 이미 존재합니다: {args.output}. "
            "기존 결과를 보존하기 위해 자동 덮어쓰지 않습니다."
        )

    parts_dir = parts_directory(args.output)
    manifest_path = parts_dir / RUN_MANIFEST_NAME
    source_records: int
    if args.resume:
        if not manifest_path.is_file():
            raise InferenceConfigurationError(
                f"--resume을 사용했지만 run manifest가 없습니다: {manifest_path}"
            )
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        source_records = int(existing["source_record_count"])
        current = build_run_manifest(
            args=args,
            world_size=world_size,
            training_manifest=training_manifest,
            source_records=source_records,
        )
        if comparable_manifest(existing) != comparable_manifest(current):
            raise InferenceConfigurationError(
                "현재 입력·adapter·GPU 수·생성 옵션이 기존 shard manifest와 다릅니다. "
                "동일한 옵션으로 재개하거나 새 --output 경로를 사용하세요."
            )
        return

    if parts_dir.exists() and any(parts_dir.iterdir()):
        raise InferenceConfigurationError(
            f"shard 디렉터리가 비어 있지 않습니다: {parts_dir}. "
            "기존 실행을 잇는 경우 --resume을 사용하세요."
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    parts_dir.mkdir(parents=True, exist_ok=True)
    source_records = count_lines(args.input)
    manifest = build_run_manifest(
        args=args,
        world_size=world_size,
        training_manifest=training_manifest,
        source_records=source_records,
    )
    atomic_write_json(manifest_path, manifest)


def recover_shard(path: Path, rank: int, world_size: int) -> tuple[int, int]:
    """Validate a resumable shard and truncate only an incomplete final line."""
    if not path.exists():
        return -1, 0
    last_index = -1
    record_count = 0
    last_good_offset = 0
    file_size = path.stat().st_size
    with path.open("r+b") as shard:
        while True:
            line_start = shard.tell()
            raw_line = shard.readline()
            if not raw_line:
                break
            line_end = shard.tell()
            if not raw_line.endswith(b"\n"):
                shard.truncate(line_start)
                break
            try:
                record = json.loads(raw_line)
                source_index = int(record["_meta"]["source_index"])
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                if line_end == file_size:
                    shard.truncate(line_start)
                    break
                raise InferenceConfigurationError(
                    f"shard 중간에 손상된 JSON이 있습니다: {path}, "
                    f"record {record_count + 1}: {exc}"
                ) from exc
            expected_index = rank + record_count * world_size
            if source_index != expected_index:
                raise InferenceConfigurationError(
                    f"shard source_index 순서가 잘못됐습니다: {path}: "
                    f"{source_index} != {expected_index}"
                )
            last_index = source_index
            record_count += 1
            last_good_offset = line_end
        if shard.tell() != last_good_offset:
            shard.truncate(last_good_offset)
    return last_index, record_count


def extract_nvd_record(raw_line: str, source_index: int) -> tuple[str, str]:
    try:
        raw = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"입력 JSON 오류: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("입력 레코드가 JSON object가 아닙니다.")
    cve = raw.get("cve", raw)
    if not isinstance(cve, dict):
        raise ValueError("cve 필드가 JSON object가 아닙니다.")
    cve_id = cve.get("id") or raw.get("cve_id")
    if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id.strip()):
        raise ValueError(f"CVE ID 형식이 올바르지 않습니다: {cve_id!r}")

    descriptions = cve.get("descriptions")
    if descriptions is None:
        descriptions = raw.get("descriptions")
    if not isinstance(descriptions, list):
        raise ValueError("descriptions가 array가 아닙니다.")
    candidates: list[tuple[str, str]] = []
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        language = item.get("lang")
        value = item.get("value")
        if isinstance(value, str) and value.strip():
            candidates.append(
                (language.lower() if isinstance(language, str) else "", value.strip())
            )
    if not candidates:
        raise ValueError("사용 가능한 description이 없습니다.")
    description = next(
        (value for language, value in candidates if language == "en"),
        next(
            (value for language, value in candidates if language.startswith("en-")),
            candidates[0][1],
        ),
    )
    return cve_id.strip().upper(), description


def apply_chat_template_ids(
    tokenizer: Any, messages: list[dict[str, str]]
) -> list[int]:
    result = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        return_dict=True,
    )
    try:
        input_ids = result["input_ids"]
    except (KeyError, TypeError) as exc:
        raise RuntimeError("chat template 결과에 input_ids가 없습니다.") from exc
    if not isinstance(input_ids, list) or (
        input_ids and not isinstance(input_ids[0], int)
    ):
        raise RuntimeError("chat template input_ids가 단일 token 목록이 아닙니다.")
    return input_ids


def user_prompt(cve_id: str, description: str) -> str:
    return f"CVE ID: {cve_id}\nDescription:\n{description}"


def build_prompt_ids(
    *,
    tokenizer: Any,
    system_prompt: str,
    cve_id: str,
    description: str,
    max_input_tokens: int,
) -> tuple[list[int], bool, int]:
    def encode(current_description: str) -> list[int]:
        return apply_chat_template_ids(
            tokenizer,
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt(cve_id, current_description)},
            ],
        )

    full_ids = encode(description)
    original_length = len(full_ids)
    if original_length <= max_input_tokens:
        return full_ids, False, original_length

    marker = "\n[... description truncated for model context ...]\n"
    description_ids = tokenizer.encode(description, add_special_tokens=False)
    empty_prompt_length = len(encode(""))
    marker_length = len(tokenizer.encode(marker, add_special_tokens=False))
    budget = max_input_tokens - empty_prompt_length - marker_length - 8
    if budget < 32:
        raise ValueError(
            f"--max-input-tokens {max_input_tokens}가 system/user prompt에도 너무 작습니다."
        )

    while budget >= 32:
        head_count = math.ceil(budget / 2)
        tail_count = budget // 2
        head = tokenizer.decode(
            description_ids[:head_count], skip_special_tokens=True
        )
        tail = tokenizer.decode(
            description_ids[-tail_count:], skip_special_tokens=True
        )
        truncated_ids = encode(f"{head}{marker}{tail}")
        if len(truncated_ids) <= max_input_tokens:
            return truncated_ids, True, original_length
        budget -= max(8, len(truncated_ids) - max_input_tokens)
    raise ValueError("description을 설정된 입력 token 한도에 맞게 축약하지 못했습니다.")


def nullable_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field}: null 또는 비어 있지 않은 문자열이어야 합니다.")
    return value.strip()


def nullable_bool(value: Any, field: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise ValueError(f"{field}: boolean 또는 null이어야 합니다.")


def validate_bindings_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or set(payload) != {"bindings"}:
        raise ValueError('최상위 JSON은 단일 키 "bindings"만 가져야 합니다.')
    raw_bindings = payload["bindings"]
    if not isinstance(raw_bindings, list):
        raise ValueError("bindings가 array가 아닙니다.")
    bindings: list[dict[str, Any]] = []
    for binding_index, raw_binding in enumerate(raw_bindings):
        prefix = f"bindings[{binding_index}]"
        if not isinstance(raw_binding, dict) or set(raw_binding) != {
            "vendor",
            "product",
            "version_ranges",
        }:
            raise ValueError(f"{prefix}: 필드 구성이 올바르지 않습니다.")
        vendor = nullable_string(raw_binding["vendor"], f"{prefix}.vendor")
        product = nullable_string(raw_binding["product"], f"{prefix}.product")
        if product is None:
            raise ValueError(f"{prefix}.product는 null일 수 없습니다.")
        raw_ranges = raw_binding["version_ranges"]
        if not isinstance(raw_ranges, list) or not raw_ranges:
            raise ValueError(f"{prefix}.version_ranges가 비어 있습니다.")
        ranges: list[dict[str, Any]] = []
        for range_index, raw_range in enumerate(raw_ranges):
            range_prefix = f"{prefix}.version_ranges[{range_index}]"
            if not isinstance(raw_range, dict) or set(raw_range) != {
                "start",
                "start_inclusive",
                "end",
                "end_inclusive",
            }:
                raise ValueError(f"{range_prefix}: 필드 구성이 올바르지 않습니다.")
            start = nullable_string(raw_range["start"], f"{range_prefix}.start")
            end = nullable_string(raw_range["end"], f"{range_prefix}.end")
            start_inclusive = nullable_bool(
                raw_range["start_inclusive"], f"{range_prefix}.start_inclusive"
            )
            end_inclusive = nullable_bool(
                raw_range["end_inclusive"], f"{range_prefix}.end_inclusive"
            )
            if (start is None) != (start_inclusive is None):
                raise ValueError(
                    f"{range_prefix}: start와 start_inclusive가 함께 null이어야 합니다."
                )
            if (end is None) != (end_inclusive is None):
                raise ValueError(
                    f"{range_prefix}: end와 end_inclusive가 함께 null이어야 합니다."
                )
            ranges.append(
                {
                    "start": start,
                    "start_inclusive": start_inclusive,
                    "end": end,
                    "end_inclusive": end_inclusive,
                }
            )
        bindings.append(
            {"vendor": vendor, "product": product, "version_ranges": ranges}
        )
    return bindings


def error_record(
    *,
    source_index: int,
    status: str,
    error: str,
    cve_id: str | None = None,
    description: str | None = None,
    raw_output: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "source_index": source_index,
        "status": status,
        "error": error,
    }
    if raw_output is not None:
        metadata["raw_model_output"] = raw_output[:8192]
    return {
        "cve_id": cve_id,
        "description": description,
        "bindings": None,
        "_meta": metadata,
    }


def successful_record(
    *,
    pending: PendingRecord,
    bindings: list[dict[str, Any]],
    status: str,
    generated_tokens: int,
    raw_output: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "source_index": pending.source_index,
        "status": status,
        "input_truncated": pending.input_truncated,
        "original_prompt_tokens": pending.original_prompt_tokens,
        "prompt_tokens": len(pending.prompt_ids),
        "generated_tokens": generated_tokens,
    }
    if raw_output is not None:
        metadata["raw_model_output"] = raw_output[:8192]
    return {
        "cve_id": pending.cve_id,
        "description": pending.description,
        "bindings": bindings,
        "_meta": metadata,
    }


def load_model_stack(
    *,
    args: argparse.Namespace,
    training_manifest: dict[str, Any],
    local_rank: int,
) -> tuple[Any, Any, Any]:
    try:
        import torch
        from peft import PeftModel
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )
        from transformers.utils import logging as transformers_logging
    except ImportError as exc:
        raise RuntimeError(
            "추론 의존성이 없습니다. 학습에 사용한 clovery310 환경을 활성화하세요: "
            f"{exc}"
        ) from exc

    transformers_logging.disable_progress_bar()
    torch.cuda.set_device(local_rank)
    tokenizer = AutoTokenizer.from_pretrained(args.adapter, use_fast=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "left"

    model_kwargs: dict[str, Any] = {
        "revision": (
            training_manifest.get("resolved_revision")
            or training_manifest.get("requested_revision")
            or "main"
        ),
        "dtype": torch.float16,
        "device_map": {"": local_rank},
        "low_cpu_mem_usage": True,
        "attn_implementation": args.attn_implementation,
    }
    if args.use_4bit:
        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
    base_model = AutoModelForCausalLM.from_pretrained(
        training_manifest["base_model"], **model_kwargs
    )
    model = PeftModel.from_pretrained(base_model, args.adapter)
    model.eval()
    model.config.use_cache = True
    return torch, tokenizer, model


def eos_token_ids(tokenizer: Any, model: Any) -> set[int]:
    values: list[Any] = [
        tokenizer.eos_token_id,
        getattr(model.generation_config, "eos_token_id", None),
    ]
    result: set[int] = set()
    for value in values:
        if isinstance(value, int):
            result.add(value)
        elif isinstance(value, (list, tuple)):
            result.update(item for item in value if isinstance(item, int))
    return result


def generate_batch(
    *,
    torch: Any,
    tokenizer: Any,
    model: Any,
    pending_records: Sequence[PendingRecord],
    max_new_tokens: int,
    local_rank: int,
) -> list[dict[str, Any]]:
    max_length = max(len(record.prompt_ids) for record in pending_records)
    padded_ids: list[list[int]] = []
    attention_masks: list[list[int]] = []
    for record in pending_records:
        padding = max_length - len(record.prompt_ids)
        padded_ids.append([tokenizer.pad_token_id] * padding + record.prompt_ids)
        attention_masks.append([0] * padding + [1] * len(record.prompt_ids))
    input_ids = torch.tensor(padded_ids, dtype=torch.long, device=f"cuda:{local_rank}")
    attention_mask = torch.tensor(
        attention_masks, dtype=torch.long, device=f"cuda:{local_rank}"
    )
    with torch.inference_mode():
        sequences = model.generate(
            input_ids=input_ids,
            attention_mask=attention_mask,
            do_sample=False,
            max_new_tokens=max_new_tokens,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
            use_cache=True,
        )

    eos_ids = eos_token_ids(tokenizer, model)
    results: list[dict[str, Any]] = []
    for row, pending in enumerate(pending_records):
        generated_ids = sequences[row, max_length:].tolist()
        eos_position = next(
            (index for index, token_id in enumerate(generated_ids) if token_id in eos_ids),
            None,
        )
        hit_generation_limit = eos_position is None and len(generated_ids) >= max_new_tokens
        content_ids = (
            generated_ids if eos_position is None else generated_ids[:eos_position]
        )
        generated_text = tokenizer.decode(
            content_ids, skip_special_tokens=True
        ).strip()
        try:
            payload = json.loads(generated_text)
            bindings = validate_bindings_payload(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            results.append(
                error_record(
                    source_index=pending.source_index,
                    cve_id=pending.cve_id,
                    description=pending.description,
                    status="invalid_model_output",
                    error=f"{type(exc).__name__}: {exc}",
                    raw_output=generated_text,
                )
            )
            continue
        status = "generation_limit" if hit_generation_limit else "ok"
        results.append(
            successful_record(
                pending=pending,
                bindings=bindings,
                status=status,
                generated_tokens=len(content_ids),
                raw_output=generated_text if hit_generation_limit else None,
            )
        )
    return results


def generate_batch_safely(
    *,
    torch: Any,
    tokenizer: Any,
    model: Any,
    pending_records: Sequence[PendingRecord],
    max_new_tokens: int,
    local_rank: int,
) -> list[dict[str, Any]]:
    try:
        return generate_batch(
            torch=torch,
            tokenizer=tokenizer,
            model=model,
            pending_records=pending_records,
            max_new_tokens=max_new_tokens,
            local_rank=local_rank,
        )
    except torch.cuda.OutOfMemoryError as exc:
        torch.cuda.empty_cache()
        if len(pending_records) > 1:
            midpoint = len(pending_records) // 2
            return generate_batch_safely(
                torch=torch,
                tokenizer=tokenizer,
                model=model,
                pending_records=pending_records[:midpoint],
                max_new_tokens=max_new_tokens,
                local_rank=local_rank,
            ) + generate_batch_safely(
                torch=torch,
                tokenizer=tokenizer,
                model=model,
                pending_records=pending_records[midpoint:],
                max_new_tokens=max_new_tokens,
                local_rank=local_rank,
            )
        pending = pending_records[0]
        return [
            error_record(
                source_index=pending.source_index,
                cve_id=pending.cve_id,
                description=pending.description,
                status="inference_error",
                error=f"CUDA out of memory: {exc}",
            )
        ]
    except RuntimeError as exc:
        torch.cuda.empty_cache()
        return [
            error_record(
                source_index=pending.source_index,
                cve_id=pending.cve_id,
                description=pending.description,
                status="inference_error",
                error=f"RuntimeError: {exc}",
            )
            for pending in pending_records
        ]


def write_records(
    writer: Any,
    records: Iterable[dict[str, Any]],
    counters: Counter[str],
) -> int:
    written = 0
    for record in records:
        writer.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        counters[record["_meta"]["status"]] += 1
        written += 1
    return written


def process_rank(
    *,
    args: argparse.Namespace,
    rank: int,
    world_size: int,
    local_rank: int,
    source_records: int,
    training_manifest: dict[str, Any],
    shard: Path,
    recovered_count: int,
) -> Counter[str]:
    selected_records = (
        min(source_records, args.max_records)
        if args.max_records is not None
        else source_records
    )
    expected_count = assigned_record_count(selected_records, rank, world_size)
    remaining = expected_count - recovered_count
    counters: Counter[str] = Counter()
    if remaining <= 0:
        print(
            f"[rank {rank}] shard already complete: {recovered_count}/{expected_count}",
            file=sys.stderr,
            flush=True,
        )
        return counters

    print(
        f"[rank {rank}] loading model on GPU {local_rank}; "
        f"remaining={remaining:,}/{expected_count:,}",
        file=sys.stderr,
        flush=True,
    )
    torch, tokenizer, model = load_model_stack(
        args=args, training_manifest=training_manifest, local_rank=local_rank
    )
    system_prompt = training_manifest["system_prompt"]
    processed_this_run = 0
    pending: list[PendingRecord] = []
    consecutive_inference_errors = 0
    started = time.perf_counter()

    with args.input.open("r", encoding="utf-8") as source, shard.open(
        "a", encoding="utf-8", buffering=1024 * 1024
    ) as writer:

        def flush_pending() -> None:
            nonlocal pending, processed_this_run, consecutive_inference_errors
            if not pending:
                return
            results = generate_batch_safely(
                torch=torch,
                tokenizer=tokenizer,
                model=model,
                pending_records=pending,
                max_new_tokens=args.max_new_tokens,
                local_rank=local_rank,
            )
            inference_errors = sum(
                record["_meta"]["status"] == "inference_error" for record in results
            )
            if inference_errors == len(results):
                consecutive_inference_errors += inference_errors
            else:
                consecutive_inference_errors = 0
            processed_this_run += write_records(writer, results, counters)
            pending = []
            if consecutive_inference_errors >= args.max_consecutive_errors:
                writer.flush()
                os.fsync(writer.fileno())
                raise RuntimeError(
                    f"rank {rank}에서 inference_error가 "
                    f"{consecutive_inference_errors}건 연속 발생했습니다."
                )
            if processed_this_run % args.flush_every < len(results):
                writer.flush()
                os.fsync(writer.fileno())
            if (
                processed_this_run % args.log_every < len(results)
                or processed_this_run == remaining
            ):
                elapsed = max(time.perf_counter() - started, 1e-9)
                rate = processed_this_run / elapsed
                total_done = recovered_count + processed_this_run
                eta = (expected_count - total_done) / rate if rate else float("inf")
                print(
                    f"[rank {rank}] {total_done:,}/{expected_count:,} "
                    f"({total_done / expected_count:.1%}) · "
                    f"{rate:.3f} CVE/s · ETA {eta / 3600:.2f}h · "
                    f"status={dict(counters)}",
                    file=sys.stderr,
                    flush=True,
                )

        for source_index, raw_line in enumerate(source):
            if args.max_records is not None and source_index >= args.max_records:
                break
            if source_index % world_size != rank:
                continue
            assigned_position = (source_index - rank) // world_size
            if assigned_position < recovered_count:
                continue
            cve_id: str | None = None
            description: str | None = None
            try:
                cve_id, description = extract_nvd_record(raw_line, source_index)
                prompt_ids, was_truncated, original_tokens = build_prompt_ids(
                    tokenizer=tokenizer,
                    system_prompt=system_prompt,
                    cve_id=cve_id,
                    description=description,
                    max_input_tokens=args.max_input_tokens,
                )
                pending.append(
                    PendingRecord(
                        source_index=source_index,
                        cve_id=cve_id,
                        description=description,
                        prompt_ids=prompt_ids,
                        input_truncated=was_truncated,
                        original_prompt_tokens=original_tokens,
                    )
                )
            except (ValueError, RuntimeError) as exc:
                flush_pending()
                processed_this_run += write_records(
                    writer,
                    [
                        error_record(
                            source_index=source_index,
                            status="input_error",
                            error=f"{type(exc).__name__}: {exc}",
                            cve_id=cve_id,
                            description=description,
                        )
                    ],
                    counters,
                )
            if len(pending) >= args.batch_size:
                flush_pending()
        flush_pending()
        writer.flush()
        os.fsync(writer.fileno())

    final_count = recovered_count + processed_this_run
    if final_count != expected_count:
        raise RuntimeError(
            f"rank {rank} 처리 수 불일치: {final_count} != {expected_count}"
        )
    return counters


def next_shard_item(handle: Any, rank: int) -> tuple[int, int, bytes] | None:
    raw_line = handle.readline()
    if not raw_line:
        return None
    record = json.loads(raw_line)
    return int(record["_meta"]["source_index"]), rank, raw_line


def merge_shards(
    *,
    output: Path,
    parts_dir: Path,
    world_size: int,
    expected_records: int,
    run_manifest: dict[str, Any],
) -> dict[str, Any]:
    shard_paths = [shard_path(parts_dir, rank, world_size) for rank in range(world_size)]
    missing = [str(path) for path in shard_paths if not path.is_file()]
    if missing:
        raise RuntimeError(f"병합할 shard가 없습니다: {missing}")
    handles = [path.open("rb") for path in shard_paths]
    heap: list[tuple[int, int, bytes]] = []
    status_counts: Counter[str] = Counter()
    temporary = output.with_name(f".{output.name}.merge.tmp")
    if temporary.exists():
        temporary.unlink()
    try:
        for rank, handle in enumerate(handles):
            item = next_shard_item(handle, rank)
            if item is not None:
                heapq.heappush(heap, item)
        expected_index = 0
        with temporary.open("wb") as destination:
            while heap:
                source_index, rank, raw_line = heapq.heappop(heap)
                if source_index != expected_index:
                    raise RuntimeError(
                        f"shard 병합 source_index 불일치: "
                        f"{source_index} != {expected_index}"
                    )
                record = json.loads(raw_line)
                status_counts[record["_meta"]["status"]] += 1
                destination.write(raw_line)
                expected_index += 1
                item = next_shard_item(handles[rank], rank)
                if item is not None:
                    heapq.heappush(heap, item)
            destination.flush()
            os.fsync(destination.fileno())
        if expected_index != expected_records:
            raise RuntimeError(
                f"병합 record 수 불일치: {expected_index} != {expected_records}"
            )
        os.replace(temporary, output)
    finally:
        for handle in handles:
            handle.close()
        if temporary.exists():
            temporary.unlink()

    summary = {
        "completed_at": utc_now(),
        "output_path": str(output.resolve()),
        "records": expected_records,
        "status_counts": dict(sorted(status_counts.items())),
        "run": run_manifest,
    }
    atomic_write_json(output.with_name(f"{output.name}.meta.json"), summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="학습된 Qwen LoRA로 NVD JSONL 전체를 multi-GPU 분산 파싱"
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2,
        help="GPU당 생성 batch 크기 (기본: 2, OOM이면 자동으로 분할)",
    )
    parser.add_argument(
        "--max-input-tokens",
        type=int,
        default=4096,
        help="system/user prompt 최대 token 수 (기본: 4096)",
    )
    parser.add_argument(
        "--max-new-tokens",
        type=int,
        default=512,
        help="bindings JSON 최대 생성 token 수 (기본: 512)",
    )
    parser.add_argument("--max-records", type=int)
    parser.add_argument("--log-every", type=int, default=100)
    parser.add_argument("--flush-every", type=int, default=25)
    parser.add_argument("--max-consecutive-errors", type=int, default=10)
    parser.add_argument(
        "--attn-implementation",
        choices=["eager", "sdpa", "flash_attention_2"],
        default="sdpa",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--skip-merge",
        action="store_true",
        help="rank shard만 생성하고 최종 JSONL 병합은 건너뜁니다.",
    )
    parser.add_argument("--no-4bit", dest="use_4bit", action="store_false")
    parser.set_defaults(use_4bit=True)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size는 1 이상이어야 합니다.")
    if args.max_input_tokens < 256:
        parser.error("--max-input-tokens는 256 이상이어야 합니다.")
    if args.max_new_tokens < 16:
        parser.error("--max-new-tokens는 16 이상이어야 합니다.")
    if args.max_records is not None and args.max_records < 1:
        parser.error("--max-records는 1 이상이어야 합니다.")
    if args.log_every < 1 or args.flush_every < 1:
        parser.error("--log-every와 --flush-every는 1 이상이어야 합니다.")
    if args.max_consecutive_errors < 1:
        parser.error("--max-consecutive-errors는 1 이상이어야 합니다.")
    return args


def main() -> int:
    args = parse_args()
    training_manifest = load_training_manifest(args.adapter)
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError("PyTorch가 설치된 학습 환경에서 실행하세요.") from exc
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU가 필요합니다.")

    rank = int(os.environ.get("RANK", "0"))
    local_rank = int(os.environ.get("LOCAL_RANK", "0"))
    world_size = int(os.environ.get("WORLD_SIZE", "1"))
    if local_rank >= torch.cuda.device_count():
        raise RuntimeError(
            f"LOCAL_RANK={local_rank}이지만 GPU는 {torch.cuda.device_count()}개입니다."
        )
    torch.cuda.set_device(local_rank)
    distributed = world_size > 1
    if distributed:
        torch.distributed.init_process_group(backend="nccl")
    warnings.filterwarnings(
        "ignore", category=FutureWarning, module=r"bitsandbytes(?:\..*)?"
    )

    try:
        prepare_output_state(
            args=args,
            rank=rank,
            world_size=world_size,
            training_manifest=training_manifest,
        )
        if distributed:
            torch.distributed.barrier(device_ids=[local_rank])
        parts_dir = parts_directory(args.output)
        run_manifest = json.loads(
            (parts_dir / RUN_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        source_records = int(run_manifest["source_record_count"])
        selected_records = int(run_manifest["selected_record_count"])
        current_shard = shard_path(parts_dir, rank, world_size)
        if not args.resume and current_shard.exists() and current_shard.stat().st_size:
            raise InferenceConfigurationError(
                f"새 실행인데 rank shard가 이미 존재합니다: {current_shard}"
            )
        _, recovered_count = recover_shard(current_shard, rank, world_size)
        counters = process_rank(
            args=args,
            rank=rank,
            world_size=world_size,
            local_rank=local_rank,
            source_records=source_records,
            training_manifest=training_manifest,
            shard=current_shard,
            recovered_count=recovered_count,
        )
        print(
            f"[rank {rank}] complete · new status={dict(counters)} · "
            f"shard={current_shard}",
            file=sys.stderr,
            flush=True,
        )
        if distributed:
            torch.distributed.barrier(device_ids=[local_rank])
        if rank == 0 and not args.skip_merge:
            started = time.perf_counter()
            summary = merge_shards(
                output=args.output,
                parts_dir=parts_dir,
                world_size=world_size,
                expected_records=selected_records,
                run_manifest=run_manifest,
            )
            print(
                f"[merge] {selected_records:,}건 완료 · "
                f"status={summary['status_counts']} · "
                f"{time.perf_counter() - started:.1f}s · output={args.output}",
                file=sys.stderr,
                flush=True,
            )
        if distributed:
            torch.distributed.barrier(device_ids=[local_rank])
    finally:
        if distributed and torch.distributed.is_initialized():
            torch.distributed.destroy_process_group()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
