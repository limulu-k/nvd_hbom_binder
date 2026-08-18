#!/usr/bin/env python3
"""Download the complete NVD CVE Change History dataset with safe resume.

The NVD API key is read from ``NVD_API_KEY`` by default.  Responses are first
stored as independently readable gzip-compressed page files.  Once every page
has been downloaded, the script atomically builds one compact JSONL gzip file
containing one ``cveChanges`` item per line.

Default layout::

    data/nvd-cve-history/
      manifest.json
      pages/page-000000000000.json.gz
      pages/page-000000005000.json.gz
      ...
      nvd-cve-history.jsonl.gz

Page files make interrupted downloads resumable without trusting a partially
appended gzip stream.  Re-running the same command fills missing/incomplete
pages and extends a previously complete download when ``totalResults`` grows.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import re
import socket
import sys
import tempfile
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0/"
DEFAULT_OUTPUT_DIR = Path("data/nvd-cve-history")
DEFAULT_PAGE_SIZE = 5_000
DEFAULT_REQUEST_DELAY = 6.0
DEFAULT_TIMEOUT = 180.0
DEFAULT_MAX_RETRIES = 12
DEFAULT_RETRY_BASE = 5.0
DEFAULT_RETRY_MAX = 300.0
DEFAULT_API_KEY_ENV = "NVD_API_KEY"
MANIFEST_SCHEMA_VERSION = 1
PAGE_PATTERN = re.compile(r"^page-(\d{12})\.json\.gz$")
JSON_SEPARATORS = (",", ":")
RETRYABLE_HTTP_STATUS = {403, 408, 425, 429, 500, 502, 503, 504}
USER_AGENT = "cve-binder-nvd-history-downloader/1.0"


class DownloadError(RuntimeError):
    """Raised when the download cannot safely continue."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def emit(event: str, **fields: Any) -> None:
    payload = {"event": event, "time": utc_now(), **fields}
    print(
        json.dumps(payload, ensure_ascii=False, sort_keys=True),
        file=sys.stderr,
        flush=True,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Download all NVD CVE Change History events with page-level resume, "
            "retry/backoff, gzip storage, and optional JSONL merge."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory. Default: {DEFAULT_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--api-key-env",
        default=DEFAULT_API_KEY_ENV,
        help=(
            "Environment variable containing the NVD API key. "
            f"Default: {DEFAULT_API_KEY_ENV}"
        ),
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"Events per request (1-5000). Default: {DEFAULT_PAGE_SIZE}",
    )
    parser.add_argument(
        "--request-delay",
        type=float,
        default=DEFAULT_REQUEST_DELAY,
        help=(
            "Minimum seconds between request starts. NVD recommends six seconds. "
            f"Default: {DEFAULT_REQUEST_DELAY}"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"Retries for transient failures. Default: {DEFAULT_MAX_RETRIES}",
    )
    parser.add_argument(
        "--retry-base",
        type=float,
        default=DEFAULT_RETRY_BASE,
        help=f"Initial exponential-backoff delay. Default: {DEFAULT_RETRY_BASE}",
    )
    parser.add_argument(
        "--retry-max",
        type=float,
        default=DEFAULT_RETRY_MAX,
        help=f"Maximum exponential-backoff delay. Default: {DEFAULT_RETRY_MAX}",
    )
    parser.add_argument(
        "--no-merge",
        action="store_true",
        help="Keep validated page files but do not build the final JSONL gzip.",
    )
    parser.add_argument(
        "--verify-existing",
        action="store_true",
        help="Decompress and validate every existing page before resuming.",
    )
    parser.add_argument(
        "--verify-unique",
        action="store_true",
        help=(
            "During merge, reject duplicate cveChangeId values. "
            "This can require several hundred MB of RAM."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Query totalResults and print the plan without downloading pages.",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        help="Download at most this many new pages in this run (smoke/resume test).",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)

    if not 1 <= args.page_size <= 5_000:
        parser.error("--page-size must be between 1 and 5000")
    if args.request_delay < 0:
        parser.error("--request-delay must be non-negative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_retries < 0:
        parser.error("--max-retries must be non-negative")
    if args.retry_base <= 0 or args.retry_max <= 0:
        parser.error("--retry-base and --retry-max must be positive")
    if args.retry_base > args.retry_max:
        parser.error("--retry-base cannot exceed --retry-max")
    if args.max_pages is not None and args.max_pages <= 0:
        parser.error("--max-pages must be positive")
    return args


def retry_after_seconds(headers: Mapping[str, str] | None) -> float | None:
    if headers is None:
        return None
    value = headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            target = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())


class NvdClient:
    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        request_delay: float,
        timeout: float,
        max_retries: int,
        retry_base: float,
        retry_max: float,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.request_delay = request_delay
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_base = retry_base
        self.retry_max = retry_max
        self.last_request_started: float | None = None

    def _pace(self) -> None:
        if self.last_request_started is None:
            return
        remaining = self.request_delay - (
            time.monotonic() - self.last_request_started
        )
        if remaining > 0:
            time.sleep(remaining)

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        exponential = min(
            self.retry_max,
            self.retry_base * (2 ** max(0, attempt - 1)),
        )
        delay = max(exponential, retry_after or 0.0)
        return min(self.retry_max, delay + random.uniform(0.0, 1.0))

    def get_json(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = urlencode({key: str(value) for key, value in params.items()})
        url = f"{self.endpoint}?{query}"
        context = {
            "start_index": params.get("startIndex"),
            "results_per_page": params.get("resultsPerPage"),
        }

        for attempt in range(self.max_retries + 1):
            self._pace()
            request = Request(
                url,
                headers={
                    "apiKey": self.api_key,
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip",
                    "User-Agent": USER_AGENT,
                },
                method="GET",
            )
            self.last_request_started = time.monotonic()
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read()
                    content_encoding = response.headers.get(
                        "Content-Encoding", ""
                    ).casefold()
                    if content_encoding == "gzip":
                        body = gzip.decompress(body)
                payload = json.loads(body.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise DownloadError("NVD response root is not an object")
                return payload
            except HTTPError as error:
                retryable = error.code in RETRYABLE_HTTP_STATUS
                detail = error.headers.get("message") if error.headers else None
                if not retryable or attempt >= self.max_retries:
                    raise DownloadError(
                        f"NVD HTTP {error.code}: {detail or error.reason}"
                    ) from error
                delay = self._backoff(
                    attempt + 1,
                    retry_after_seconds(error.headers),
                )
                emit(
                    "request_retry",
                    attempt=attempt + 1,
                    max_retries=self.max_retries,
                    reason=f"http_{error.code}",
                    delay_seconds=round(delay, 3),
                    **context,
                )
                time.sleep(delay)
            except (
                URLError,
                TimeoutError,
                socket.timeout,
                gzip.BadGzipFile,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as error:
                if attempt >= self.max_retries:
                    raise DownloadError(
                        f"NVD request failed after {attempt + 1} attempts: {error}"
                    ) from error
                delay = self._backoff(attempt + 1, None)
                emit(
                    "request_retry",
                    attempt=attempt + 1,
                    max_retries=self.max_retries,
                    reason=type(error).__name__,
                    delay_seconds=round(delay, 3),
                    **context,
                )
                time.sleep(delay)

        raise AssertionError("retry loop terminated unexpectedly")


def validate_page(
    payload: Mapping[str, Any],
    *,
    expected_start: int,
    requested_page_size: int,
) -> dict[str, Any]:
    try:
        start_index = int(payload["startIndex"])
        results_per_page = int(payload["resultsPerPage"])
        total_results = int(payload["totalResults"])
        changes = payload["cveChanges"]
    except (KeyError, TypeError, ValueError) as error:
        raise DownloadError(f"Malformed NVD page metadata: {error}") from error

    if start_index != expected_start:
        raise DownloadError(
            f"NVD returned startIndex={start_index}, expected {expected_start}"
        )
    if results_per_page < 1 or results_per_page > requested_page_size:
        raise DownloadError(
            "NVD returned invalid resultsPerPage="
            f"{results_per_page}; requested {requested_page_size}"
        )
    if total_results < 0:
        raise DownloadError(f"NVD returned invalid totalResults={total_results}")
    if not isinstance(changes, list):
        raise DownloadError("NVD cveChanges is not an array")
    if len(changes) > requested_page_size:
        raise DownloadError(
            f"NVD returned {len(changes)} events; page size is {requested_page_size}"
        )
    for offset, item in enumerate(changes):
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            raise DownloadError(
                f"Malformed cveChanges item at page offset {offset}"
            )

    return {
        "start_index": start_index,
        "results_per_page": results_per_page,
        "total_results": total_results,
        "event_count": len(changes),
    }


def page_path(pages_dir: Path, start_index: int) -> Path:
    return pages_dir / f"page-{start_index:012d}.json.gz"


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=JSON_SEPARATORS,
    ).encode("utf-8")


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
            )
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def atomic_write_gzip_json(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = compact_json_bytes(payload)
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw_handle:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=6,
                fileobj=raw_handle,
                mtime=0,
            ) as compressed:
                compressed.write(raw)
            raw_handle.flush()
            os.fsync(raw_handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return {
        "compressed_bytes": path.stat().st_size,
        "raw_bytes": len(raw),
        "raw_sha256": raw_sha256,
    }


def read_gzip_json(path: Path) -> dict[str, Any]:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DownloadError(f"Cannot read existing page {path}: {error}") from error
    if not isinstance(payload, dict):
        raise DownloadError(f"Existing page root is not an object: {path}")
    return payload


def new_manifest(endpoint: str, page_size: int) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "endpoint": endpoint,
        "page_size": page_size,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "total_results": 0,
        "complete": False,
        "pages": {},
        "merged_output": None,
    }


def load_manifest(
    path: Path,
    *,
    endpoint: str,
    page_size: int,
) -> dict[str, Any]:
    if not path.exists():
        return new_manifest(endpoint, page_size)
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DownloadError(f"Cannot read manifest {path}: {error}") from error
    if not isinstance(manifest, dict):
        raise DownloadError(f"Manifest root is not an object: {path}")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise DownloadError(
            f"Unsupported manifest schema: {manifest.get('schema_version')!r}"
        )
    if manifest.get("endpoint") != endpoint:
        raise DownloadError(
            "Existing manifest endpoint differs; use another --output-dir"
        )
    if manifest.get("page_size") != page_size:
        raise DownloadError(
            "Existing manifest page size differs; reuse its --page-size "
            "or choose another --output-dir"
        )
    if not isinstance(manifest.get("pages"), dict):
        raise DownloadError("Manifest pages field is not an object")
    return manifest


def page_metadata(
    *,
    relative_path: str,
    validation: Mapping[str, Any],
    storage: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "path": relative_path,
        "event_count": int(validation["event_count"]),
        "total_results_observed": int(validation["total_results"]),
        "results_per_page": int(validation["results_per_page"]),
        "compressed_bytes": int(storage["compressed_bytes"]),
        "raw_bytes": int(storage["raw_bytes"]),
        "raw_sha256": str(storage["raw_sha256"]),
        "downloaded_at": utc_now(),
    }


def inspect_existing_pages(
    *,
    output_dir: Path,
    pages_dir: Path,
    manifest: dict[str, Any],
    page_size: int,
    verify_existing: bool,
) -> None:
    page_records = manifest["pages"]
    for key in list(page_records):
        record = page_records[key]
        if not isinstance(record, dict):
            del page_records[key]
            continue
        relative = record.get("path")
        if not isinstance(relative, str) or not (output_dir / relative).is_file():
            del page_records[key]

    for path in sorted(pages_dir.glob("page-*.json.gz")):
        match = PAGE_PATTERN.match(path.name)
        if match is None:
            continue
        start_index = int(match.group(1))
        key = str(start_index)
        if key in page_records and not verify_existing:
            continue
        payload = read_gzip_json(path)
        validation = validate_page(
            payload,
            expected_start=start_index,
            requested_page_size=page_size,
        )
        raw = compact_json_bytes(payload)
        storage = {
            "compressed_bytes": path.stat().st_size,
            "raw_bytes": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }
        page_records[key] = page_metadata(
            relative_path=str(path.relative_to(output_dir)),
            validation=validation,
            storage=storage,
        )


def probe_total(client: NvdClient) -> int:
    payload = client.get_json({"resultsPerPage": 1, "startIndex": 0})
    validation = validate_page(
        payload,
        expected_start=0,
        requested_page_size=1,
    )
    return int(validation["total_results"])


def expected_page_count(start_index: int, total: int, page_size: int) -> int:
    return max(0, min(page_size, total - start_index))


def pending_page_starts(
    manifest: Mapping[str, Any],
    *,
    total: int,
    page_size: int,
) -> list[int]:
    pages = manifest["pages"]
    pending: list[int] = []
    for start_index in range(0, total, page_size):
        record = pages.get(str(start_index))
        expected = expected_page_count(start_index, total, page_size)
        if not isinstance(record, dict) or record.get("event_count") != expected:
            pending.append(start_index)
    return pending


def save_manifest(path: Path, manifest: dict[str, Any]) -> None:
    manifest["updated_at"] = utc_now()
    atomic_write_json(path, manifest)


def download_page(
    *,
    client: NvdClient,
    output_dir: Path,
    pages_dir: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    start_index: int,
    page_size: int,
) -> int:
    started = time.monotonic()
    payload = client.get_json(
        {
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
    )
    validation = validate_page(
        payload,
        expected_start=start_index,
        requested_page_size=page_size,
    )
    path = page_path(pages_dir, start_index)
    storage = atomic_write_gzip_json(path, payload)
    manifest["pages"][str(start_index)] = page_metadata(
        relative_path=str(path.relative_to(output_dir)),
        validation=validation,
        storage=storage,
    )
    manifest["total_results"] = int(validation["total_results"])
    manifest["complete"] = False
    manifest["merged_output"] = None
    save_manifest(manifest_path, manifest)
    emit(
        "page_saved",
        start_index=start_index,
        event_count=validation["event_count"],
        total_results=validation["total_results"],
        compressed_bytes=storage["compressed_bytes"],
        elapsed_seconds=round(time.monotonic() - started, 3),
    )
    return int(validation["total_results"])


def merge_pages(
    *,
    output_dir: Path,
    pages_dir: Path,
    destination: Path,
    total: int,
    page_size: int,
    verify_unique: bool,
) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    stream_sha256 = hashlib.sha256()
    event_count = 0
    seen_ids: set[str] | None = set() if verify_unique else None
    started = time.monotonic()

    try:
        with os.fdopen(descriptor, "wb") as raw_handle:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=6,
                fileobj=raw_handle,
                mtime=0,
            ) as compressed:
                for start_index in range(0, total, page_size):
                    path = page_path(pages_dir, start_index)
                    payload = read_gzip_json(path)
                    validation = validate_page(
                        payload,
                        expected_start=start_index,
                        requested_page_size=page_size,
                    )
                    expected = expected_page_count(
                        start_index,
                        total,
                        page_size,
                    )
                    if validation["event_count"] != expected:
                        raise DownloadError(
                            f"Page {start_index} has "
                            f"{validation['event_count']} events; expected {expected}"
                        )
                    for item in payload["cveChanges"]:
                        if seen_ids is not None:
                            change_id = item["change"].get("cveChangeId")
                            if not isinstance(change_id, str) or not change_id:
                                raise DownloadError(
                                    "Missing cveChangeId while checking uniqueness"
                                )
                            if change_id in seen_ids:
                                raise DownloadError(
                                    f"Duplicate cveChangeId detected: {change_id}"
                                )
                            seen_ids.add(change_id)
                        line = compact_json_bytes(item) + b"\n"
                        compressed.write(line)
                        stream_sha256.update(line)
                        event_count += 1
            raw_handle.flush()
            os.fsync(raw_handle.fileno())

        if event_count != total:
            raise DownloadError(
                f"Merged event count is {event_count}; expected {total}"
            )
        os.replace(temporary_path, destination)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise

    result = {
        "path": str(destination.relative_to(output_dir)),
        "event_count": event_count,
        "compressed_bytes": destination.stat().st_size,
        "jsonl_sha256": stream_sha256.hexdigest(),
        "created_at": utc_now(),
        "verify_unique": verify_unique,
    }
    emit(
        "merge_complete",
        **result,
        elapsed_seconds=round(time.monotonic() - started, 3),
    )
    return result


def download(args: argparse.Namespace) -> dict[str, Any]:
    api_key = os.environ.get(args.api_key_env, "").strip()
    if not api_key:
        raise DownloadError(
            f"Set the NVD API key in environment variable {args.api_key_env!r}"
        )

    output_dir: Path = args.output_dir
    pages_dir = output_dir / "pages"
    manifest_path = output_dir / "manifest.json"
    merged_path = output_dir / "nvd-cve-history.jsonl.gz"
    pages_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest(
        manifest_path,
        endpoint=args.endpoint,
        page_size=args.page_size,
    )
    inspect_existing_pages(
        output_dir=output_dir,
        pages_dir=pages_dir,
        manifest=manifest,
        page_size=args.page_size,
        verify_existing=args.verify_existing,
    )
    save_manifest(manifest_path, manifest)

    client = NvdClient(
        endpoint=args.endpoint,
        api_key=api_key,
        request_delay=args.request_delay,
        timeout=args.timeout,
        max_retries=args.max_retries,
        retry_base=args.retry_base,
        retry_max=args.retry_max,
    )

    total = probe_total(client)
    request_count = (total + args.page_size - 1) // args.page_size
    emit(
        "download_plan",
        total_results=total,
        page_size=args.page_size,
        request_count=request_count,
        existing_pages=len(manifest["pages"]),
        output_dir=str(output_dir),
    )
    manifest["total_results"] = total
    save_manifest(manifest_path, manifest)

    if args.dry_run:
        return {
            "status": "dry_run",
            "total_results": total,
            "page_size": args.page_size,
            "request_count": request_count,
            "output_dir": str(output_dir),
        }

    pages_downloaded = 0
    while True:
        pending = pending_page_starts(
            manifest,
            total=total,
            page_size=args.page_size,
        )
        if pending:
            for start_index in pending:
                if (
                    args.max_pages is not None
                    and pages_downloaded >= args.max_pages
                ):
                    manifest["total_results"] = total
                    manifest["complete"] = False
                    save_manifest(manifest_path, manifest)
                    return {
                        "status": "partial",
                        "total_results": total,
                        "pages_downloaded_this_run": pages_downloaded,
                        "remaining_pages": len(
                            pending_page_starts(
                                manifest,
                                total=total,
                                page_size=args.page_size,
                            )
                        ),
                        "manifest": str(manifest_path),
                    }
                observed_total = download_page(
                    client=client,
                    output_dir=output_dir,
                    pages_dir=pages_dir,
                    manifest_path=manifest_path,
                    manifest=manifest,
                    start_index=start_index,
                    page_size=args.page_size,
                )
                pages_downloaded += 1
                total = max(total, observed_total)
            continue

        refreshed_total = probe_total(client)
        if refreshed_total != total:
            emit(
                "total_results_changed",
                previous_total=total,
                current_total=refreshed_total,
            )
            total = refreshed_total
            manifest["total_results"] = total
            save_manifest(manifest_path, manifest)
            continue
        break

    manifest["total_results"] = total
    manifest["complete"] = True
    if args.no_merge:
        manifest["merged_output"] = None
    else:
        manifest["merged_output"] = merge_pages(
            output_dir=output_dir,
            pages_dir=pages_dir,
            destination=merged_path,
            total=total,
            page_size=args.page_size,
            verify_unique=args.verify_unique,
        )
    save_manifest(manifest_path, manifest)

    return {
        "status": "complete",
        "total_results": total,
        "page_size": args.page_size,
        "page_count": (total + args.page_size - 1) // args.page_size,
        "pages_downloaded_this_run": pages_downloaded,
        "manifest": str(manifest_path),
        "merged_output": manifest["merged_output"],
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = download(args)
    except (DownloadError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted; completed pages are safe and resumable", file=sys.stderr)
        return 130
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
