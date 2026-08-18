#!/usr/bin/env python3
"""Collect CVE/commit evidence from the normalized DB, OSV, and git caches.

The command writes a sorted JSONL and CSV pair for each input source:

* ``reference_commit_records``: commit URLs found below NVD references of CVEs
  admitted to the normalized database.
* ``osv_exact_version_repo_records``: OSV affected entries that contain a CVE
  identifier, an explicit ``versions`` list, and a GIT range repository.
* ``git_cache_cve_commits``: cached GitHub API commits or local git commits
  whose commit message mentions a CVE identifier.

Example::

    python3 utils/collect_cve_commit_evidence.py --db workspace/nvd_applicability_v10.sqlite
      --osv-dir data/osv --git-cache workspace/github_cache
      --output-dir workspace/cve_commit_evidence

``--git-cache`` may be repeated.  A cache root can contain GitHub API JSON
files, normal worktrees, or bare repositories.  Inputs are read-only and output
files are replaced atomically after a successful collection.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import parse_qs, unquote, urlparse


CVE_RE = re.compile(r"(?<![A-Z0-9])CVE-(\d{4})-(\d{4,})(?![A-Z0-9])", re.I)
HEX_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$", re.I)
PATH_COMMIT_RE = re.compile(
    r"/(?:-|projects/[^/]+/repository)?/?(?:commit|commits|changeset|revision)/"
    r"([0-9a-f]{7,64})(?:$|[/?#])",
    re.I,
)
GOOGLESOURCE_COMMIT_RE = re.compile(r"/\+/([0-9a-f]{7,64})(?:$|[/?#])", re.I)
SUPPORTED_JSON_SUFFIXES = (".json", ".jsonl", ".ndjson", ".json.gz", ".jsonl.gz", ".ndjson.gz")

REFERENCE_FIELDS = (
    "cve_id",
    "reference_url",
    "repository",
    "provider",
    "commit_id",
    "reference_source",
    "reference_tags",
    "db_source_path",
    "db_line_number",
)
OSV_FIELDS = (
    "cve_id",
    "osv_id",
    "package_ecosystem",
    "package_name",
    "package_purl",
    "repository",
    "repository_url",
    "exact_versions",
    "git_events",
    "osv_path",
    "affected_index",
    "range_index",
)
GIT_FIELDS = (
    "cve_id",
    "repo_key",
    "commit_sha",
    "commit_date",
    "commit_url",
    "subject",
    "message",
    "cache_sources",
)


class CollectionError(RuntimeError):
    """Raised when a required input cannot be safely interpreted."""


def cve_ids(value: Any) -> list[str]:
    """Return unique, normalized CVE identifiers occurring in *value*."""

    if not isinstance(value, str):
        return []
    found = {match.group(0).upper() for match in CVE_RE.finditer(value)}
    return sorted(found, key=cve_sort_key)


def cve_sort_key(value: str) -> tuple[int, int, str]:
    match = CVE_RE.fullmatch(value.strip())
    if not match:
        return (sys.maxsize, sys.maxsize, value.casefold())
    return (int(match.group(1)), int(match.group(2)), value.upper())


def record_sort_key(record: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        cve_sort_key(str(record.get("cve_id", ""))),
        str(record.get("repository") or record.get("repo_key") or "").casefold(),
        str(record.get("commit_id") or record.get("commit_sha") or "").casefold(),
        str(record.get("reference_url") or record.get("osv_id") or "").casefold(),
    )


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?", (name,)
    ).fetchone() is not None


def connect_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise CollectionError(f"DB 파일을 찾을 수 없습니다: {path}")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def record_cve_id(record: Mapping[str, Any]) -> str | None:
    cve = record.get("cve")
    if isinstance(cve, Mapping) and isinstance(cve.get("id"), str):
        ids = cve_ids(cve["id"])
        if ids:
            return ids[0]
    metadata = record.get("cveMetadata")
    if isinstance(metadata, Mapping) and isinstance(metadata.get("cveId"), str):
        ids = cve_ids(metadata["cveId"])
        if ids:
            return ids[0]
    for key in ("cve_id", "cveId", "id"):
        ids = cve_ids(record.get(key))
        if ids:
            return ids[0]
    return None


def iter_reference_items(value: Any) -> Iterator[Any]:
    """Yield individual values located below keys named ``references``."""

    def descend_reference(node: Any) -> Iterator[Any]:
        if isinstance(node, list):
            for item in node:
                yield item
        else:
            yield node

    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() == "references":
                yield from descend_reference(child)
            elif isinstance(child, (Mapping, list)):
                yield from iter_reference_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_reference_items(child)


def urls_in_reference(item: Any) -> Iterator[tuple[str, Mapping[str, Any] | None]]:
    if isinstance(item, str):
        if "://" in item:
            yield item, None
        return
    if isinstance(item, Mapping):
        yielded = False
        for key in ("url", "href"):
            value = item.get(key)
            if isinstance(value, str) and "://" in value:
                yielded = True
                yield value, item
        if not yielded:
            for child in item.values():
                if isinstance(child, (Mapping, list)):
                    yield from urls_in_reference(child)
    elif isinstance(item, list):
        for child in item:
            yield from urls_in_reference(child)


def commit_id_from_url(url: str) -> str | None:
    """Recognize common GitHub/GitLab/cgit/gitweb commit URL forms."""

    match = PATH_COMMIT_RE.search(url) or GOOGLESOURCE_COMMIT_RE.search(url)
    if match:
        return match.group(1).lower()
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    path = parsed.path.casefold()
    query = parse_qs(parsed.query.replace(";", "&"))
    looks_like_commit = any(token in path for token in ("commit", "changeset", "revision"))
    action = next(iter(query.get("a", [])), "").casefold()
    looks_like_commit = looks_like_commit or action in {"commit", "commitdiff", "commitdiff_plain"}
    if not looks_like_commit:
        return None
    for key in ("id", "h", "commit", "sha", "rev", "revision"):
        for candidate in query.get(key, []):
            candidate = candidate.strip()
            if HEX_COMMIT_RE.fullmatch(candidate):
                return candidate.lower()
    # Listing URLs such as /commits/main are not concrete commit evidence.
    return None


def repository_from_url(url: str) -> tuple[str, str]:
    """Return a display repository key and provider host for a commit URL."""

    try:
        parsed = urlparse(url)
    except ValueError:
        return "", ""
    host = parsed.netloc.casefold().split(":", 1)[0]
    segments = [unquote(part) for part in parsed.path.split("/") if part]
    if host == "api.github.com" and len(segments) >= 3 and segments[0].casefold() == "repos":
        return f"{segments[1]}@{segments[2].removesuffix('.git')}", host
    if host in {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com"} and len(segments) >= 2:
        if host.endswith("gitlab.com") and "-" in segments:
            marker = segments.index("-")
            repo_parts = segments[:marker]
            if len(repo_parts) >= 2:
                return f"{'/'.join(repo_parts[:-1])}@{repo_parts[-1].removesuffix('.git')}", host
        return f"{segments[0]}@{segments[1].removesuffix('.git')}", host
    return host, host


def normalize_tags(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return sorted({str(item) for item in value if item is not None})
    return []


def reference_record(
    cve_id: str,
    url: str,
    metadata: Mapping[str, Any] | None,
    source_path: str,
    line_number: int | None,
) -> dict[str, Any] | None:
    commit_id = commit_id_from_url(url)
    if commit_id is None:
        return None
    repository, provider = repository_from_url(url)
    source = ""
    tags: list[str] = []
    if metadata:
        for key in ("source", "name"):
            if isinstance(metadata.get(key), str):
                source = str(metadata[key])
                break
        tags = normalize_tags(metadata.get("tags"))
    return {
        "cve_id": cve_id,
        "reference_url": url,
        "repository": repository,
        "provider": provider,
        "commit_id": commit_id,
        "reference_source": source,
        "reference_tags": tags,
        "db_source_path": source_path,
        "db_line_number": line_number,
    }


def collect_reference_commits(
    db_path: Path,
    nvd_jsonl_override: Path | None,
    progress_every: int,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    """Collect reference commit URLs while using the DB as the CVE authority."""

    records: dict[tuple[str, str], dict[str, Any]] = {}
    stats: Counter[str] = Counter()
    with connect_read_only(db_path) as connection:
        if table_exists(connection, "raw_cve") and table_exists(connection, "source_snapshot_manifest"):
            query = """
                SELECT r.cve_id,r.line_number,r.byte_offset,r.byte_length,s.source_path
                FROM raw_cve r JOIN source_snapshot_manifest s USING(snapshot_id)
                ORDER BY s.source_path,r.byte_offset
            """
            current_path = ""
            handle = None
            try:
                for row in connection.execute(query):
                    stats["db_cves_seen"] += 1
                    source_path = str(nvd_jsonl_override or row["source_path"])
                    if source_path != current_path:
                        if handle is not None:
                            handle.close()
                        path = Path(source_path)
                        if not path.is_file():
                            raise CollectionError(
                                f"DB snapshot 원문이 없습니다: {path} (--nvd-jsonl로 지정 가능)"
                            )
                        handle = path.open("rb")
                        current_path = source_path
                    assert handle is not None
                    handle.seek(int(row["byte_offset"]))
                    raw = handle.read(int(row["byte_length"]))
                    lowered = raw.lower()
                    if not any(token in lowered for token in (b"commit", b"changeset", b"revision", b"/+")):
                        continue
                    stats["reference_candidate_cves"] += 1
                    try:
                        record = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        stats["reference_json_errors"] += 1
                        continue
                    if not isinstance(record, Mapping):
                        continue
                    cve_id = str(row["cve_id"]).upper()
                    raw_cve = record_cve_id(record)
                    if raw_cve and raw_cve != cve_id:
                        stats["reference_cve_mismatches"] += 1
                        continue
                    for item in iter_reference_items(record):
                        for url, metadata in urls_in_reference(item):
                            result = reference_record(
                                cve_id, url, metadata, source_path, int(row["line_number"])
                            )
                            if result is not None:
                                records[(cve_id, url)] = result
                    if progress_every and stats["db_cves_seen"] % progress_every == 0:
                        print(
                            f"[reference] DB CVE {stats['db_cves_seen']:,}개 검사",
                            file=sys.stderr,
                        )
            finally:
                if handle is not None:
                    handle.close()
        elif table_exists(connection, "cve_github_refs"):
            columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(cve_github_refs)")
            }
            required = {"cve_id", "github_url"}
            if not required.issubset(columns):
                raise CollectionError("cve_github_refs에 cve_id/github_url 컬럼이 없습니다")
            where = "WHERE ref_kind='commit'" if "ref_kind" in columns else ""
            for row in connection.execute(
                f"SELECT cve_id,github_url FROM cve_github_refs {where} ORDER BY cve_id"  # noqa: S608
            ):
                cve_id = str(row["cve_id"]).upper()
                url = str(row["github_url"])
                result = reference_record(cve_id, url, None, str(db_path), None)
                if result is not None:
                    records[(cve_id, url)] = result
                stats["db_reference_rows_seen"] += 1
        else:
            raise CollectionError(
                "지원 DB 스키마가 아닙니다: raw_cve/source_snapshot_manifest 또는 "
                "cve_github_refs가 필요합니다"
            )
    result = sorted(records.values(), key=record_sort_key)
    stats["reference_commit_records"] = len(result)
    stats["reference_commit_cves"] = len({row["cve_id"] for row in result})
    return result, stats


def open_text(path: Path):
    if path.name.casefold().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("rt", encoding="utf-8")


def iter_json_records(path: Path) -> Iterator[Any]:
    """Read a JSON object/array or line-delimited JSON without format guessing by name."""

    with open_text(path) as handle:
        first = ""
        while True:
            char = handle.read(1)
            if not char:
                return
            if not char.isspace():
                first = char
                break
        handle.seek(0)
        if first == "[":
            value = json.load(handle)
            if isinstance(value, list):
                yield from value
            else:
                yield value
            return
        if first == "{":
            try:
                value = json.load(handle)
            except json.JSONDecodeError:
                handle.seek(0)
            else:
                yield value
                return
        for line in handle:
            if line.strip():
                yield json.loads(line)


def iter_supported_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        if root.name.casefold().endswith(SUPPORTED_JSON_SUFFIXES):
            yield root
        return
    for directory, names, files in os.walk(root):
        names.sort()
        files.sort()
        for name in files:
            if name.casefold().endswith(SUPPORTED_JSON_SUFFIXES):
                yield Path(directory) / name


def github_repo_key(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    host = parsed.netloc.casefold().split(":", 1)[0]
    parts = [unquote(part) for part in parsed.path.split("/") if part]
    if host == "api.github.com" and len(parts) >= 3 and parts[0].casefold() == "repos":
        return f"{parts[1]}@{parts[2].removesuffix('.git')}"
    if host in {"github.com", "www.github.com"} and len(parts) >= 2:
        return f"{parts[0]}@{parts[1].removesuffix('.git')}"
    return ""


def osv_cves(record: Mapping[str, Any]) -> list[str]:
    identifiers: set[str] = set(cve_ids(record.get("id")))
    aliases = record.get("aliases")
    if isinstance(aliases, Sequence) and not isinstance(aliases, (str, bytes)):
        for alias in aliases:
            identifiers.update(cve_ids(alias))
    return sorted(identifiers, key=cve_sort_key)


def collect_osv_records(
    osv_roots: Sequence[Path], progress_every: int, fail_on_error: bool
) -> tuple[list[dict[str, Any]], Counter[str], list[str]]:
    records: dict[tuple[str, str, int, int, str], dict[str, Any]] = {}
    stats: Counter[str] = Counter()
    errors: list[str] = []
    for root in osv_roots:
        if not root.exists():
            raise CollectionError(f"OSV 경로를 찾을 수 없습니다: {root}")
        for path in iter_supported_files(root):
            stats["osv_files_seen"] += 1
            try:
                source_records = iter_json_records(path)
                for value in source_records:
                    stats["osv_records_seen"] += 1
                    if not isinstance(value, Mapping):
                        continue
                    identifiers = osv_cves(value)
                    if not identifiers:
                        continue
                    affected_values = value.get("affected")
                    if not isinstance(affected_values, list):
                        continue
                    for affected_index, affected in enumerate(affected_values):
                        if not isinstance(affected, Mapping):
                            continue
                        versions = sorted(
                            {
                                version
                                for version in affected.get("versions", [])
                                if isinstance(version, str) and version.strip()
                            }
                        )
                        if not versions:
                            continue
                        package = affected.get("package")
                        package = package if isinstance(package, Mapping) else {}
                        ranges = affected.get("ranges")
                        if not isinstance(ranges, list):
                            continue
                        for range_index, range_value in enumerate(ranges):
                            if not isinstance(range_value, Mapping):
                                continue
                            if str(range_value.get("type", "")).upper() != "GIT":
                                continue
                            repository_url = range_value.get("repo")
                            if not isinstance(repository_url, str) or not repository_url.strip():
                                continue
                            events = [
                                event
                                for event in range_value.get("events", [])
                                if isinstance(event, Mapping)
                            ]
                            repository = github_repo_key(repository_url) or repository_url
                            for cve_id in identifiers:
                                result = {
                                    "cve_id": cve_id,
                                    "osv_id": str(value.get("id", "")),
                                    "package_ecosystem": str(package.get("ecosystem", "")),
                                    "package_name": str(package.get("name", "")),
                                    "package_purl": str(package.get("purl", "")),
                                    "repository": repository,
                                    "repository_url": repository_url,
                                    "exact_versions": versions,
                                    "git_events": events,
                                    "osv_path": str(path),
                                    "affected_index": affected_index,
                                    "range_index": range_index,
                                }
                                key = (cve_id, str(value.get("id", "")), affected_index, range_index, repository_url)
                                records[key] = result
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                stats["osv_errors"] += 1
                message = f"{path}: {exc}"
                if len(errors) < 100:
                    errors.append(message)
                if fail_on_error:
                    raise CollectionError(message) from exc
            if progress_every and stats["osv_files_seen"] % progress_every == 0:
                print(f"[osv] 파일 {stats['osv_files_seen']:,}개 검사", file=sys.stderr)
    result = sorted(records.values(), key=record_sort_key)
    stats["osv_exact_version_repo_records"] = len(result)
    stats["osv_exact_version_repo_cves"] = len({row["cve_id"] for row in result})
    return result, stats, errors


def infer_repo_from_cache_path(path: Path) -> str:
    match = re.search(r"([A-Za-z0-9_.-]+)__([A-Za-z0-9_.-]+)__(?:commits?|commit)__", path.name, re.I)
    if match:
        return f"{match.group(1)}@{match.group(2)}"
    match = re.search(r"([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)", str(path))
    if match:
        return f"{match.group(1)}@{match.group(2)}"
    return ""


def infer_repo_from_object(value: Mapping[str, Any]) -> str:
    for key in ("repo_key", "git_key", "full_name"):
        item = value.get(key)
        if isinstance(item, str):
            if "@" in item:
                return item
            if "/" in item and "://" not in item:
                owner, repo = item.split("/", 1)
                return f"{owner}@{repo}"
    repository = value.get("repository")
    if isinstance(repository, Mapping):
        result = infer_repo_from_object(repository)
        if result:
            return result
    for key in ("html_url", "url"):
        item = value.get(key)
        if isinstance(item, str):
            result = github_repo_key(item)
            if result:
                return result
    return ""


def iter_commit_objects(value: Any, inherited_repo: str = "") -> Iterator[tuple[Mapping[str, Any], str]]:
    if isinstance(value, list):
        for item in value:
            yield from iter_commit_objects(item, inherited_repo)
        return
    if not isinstance(value, Mapping):
        return
    repo = infer_repo_from_object(value) or inherited_repo
    commit = value.get("commit")
    sha = value.get("sha")
    if isinstance(sha, str) and isinstance(commit, Mapping) and isinstance(commit.get("message"), str):
        yield value, repo
        return
    for key in ("data", "items", "result", "response", "commits"):
        child = value.get(key)
        if isinstance(child, (list, Mapping)):
            yield from iter_commit_objects(child, repo)


def commit_date(item: Mapping[str, Any]) -> str:
    commit = item.get("commit")
    if not isinstance(commit, Mapping):
        return ""
    for who in ("committer", "author"):
        person = commit.get(who)
        if isinstance(person, Mapping) and isinstance(person.get("date"), str):
            return str(person["date"])
    return ""


def add_git_commit_record(
    target: dict[tuple[str, str, str], dict[str, Any]],
    repo_key: str,
    sha: str,
    date: str,
    message: str,
    commit_url: str,
    source: str,
) -> None:
    for cve_id in cve_ids(message):
        key = (cve_id, repo_key.casefold(), sha.casefold())
        existing = target.get(key)
        if existing is None:
            target[key] = {
                "cve_id": cve_id,
                "repo_key": repo_key,
                "commit_sha": sha,
                "commit_date": date,
                "commit_url": commit_url,
                "subject": message.splitlines()[0] if message.splitlines() else "",
                "message": message,
                "cache_sources": [source],
            }
        elif source not in existing["cache_sources"]:
            existing["cache_sources"].append(source)
            existing["cache_sources"].sort()


def is_probable_commit_cache_file(path: Path) -> bool:
    name = path.name.casefold()
    if not name.endswith(SUPPORTED_JSON_SUFFIXES):
        return False
    cache_kind_in_name = re.search(r"__(?:commit|commits)__", name) is not None
    standalone_name = re.match(r"commits?(?:[_.-]|$)", name) is not None
    parent_is_commit_cache = path.parent.name.casefold() in {"commit", "commits"}
    return cache_kind_in_name or standalone_name or parent_is_commit_cache


def collect_api_cache(
    root: Path,
    target: dict[tuple[str, str, str], dict[str, Any]],
    stats: Counter[str],
    errors: list[str],
    fail_on_error: bool,
) -> None:
    for path in iter_supported_files(root):
        if not is_probable_commit_cache_file(path):
            continue
        stats["git_api_files_seen"] += 1
        path_repo = infer_repo_from_cache_path(path)
        try:
            for value in iter_json_records(path):
                for item, object_repo in iter_commit_objects(value, path_repo):
                    stats["git_api_commits_seen"] += 1
                    commit = item["commit"]
                    assert isinstance(commit, Mapping)
                    message = str(commit["message"])
                    if not cve_ids(message):
                        continue
                    repo = object_repo or path_repo
                    sha = str(item.get("sha", ""))
                    url = str(item.get("html_url") or item.get("url") or "")
                    add_git_commit_record(
                        target, repo, sha, commit_date(item), message, url, str(path)
                    )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            stats["git_api_errors"] += 1
            message = f"{path}: {exc}"
            if len(errors) < 100:
                errors.append(message)
            if fail_on_error:
                raise CollectionError(message) from exc


def iter_git_repositories(root: Path) -> Iterator[tuple[Path, bool]]:
    """Yield ``(path, is_bare)`` without descending into repository internals."""

    if root.is_file():
        return
    for directory, names, files in os.walk(root):
        path = Path(directory)
        if ".git" in names:
            names.remove(".git")
            yield path, False
            names[:] = []
            continue
        if "HEAD" in files and "objects" in names and ("refs" in names or "packed-refs" in files):
            yield path, True
            names[:] = []


def git_remote_repo(path: Path, bare: bool) -> str:
    command = ["git"]
    command.extend(["--git-dir", str(path)] if bare else ["-C", str(path)])
    command.extend(["config", "--get", "remote.origin.url"])
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    remote = result.stdout.decode("utf-8", "replace").strip()
    if remote.startswith("git@github.com:"):
        remote = "https://github.com/" + remote.split(":", 1)[1]
    repo = github_repo_key(remote)
    return repo or path.name


def collect_local_git_repo(
    path: Path,
    bare: bool,
    target: dict[tuple[str, str, str], dict[str, Any]],
    stats: Counter[str],
    errors: list[str],
    fail_on_error: bool,
) -> None:
    repo_key = git_remote_repo(path, bare)
    command = ["git"]
    command.extend(["--git-dir", str(path)] if bare else ["-C", str(path)])
    command.extend(
        [
            "log",
            "--all",
            "--extended-regexp",
            "--regexp-ignore-case",
            "--grep=CVE-[0-9]{4}-[0-9]{4,}",
            "--format=%H%x1f%cI%x1f%B%x1e",
        ]
    )
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    stats["git_repositories_seen"] += 1
    if result.returncode != 0:
        stats["git_repository_errors"] += 1
        message = f"{path}: {result.stderr.decode('utf-8', 'replace').strip()}"
        if len(errors) < 100:
            errors.append(message)
        if fail_on_error:
            raise CollectionError(message)
        return
    text = result.stdout.decode("utf-8", "replace")
    for raw_record in text.split("\x1e"):
        raw_record = raw_record.strip("\r\n")
        if not raw_record:
            continue
        parts = raw_record.split("\x1f", 2)
        if len(parts) != 3:
            stats["git_log_parse_errors"] += 1
            continue
        sha, date, message = parts
        stats["git_local_matching_commits_seen"] += 1
        add_git_commit_record(target, repo_key, sha, date, message, "", str(path))


def collect_git_cache_records(
    roots: Sequence[Path], fail_on_error: bool
) -> tuple[list[dict[str, Any]], Counter[str], list[str]]:
    records: dict[tuple[str, str, str], dict[str, Any]] = {}
    stats: Counter[str] = Counter()
    errors: list[str] = []
    for root in roots:
        if not root.exists():
            raise CollectionError(f"git cache 경로를 찾을 수 없습니다: {root}")
        collect_api_cache(root, records, stats, errors, fail_on_error)
        for repo, bare in iter_git_repositories(root):
            collect_local_git_repo(repo, bare, records, stats, errors, fail_on_error)
    result = sorted(records.values(), key=record_sort_key)
    stats["git_cache_cve_commit_records"] = len(result)
    stats["git_cache_cves"] = len({row["cve_id"] for row in result})
    return result, stats, errors


def csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json_text(value)
    if value is None:
        return ""
    return value


def atomic_write_outputs(
    output_dir: Path,
    basename: str,
    records: Sequence[Mapping[str, Any]],
    fields: Sequence[str],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for suffix in ("jsonl", "csv"):
        target = output_dir / f"{basename}.{suffix}"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{basename}.", suffix=f".{suffix}.tmp", dir=output_dir
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                if suffix == "jsonl":
                    for record in records:
                        handle.write(json_text(record) + "\n")
                else:
                    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                    writer.writeheader()
                    for record in records:
                        writer.writerow({field: csv_value(record.get(field)) for field in fields})
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, target)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise


def write_summary(output_dir: Path, summary: Mapping[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "summary.json"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".summary.", suffix=".tmp", dir=output_dir)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def default_git_cache_roots() -> list[Path]:
    candidates = [Path("workspace/github_cache"), Path("workspace/git_cache"), Path("github_cache")]
    return [path for path in candidates if path.exists()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", type=Path, default=Path("workspace/nvd_applicability_v10.sqlite"))
    parser.add_argument(
        "--nvd-jsonl",
        type=Path,
        help="DB manifest의 source_path가 이동했을 때 동일 snapshot JSONL 경로",
    )
    parser.add_argument("--osv-dir", type=Path, action="append", dest="osv_dirs")
    parser.add_argument("--git-cache", type=Path, action="append", dest="git_caches")
    parser.add_argument("--output-dir", type=Path, default=Path("workspace/cve_commit_evidence"))
    parser.add_argument(
        "--only",
        choices=("all", "references", "osv", "git-cache"),
        default="all",
        help="특정 수집기만 실행 (기본: all)",
    )
    parser.add_argument("--progress-every", type=int, default=10_000)
    parser.add_argument("--fail-on-error", action="store_true", help="개별 손상 JSON/git repo도 즉시 실패")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.progress_every < 0:
        raise CollectionError("--progress-every는 0 이상이어야 합니다")
    osv_roots = args.osv_dirs or [Path("data/osv")]
    git_roots = args.git_caches if args.git_caches is not None else default_git_cache_roots()
    summary: dict[str, Any] = {
        "inputs": {
            "db": str(args.db),
            "nvd_jsonl_override": str(args.nvd_jsonl) if args.nvd_jsonl else None,
            "osv_roots": [str(path) for path in osv_roots],
            "git_cache_roots": [str(path) for path in git_roots],
        },
        "outputs_sorted_by": "CVE year, CVE sequence, repository, commit",
        "collections": {},
        "errors": {},
    }
    if args.only in {"all", "references"}:
        records, stats = collect_reference_commits(args.db, args.nvd_jsonl, args.progress_every)
        atomic_write_outputs(args.output_dir, "reference_commit_records", records, REFERENCE_FIELDS)
        summary["collections"]["references"] = dict(stats)
        print(f"[done] reference commit records: {len(records):,}", file=sys.stderr)
    if args.only in {"all", "osv"}:
        records, stats, errors = collect_osv_records(osv_roots, args.progress_every, args.fail_on_error)
        atomic_write_outputs(args.output_dir, "osv_exact_version_repo_records", records, OSV_FIELDS)
        summary["collections"]["osv"] = dict(stats)
        summary["errors"]["osv"] = errors
        print(f"[done] OSV exact-version/repo records: {len(records):,}", file=sys.stderr)
    if args.only in {"all", "git-cache"}:
        if not git_roots:
            print(
                "[warning] git cache를 자동 발견하지 못했습니다. --git-cache PATH를 지정하세요.",
                file=sys.stderr,
            )
            atomic_write_outputs(args.output_dir, "git_cache_cve_commits", [], GIT_FIELDS)
            summary["collections"]["git_cache"] = {"skipped_no_cache": 1}
        else:
            records, stats, errors = collect_git_cache_records(git_roots, args.fail_on_error)
            atomic_write_outputs(args.output_dir, "git_cache_cve_commits", records, GIT_FIELDS)
            summary["collections"]["git_cache"] = dict(stats)
            summary["errors"]["git_cache"] = errors
            print(f"[done] git-cache CVE commits: {len(records):,}", file=sys.stderr)
    write_summary(args.output_dir, summary)
    print(f"[done] output: {args.output_dir.resolve()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CollectionError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
