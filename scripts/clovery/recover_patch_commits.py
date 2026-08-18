#!/usr/bin/env python3
"""Find patch commits for CVEs whose NVD references do not carry one.

Clovery needs a security patch commit to reconstruct the vulnerable and patched
functions (paper, Sect. 3.1 and Sect. 6). NVD often does not provide one: of the
124 CVEs the DB binds to Exiv2, only 10 reference a commit - 77 link an issue or
advisory instead, and 37 carry no git link at all.

Two recovery paths, neither of which needs NVD to improve:

``osv``
    OSV records the fix as structured data: ``affected[].ranges`` of
    ``type: GIT`` with ``fixed: <sha>`` events. Public API, no auth. On Exiv2
    this recovers 14 of the 114 missing CVEs. Many other records only carry
    ``last_affected``, which is a boundary rather than a patch, so it is
    reported but not used as a patch commit.

``gitlog``
    Projects routinely name the CVE in the commit message, so
    ``git log --all --grep <CVE>`` finds the patch with no network at all.
    On Exiv2 this recovers 21 of the 114. It needs filtering: merge commits
    carry no usable diff, and "add a reproducer for CVE-x" commits touch only
    tests, so both are dropped.

The recovered commit is turned into a ``https://github.com/<owner>/<repo>/commit/<sha>``
reference and appended to the CVE's feed entry, which is the only form Clovery's
collector accepts.

Usage
-----
    python scripts/clovery/recover_patch_commits.py --repo Exiv2@exiv2 --osv
    python scripts/clovery/recover_patch_commits.py --repo Exiv2@exiv2 \
        --gitlog --clone /path/to/exiv2
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{cve}"
CLOVERY_SUFFIXES = (".c", ".cc", ".cpp")
C_FAMILY_SUFFIXES = CLOVERY_SUFFIXES + (".cxx", ".h", ".hh", ".hpp", ".hxx")
# "Added the reproducer for CVE-x" commits match the message grep but only touch
# tests, so they carry no patch.
TEST_PATH = re.compile(
    r"(^|/)(test|tests|testsuite|samples?|fuzz|regression|reproducers?)(/|$)",
    re.IGNORECASE,
)
SHA = re.compile(r"^[0-9a-f]{7,40}$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
CVE_IN_TEXT = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,}(?![A-Z0-9])", re.I)
STANDARD_REVERT_SUBJECT = re.compile(
    r"^\s*revert\s+[\"'].*CVE-\d{4}-\d{4,}", re.I
)
AGGREGATE_SUBJECT = re.compile(
    r"\b(sync|merge(?:s|d)?|release|snapshot|rollup|cherry[- ]pick)\b"
    r"|\b\d+(?:\.\d+)+/master\b",
    re.I,
)


class RecoveryError(RuntimeError):
    pass


# ------------------------------------------------------------------------- osv


def osv_record(
    cve_id: str, *, timeout: int = 20, osv_dir: Path | None = None
) -> Mapping[str, Any] | None:
    if osv_dir is not None:
        cached = osv_dir / f"{cve_id}.json"
        if not cached.is_file():
            # An explicitly selected mirror is the authoritative offline
            # source. Falling back to the API here turns a plan over thousands
            # of CVEs into one network timeout per missing file.
            return None
        try:
            return json.loads(cached.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
    try:
        with urllib.request.urlopen(
            OSV_VULN_URL.format(cve=cve_id), timeout=timeout
        ) as response:
            return json.load(response)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None
    except json.JSONDecodeError:
        return None


def osv_records(
    cve_id: str, *, timeout: int = 20, osv_dir: Path | None = None
) -> list[Mapping[str, Any]]:
    """Return the CVE record plus locally cached native alias advisories."""

    first = osv_record(cve_id, timeout=timeout, osv_dir=osv_dir)
    if first is None:
        return []
    records = [first]
    if osv_dir is None:
        return records
    seen = {str(first.get("id") or cve_id)}
    for alias in first.get("aliases") or []:
        alias = str(alias)
        if alias in seen:
            continue
        path = osv_dir / f"{alias}.json"
        if not path.is_file():
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        records.append(record)
        seen.add(alias)
    return records


def _repo_matches(url: str, owner: str, name: str) -> bool:
    parsed = urlparse(url)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return False
    parts = [part for part in parsed.path.split("/") if part]
    return len(parts) >= 2 and (
        parts[0].lower(),
        parts[1].removesuffix(".git").lower(),
    ) == (owner.lower(), name.lower())


def canonical_github_commit(
    url: str, owner: str, name: str
) -> tuple[str | None, str]:
    """Return a SHA only for a canonical GitHub commit URL."""

    parsed = urlparse(url)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None, "unsupported_host"
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4:
        return None, "invalid_commit_url"
    if (
        parts[0].lower(),
        parts[1].removesuffix(".git").lower(),
    ) != (owner.lower(), name.lower()):
        return None, "wrong_repository"
    sha = ""
    if len(parts) == 4 and parts[2] in {"commit", "commits"}:
        sha = parts[3]
    elif (
        len(parts) == 6
        and parts[2] == "pull"
        and parts[3].isdigit()
        and parts[4] == "commits"
    ):
        sha = parts[5]
    else:
        return None, "invalid_commit_url"
    sha = sha.removesuffix(".diff").lower()
    if not SHA.fullmatch(sha):
        return None, "invalid_commit_sha"
    return sha, "ok"


def _converted_osv_range(
    record: Mapping[str, Any], entry: Mapping[str, Any]
) -> bool:
    top = record.get("database_specific") or {}
    details = entry.get("database_specific") or {}
    sources = {str(value) for value in details.get("source") or []}
    return bool(top.get("osv_generated_from")) or bool(
        {"CPE_RANGE", "AFFECTED_FIELD", "DESCRIPTION"} & sources
    )


def osv_candidates(
    record: Mapping[str, Any], owner: str, name: str
) -> list[dict[str, Any]]:
    """Return patch candidates and boundary hints from one OSV document."""

    candidates: list[dict[str, Any]] = []
    record_id = str(record.get("id") or "")
    seen: set[tuple[str, str]] = set()
    for reference in record.get("references") or []:
        url = str(reference.get("url") or "")
        sha, _ = canonical_github_commit(url, owner, name)
        if sha is None:
            continue
        key = (sha, "osv_reference")
        if key not in seen:
            candidates.append(
                {
                    "sha": sha,
                    "source": "osv_reference",
                    "url": url,
                    "osv_id": record_id,
                    "boundary_only": False,
                }
            )
            seen.add(key)

    wanted = f"{owner}/{name}".lower()
    for affected in record.get("affected") or []:
        for entry in affected.get("ranges") or []:
            if entry.get("type") != "GIT":
                continue
            repo = (
                str(entry.get("repo") or "")
                .lower()
                .rstrip("/")
                .removesuffix(".git")
            )
            if not repo.endswith(wanted):
                continue
            converted = _converted_osv_range(record, entry)
            for event in entry.get("events") or []:
                for event_name in ("fixed", "last_affected"):
                    sha = str(event.get(event_name) or "").lower()
                    if not SHA.fullmatch(sha):
                        continue
                    boundary_only = converted or event_name == "last_affected"
                    source = (
                        "osv_converted_boundary"
                        if boundary_only
                        else "osv_native_fixed"
                    )
                    key = (sha, source)
                    if key in seen:
                        continue
                    candidates.append(
                        {
                            "sha": sha,
                            "source": source,
                            "url": commit_url(owner, name, sha),
                            "osv_id": record_id,
                            "event": event_name,
                            "boundary_only": boundary_only,
                        }
                    )
                    seen.add(key)
    return candidates


def osv_commits(
    record: Mapping[str, Any], owner: str, name: str
) -> tuple[list[str], list[str]]:
    """(fix commits, last-affected commits) for this repository."""

    wanted = f"{owner}/{name}".lower()
    fixed: list[str] = []
    last_affected: list[str] = []
    for affected in record.get("affected") or []:
        for entry in affected.get("ranges") or []:
            if entry.get("type") != "GIT":
                continue
            repo = str(entry.get("repo") or "").lower().rstrip("/")
            if not repo.endswith(wanted):
                continue
            for event in entry.get("events") or []:
                if "fixed" in event and SHA.match(str(event["fixed"])):
                    if event["fixed"] not in fixed:
                        fixed.append(event["fixed"])
                elif "last_affected" in event and SHA.match(str(event["last_affected"])):
                    if event["last_affected"] not in last_affected:
                        last_affected.append(event["last_affected"])
    return fixed, last_affected


def recover_from_osv(
    cve_ids: Iterable[str],
    owner: str,
    name: str,
    *,
    progress: bool = False,
    osv_dir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for index, cve_id in enumerate(sorted(set(cve_ids)), start=1):
        records = osv_records(cve_id, osv_dir=osv_dir)
        if progress and index % 25 == 0:
            print(f"    osv {index} ...", flush=True)
        if not records:
            continue
        candidates = [
            candidate
            for record in records
            for candidate in osv_candidates(record, owner, name)
        ]
        patch = [
            candidate for candidate in candidates
            if not candidate["boundary_only"]
        ]
        boundaries = [
            candidate["sha"] for candidate in candidates
            if candidate["boundary_only"]
        ]
        if patch or boundaries:
            out[cve_id] = {
                "commits": list(
                    dict.fromkeys(candidate["sha"] for candidate in patch)
                ),
                "boundaries": list(dict.fromkeys(boundaries)),
                "candidates": candidates,
                "source": (
                    patch[0]["source"] if patch else "osv_boundary_only"
                ),
            }
    return out


# ---------------------------------------------------------------------- gitlog


def _git(clone: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(clone), *args], capture_output=True, text=True, check=False
    )
    return completed.stdout if completed.returncode == 0 else ""


def commit_touches_c_source(clone: Path, sha: str) -> bool:
    """True when the commit changes non-test C/C++ source."""
    files = [
        line.strip()
        for line in _git(clone, "show", "--name-only", "--pretty=format:", sha).splitlines()
        if line.strip()
    ]
    if not files:
        return False
    productive = [
        path
        for path in files
        if path.lower().endswith(CLOVERY_SUFFIXES) and not TEST_PATH.search(path)
    ]
    return bool(productive)


def gitlog_message_role(cve_id: str, message: str) -> dict[str, Any]:
    """Classify how directly a git-log match claims to fix ``cve_id``.

    Squash/synchronisation commits often copy hundreds of child commit
    messages into their body. A CVE mentioned there is weaker evidence than a
    commit whose own subject names it. Standard ``git revert`` subjects quote
    the reverted fix and are negative evidence, not another fix.
    """

    lines = message.splitlines()
    subject = lines[0].strip() if lines else ""
    cve_lower = cve_id.lower()
    subject_match = cve_lower in subject.lower()
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", message) if part.strip()]
    lead = "\n\n".join(paragraphs[:2])
    if subject_match:
        match = "subject"
    elif cve_lower in lead.lower():
        match = "lead"
    else:
        match = "body"
    return {
        "gitlog_match": match,
        "gitlog_subject": subject,
        "aggregate_hint": bool(AGGREGATE_SUBJECT.search(subject))
        or len(lines) >= 100,
        "standard_revert": bool(STANDARD_REVERT_SUBJECT.search(subject)),
    }


def recover_from_gitlog(
    clone: Path, cve_ids: Iterable[str], *, max_per_cve: int = 3
) -> dict[str, dict[str, Any]]:
    """Commits whose message names the CVE, filtered to real patches."""

    wanted = sorted({str(cve).upper() for cve in cve_ids})
    wanted_set = set(wanted)
    candidates: dict[str, list[dict[str, Any]]] = {cve: [] for cve in wanted}
    # One `git log --grep` walk per CVE made an 817-CVE repository walk the
    # same history 817 times. Git ORs repeated --grep expressions, so bounded
    # batches preserve the exact-message check with only a handful of walks.
    for offset in range(0, len(wanted), 200):
        batch = wanted[offset : offset + 200]
        raw = _git(
            clone,
            "log",
            "--all",
            "--no-merges",
            "--format=%H%x1f%B%x1e",
            *(f"--grep={cve}" for cve in batch),
        )
        for entry in raw.split("\x1e"):
            if "\x1f" not in entry:
                continue
            sha, message = entry.split("\x1f", 1)
            sha = sha.strip().lower()
            if not FULL_SHA.fullmatch(sha):
                continue
            mentioned = {
                match.group().upper() for match in CVE_IN_TEXT.finditer(message)
            }
            for cve_id in sorted(mentioned & wanted_set):
                if not any(item["sha"] == sha for item in candidates[cve_id]):
                    candidates[cve_id].append(
                        {
                            "sha": sha,
                            "order": len(candidates[cve_id]),
                            **gitlog_message_role(cve_id, message),
                        }
                    )

    usable: dict[str, bool] = {}
    out: dict[str, dict[str, Any]] = {}
    for cve_id in wanted:
        keep: list[dict[str, Any]] = []
        for candidate in candidates[cve_id]:
            sha = str(candidate["sha"])
            if candidate["standard_revert"]:
                continue
            if sha not in usable:
                usable[sha] = commit_touches_c_source(clone, sha)
            if usable[sha]:
                keep.append(candidate)
        if keep:
            strength = {"subject": 3, "lead": 2, "body": 1}
            keep.sort(
                key=lambda item: (
                    -strength[str(item["gitlog_match"])],
                    bool(item["aggregate_hint"]),
                    int(item["order"]),
                )
            )
            chosen = keep[:max_per_cve]
            out[cve_id] = {
                "commits": [str(item["sha"]) for item in chosen],
                "source": "gitlog_message",
                "metadata": {
                    str(item["sha"]): {
                        key: value
                        for key, value in item.items()
                        if key not in {"sha", "order", "standard_revert"}
                    }
                    for item in chosen
                },
            }
    return out


# ------------------------------------------------------------------------ feed


def commit_url(owner: str, name: str, sha: str) -> str:
    return f"https://github.com/{owner}/{name}/commit/{sha}"


def _resolve_commit(clone: Path, sha: str) -> str | None:
    resolved = _git(
        clone, "rev-parse", "--verify", f"{sha}^{{commit}}"
    ).strip().lower()
    return resolved if FULL_SHA.fullmatch(resolved) else None


def validate_candidate(
    clone: Path, cve_id: str, candidate: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate repository existence, language scope and patch provenance."""

    result = dict(candidate)
    result.update(
        {"accepted": False, "reason": "unknown", "changed_files": []}
    )
    if candidate.get("boundary_only") and candidate.get("event") == "last_affected":
        result["reason"] = "version_boundary_not_patch"
        return result
    sha = _resolve_commit(clone, str(candidate.get("sha") or ""))
    if sha is None:
        result["reason"] = "commit_not_found"
        return result
    result["sha"] = sha
    parents = _git(clone, "rev-list", "--parents", "-n", "1", sha).split()
    diff_args = (
        ("diff", "--name-only", f"{sha}^1", sha)
        if len(parents) > 2
        else (
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            sha,
        )
    )
    files = [
        line.strip()
        for line in _git(clone, *diff_args).splitlines()
        if line.strip()
    ]
    files = list(dict.fromkeys(files))
    result["changed_files"] = files
    productive = [
        path
        for path in files
        if path.lower().endswith(CLOVERY_SUFFIXES)
        and not TEST_PATH.search(path)
    ]
    family = [
        path for path in files
        if path.lower().endswith(C_FAMILY_SUFFIXES)
    ]
    result["productive_files"] = productive
    if not productive:
        if family:
            result["reason"] = "unsupported_c_family_file"
        elif files and all(TEST_PATH.search(path) for path in files):
            result["reason"] = "test_only"
        else:
            result["reason"] = "unsupported_language_or_docs"
        return result
    message = _git(clone, "show", "-s", "--format=%B", sha).strip()
    result["message"] = message[:500]
    result["cve_in_message"] = cve_id.lower() in message.lower()
    # NVD-to-OSV conversion represents CPE version ends as GIT ``fixed``
    # events. They are only patch evidence when the local commit itself names
    # the CVE and changes supported source; otherwise it is just a convenient
    # clone/bootstrap boundary and must not enter Clovery.
    if candidate.get("boundary_only") and not result["cve_in_message"]:
        result["reason"] = "version_boundary_not_patch"
        return result
    source = str(candidate.get("source") or "")
    source_score = {
        "nvd_reference": 300,
        "gitlog_message": 280,
        "osv_reference": 240,
        "osv_native_fixed": 180,
    }.get(source, 100)
    if source == "gitlog_message":
        message_bonus = {
            "subject": 50,
            "lead": 40,
            "body": 20,
        }.get(str(candidate.get("gitlog_match") or "body"), 20)
        if candidate.get("aggregate_hint"):
            message_bonus -= 10
    else:
        message_bonus = 50 if result["cve_in_message"] else 0
    result["score"] = source_score + message_bonus
    result["accepted"] = True
    result["reason"] = "accepted"
    return result


def _record_urls(
    record: Mapping[str, Any], owner: str, name: str
) -> list[str]:
    urls: list[str] = []
    for reference in record.get("references") or []:
        url = str(reference.get("url") or "")
        if _repo_matches(url, owner, name) and url not in urls:
            urls.append(url)
    return urls


def osv_patch_hints(
    cve_id: str, owner: str, name: str, osv_dir: Path | None
) -> list[dict[str, Any]]:
    if osv_dir is None:
        return []
    return [
        candidate
        for record in osv_records(cve_id, osv_dir=osv_dir)
        for candidate in osv_candidates(record, owner, name)
    ]


def osv_target_hints(
    cve_id: str, owner: str, name: str, osv_dir: Path | None
) -> list[dict[str, Any]]:
    """OSV fixed events used to form the 605-repository plan upper bound.

    Planning uses the exact CVE document only. Alias advisory references and
    native ranges remain runtime recovery evidence, but widening the target set
    with them changes the historical upper-bound definition. ``last_affected``
    is deliberately excluded: it names a vulnerable boundary, not a fix.
    """

    if osv_dir is None:
        return []
    record = osv_record(cve_id, osv_dir=osv_dir)
    if record is None:
        return []
    return [
        candidate
        for candidate in osv_candidates(record, owner, name)
        if candidate.get("event") == "fixed"
    ]


def build_validated_feed(
    feed_path: Path,
    records: Mapping[str, Mapping[str, Any]],
    cve_ids: Iterable[str],
    owner: str,
    name: str,
    clone: Path,
    *,
    recover: str = "both",
    osv_dir: Path | None = None,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Replace a plan feed with evidence-validated patch commits."""

    from nvd2_to_clovery_feed import to_v11_item

    all_cves = sorted(set(cve_ids))
    manifest: dict[str, Any] = {
        "schema_version": 2,
        "repo": f"{owner}@{name}",
        "cves": {},
        "selected_cves": 0,
    }
    candidates_by_cve: dict[str, list[dict[str, Any]]] = {
        cve: [] for cve in all_cves
    }

    for cve_id in all_cves:
        record = records.get(cve_id) or {}
        for url in _record_urls(record, owner, name):
            sha, reason = canonical_github_commit(url, owner, name)
            if sha is None:
                candidates_by_cve[cve_id].append(
                    {
                        "source": "nvd_reference",
                        "url": url,
                        "accepted": False,
                        "reason": reason,
                    }
                )
                continue
            candidates_by_cve[cve_id].append(
                {
                    "source": "nvd_reference",
                    "url": url,
                    "sha": sha,
                    "boundary_only": False,
                }
            )

    def validate_new(cve_id: str) -> list[dict[str, Any]]:
        validated: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for candidate in candidates_by_cve[cve_id]:
            if "sha" not in candidate:
                validated.append(candidate)
                continue
            key = (
                str(candidate.get("sha")),
                str(candidate.get("source")),
            )
            if key in seen:
                continue
            seen.add(key)
            if "accepted" in candidate:
                validated.append(candidate)
            else:
                validated.append(
                    validate_candidate(clone, cve_id, candidate)
                )
        candidates_by_cve[cve_id] = validated
        return validated

    unresolved: list[str] = []
    for cve_id in all_cves:
        if not any(
            item.get("accepted") for item in validate_new(cve_id)
        ):
            unresolved.append(cve_id)

    if recover in {"gitlog", "both"} and unresolved:
        found = recover_from_gitlog(clone, unresolved)
        for cve_id, info in found.items():
            metadata = info.get("metadata") or {}
            candidates_by_cve[cve_id].extend(
                {
                    "source": "gitlog_message",
                    "url": commit_url(owner, name, sha),
                    "sha": sha,
                    "boundary_only": False,
                    **(metadata.get(sha) or {}),
                }
                for sha in info.get("commits") or []
            )
            validate_new(cve_id)
        unresolved = [
            cve
            for cve in unresolved
            if not any(
                item.get("accepted")
                for item in candidates_by_cve[cve]
            )
        ]

    if recover in {"osv", "both"} and unresolved:
        found = recover_from_osv(
            unresolved, owner, name, osv_dir=osv_dir
        )
        for cve_id, info in found.items():
            candidates_by_cve[cve_id].extend(
                info.get("candidates") or []
            )
            validate_new(cve_id)

    selected: dict[str, list[dict[str, Any]]] = {}
    for cve_id in all_cves:
        candidates = candidates_by_cve[cve_id]
        accepted = sorted(
            (
                item for item in candidates
                if item.get("accepted")
            ),
            key=lambda item: (
                -int(item.get("score") or 0),
                str(item.get("sha") or ""),
            ),
        )
        if accepted:
            best_score = int(accepted[0]["score"])
            selected[cve_id] = [
                item
                for item in accepted
                if int(item["score"]) == best_score
            ]
            status = "selected"
        elif any(
            item.get("reason") == "version_boundary_not_patch"
            for item in candidates
        ):
            status = "boundary_only"
        elif any(
            item.get("reason") == "unsupported_c_family_file"
            for item in candidates
        ):
            status = "unsupported_c_family_file"
        elif any(
            item.get("reason")
            in {"unsupported_language_or_docs", "test_only"}
            for item in candidates
        ):
            status = "unsupported_language_or_docs"
        elif candidates:
            status = "invalid_patch_candidate"
        else:
            status = "no_patch_evidence"
        manifest["cves"][cve_id] = {
            "status": status,
            "selected": selected.get(cve_id, []),
            "candidates": candidates,
        }

    items = []
    for cve_id, chosen in sorted(selected.items()):
        record = records.get(cve_id)
        if record is None:
            manifest["cves"][cve_id][
                "status"
            ] = "source_record_missing"
            continue
        urls = [
            commit_url(owner, name, str(item["sha"]))
            for item in chosen
        ]
        items.append(to_v11_item(record, urls))
    feed = {
        "CVE_data_type": "CVE",
        "CVE_data_format": "MITRE",
        "CVE_data_version": "4.0",
        "CVE_data_numberOfCVEs": str(len(items)),
        "CVE_Items": items,
    }
    temporary = feed_path.with_name(f".{feed_path.name}.tmp")
    temporary.write_text(json.dumps(feed), encoding="utf-8")
    temporary.replace(feed_path)
    manifest["selected_cves"] = len(items)
    counts: dict[str, int] = {}
    for item in manifest["cves"].values():
        status = str(item["status"])
        counts[status] = counts.get(status, 0) + 1
    manifest["status_counts"] = counts
    if manifest_path is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return manifest


def augment_feed(
    feed_path: Path,
    records: Mapping[str, Mapping[str, Any]],
    recovered: Mapping[str, Mapping[str, Any]],
    owner: str,
    name: str,
) -> int:
    """Add recovered CVEs to a Clovery feed. Returns how many were added."""

    from nvd2_to_clovery_feed import to_v11_item  # local import: same directory

    feed = json.loads(feed_path.read_text(encoding="utf-8"))
    present = {
        item["cve"]["CVE_data_meta"]["ID"] for item in feed.get("CVE_Items") or []
    }
    added = 0
    for cve_id, info in sorted(recovered.items()):
        commits = info.get("commits") or []
        if not commits or cve_id in present:
            continue
        record = records.get(cve_id)
        if record is None:
            continue
        urls = [commit_url(owner, name, sha) for sha in commits]
        feed["CVE_Items"].append(to_v11_item(record, urls))
        added += 1
    if added:
        feed["CVE_data_numberOfCVEs"] = str(len(feed["CVE_Items"]))
        temporary = feed_path.with_name(f".{feed_path.name}.tmp")
        temporary.write_text(json.dumps(feed), encoding="utf-8")
        temporary.replace(feed_path)
    return added


# ------------------------------------------------------------------------- cli


def _load_target(repo: str) -> Mapping[str, Any]:
    plan_path = REPO_ROOT / "workspace" / "clovery" / "targets.json"
    if not plan_path.exists():
        raise RecoveryError(f"no plan at {plan_path}; run `clovery_cycle.py plan` first")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    for target in plan["targets"]:
        if target["repo"] == repo:
            return target
    raise RecoveryError(f"{repo} is not in the plan")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover patch commits for CVEs whose NVD references lack one"
    )
    parser.add_argument("--repo", required=True, help="owner@repo as spelled in the plan")
    parser.add_argument("--osv", action="store_true", help="query the OSV API")
    parser.add_argument(
        "--gitlog", action="store_true", help="search commit messages (needs --clone)"
    )
    parser.add_argument("--clone", type=Path, help="repository checkout for --gitlog")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="append the recovered commits to the repo's feed",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.osv and not args.gitlog:
        print("error: pass --osv and/or --gitlog", file=sys.stderr)
        return 1
    try:
        target = _load_target(args.repo)
        owner, name = target["owner"], target["name"]
        feed_path = REPO_ROOT / target["feed"]
        feed = json.loads(feed_path.read_text(encoding="utf-8"))
        present = {
            item["cve"]["CVE_data_meta"]["ID"] for item in feed.get("CVE_Items") or []
        }
        missing = [cve for cve in target["db_cves"] if cve not in present]
        print(f"{args.repo}: {len(present)} in feed, {len(missing)} DB CVEs without a patch")

        recovered: dict[str, dict[str, Any]] = {}
        if args.osv:
            found = recover_from_osv(missing, owner, name, progress=True)
            usable = {k: v for k, v in found.items() if v.get("commits")}
            print(f"  osv    : {len(usable)} with a fix commit, "
                  f"{len(found) - len(usable)} boundary-only")
            recovered.update(usable)
        if args.gitlog:
            if not args.clone or not (args.clone / ".git").exists():
                raise RecoveryError("--gitlog needs --clone pointing at a checkout")
            still = [cve for cve in missing if cve not in recovered]
            found = recover_from_gitlog(args.clone, still)
            print(f"  gitlog : {len(found)} with a patch commit")
            recovered.update(found)

        print(f"  total  : {len(recovered)} recovered")

        if args.apply and recovered:
            from clovery_cycle import (  # local import: same directory
                default_database,
                read_cve_records,
                source_jsonl,
            )
            import sqlite3

            conn = sqlite3.connect(f"file:{default_database()}?mode=ro", uri=True)
            conn.execute("CREATE TEMP TABLE cycle_cves(cve_id TEXT PRIMARY KEY)")
            records = read_cve_records(conn, recovered.keys(), source_jsonl(conn, None))
            conn.close()
            added = augment_feed(feed_path, records, recovered, owner, name)
            print(f"  feed   : +{added} CVE -> {feed_path}")
    except (RecoveryError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(recovered, indent=2, sort_keys=True))
    else:
        for cve_id, info in sorted(recovered.items()):
            print(f"  {cve_id}  {info['source']:<18} {', '.join(info['commits'])[:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
