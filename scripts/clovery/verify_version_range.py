#!/usr/bin/env python3
"""Validate and update a CVE's version range from Clovery evidence.

This follows Clovery's own ``verifyCPE`` design (3_clovery_cpg.py:1461-1830):
normalise the git tags, collapse the per-tag Vulnerable/Safe verdicts into
contiguous ranges, read the published range, and compare the two at the start,
end and middle.  Two things differ:

* the published range comes from the applicability DB (``version_segment``)
  rather than a dumped CPE text file, because that is the range we are
  correcting;
* the comparison feeds a *proposed* range instead of only reporting a
  discrepancy - the point here is to update the DB, not just audit it.

Two deviations from upstream are deliberate, and both are bugs there:

* ``compare_CPE`` compares versions with plain string ``<`` / ``>``, so "1.10"
  sorts before "1.9".  Every comparison here goes through ``version_key``, the
  natural-sort helper Clovery already defines and uses elsewhere.
* ``extract_vulnerable_ranges`` closes a run using ``last_version`` which is the
  *numeric* form while the run start stays raw, so a range can mix spellings.
  Both ends are normalised here.

Three independent signals are reconciled:

    Clovery tagCombi   per git tag, does the vulnerable code still exist
    patch commit       the release boundary (git tag --contains)
    applicability DB   what NVD/CNA currently publish

Usage
-----
    python scripts/clovery/verify_version_range.py \
        --results workspace/clovery/results/DaveGamble##cJSON

    python scripts/clovery/verify_version_range.py --all-results workspace/clovery/results
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from nvd_normalization.rules import normalize_key  # noqa: E402


class VerifyError(RuntimeError):
    pass


# --------------------------------------------------------- Clovery version helpers


def version_key(version: str) -> list:
    """Natural sort key; upstream ``version_key`` verbatim."""
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", version)]


def extract_numeric_version(version: str) -> str | None:
    matches = re.findall(r"\d+(?:[.\-_]\d+)+", version)
    if matches:
        return max(matches, key=len).replace("-", ".").replace("_", ".")
    return None


def get_prefix_keyword(version: str) -> str | None:
    prefix = re.match(r"^[^\d]+", version)
    return prefix.group(0) if prefix else None


def is_valid_version(version: str | None) -> bool:
    """Upstream ``is_valid_version``: keep things that look like releases."""
    if version is None or not isinstance(version, str):
        return False
    if re.match(r"^\d{4}[-.]\d{2}[-.]\d{2}$", version):
        return True
    version = re.sub(r"(-alpha|-beta|-rc)\d*$", "", version)
    if re.search(r"[a-zA-Z]", version) and not re.match(r"^[^\d]+", version):
        return False
    dots = version.count(".")
    hyphens = version.count("-")
    if dots >= 1 and hyphens == 0:
        return True
    if hyphens >= 2:
        return True
    if dots >= 1 and hyphens >= 1 and (dots >= 2 or hyphens >= 2):
        return True
    if re.search(r"[a-zA-Z]+\d+[.\-_]\d+", version):
        return False
    return False


def filter_and_normalize_versions(data: Mapping[str, str]) -> dict[str, str]:
    """Upstream ``filter_and_normalize_versions``: drop noise tags, strip prefixes.

    A prefix (``v``, ``rel-``, ``thunar-``) is only trusted once it appears on at
    least four tags, which is what separates a real naming convention from a
    one-off branch name.
    """
    prefixes = [get_prefix_keyword(key) for key in data if get_prefix_keyword(key)]
    allowed = {prefix for prefix, count in Counter(prefixes).items() if count >= 4}

    valid: dict[str, str] = {}
    for key, value in data.items():
        if re.match(r"^\d{4}[-.]\d{2}[-.]\d{2}$", key):
            valid[key] = value
            continue
        prefix = get_prefix_keyword(key)
        numeric = extract_numeric_version(key)
        if prefix not in allowed and numeric and "-" in key and key.count("-") == 1:
            continue
        if prefix in allowed or is_valid_version(numeric):
            if numeric and is_valid_version(numeric):
                valid[numeric] = value
    return valid


def next_version_in_list(version: str, all_versions: Sequence[str], exclude: bool = False) -> str:
    if version in all_versions:
        index = all_versions.index(version)
        return all_versions[index + 1] if exclude and index + 1 < len(all_versions) else version
    return version


def prev_version_in_list(version: str, all_versions: Sequence[str], exclude: bool = False) -> str:
    if version in all_versions:
        index = all_versions.index(version)
        return all_versions[index - 1] if exclude and index > 0 else version
    return version


def are_versions_adjacent(first: str, second: str, all_versions: Sequence[str]) -> bool:
    try:
        return all_versions.index(second) == all_versions.index(first) + 1
    except ValueError:
        return False


def merge_ranges(
    ranges: Sequence[tuple[str, str]], all_versions: Sequence[str]
) -> list[tuple[str, str]]:
    """Upstream ``merge_ranges``: fold overlapping or adjacent intervals."""
    if not ranges:
        return []
    ordered = sorted(ranges, key=lambda item: version_key(item[0]))
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if version_key(start) <= version_key(last_end) or are_versions_adjacent(
            last_end, start, all_versions
        ):
            merged[-1] = (last_start, max(last_end, end, key=version_key))
        else:
            merged.append((start, end))
    return merged


def extract_vulnerable_ranges(
    tag_verdicts: Mapping[str, str]
) -> tuple[list[tuple[str, str]] | str, list[str] | None]:
    """Collapse per-tag verdicts into contiguous vulnerable ranges.

    Returns ``("Safe", None)`` when no release is vulnerable, matching upstream.

    A tag whose function could not be extracted carries no information. It must
    not close a vulnerable run the way a real ``Safe`` verdict does, and it must
    not count as evidence of safety either, so it is dropped here and reported
    separately as reduced coverage.
    """
    data = filter_and_normalize_versions(tag_verdicts)
    data = {
        version: status
        for version, status in data.items()
        if status in ("Vulnerable", "Safe")
    }
    versions = sorted(data.keys(), key=version_key)
    if not versions or all(status == "Safe" for status in data.values()):
        return "Safe", None

    ranges: list[tuple[str, str]] = []
    start: str | None = None
    last: str | None = None
    for version in versions:
        if data[version] == "Vulnerable":
            if start is None:
                start = version
            last = version
        elif start is not None:
            ranges.append((start, last or start))
            start = None
    if start is not None:
        ranges.append((start, last or start))

    return merge_ranges(ranges, versions), versions


# ------------------------------------------------------------------ published range


def db_ranges(
    conn: sqlite3.Connection,
    cve_id: str,
    repo_name: str,
    all_versions: Sequence[str],
) -> tuple[list[tuple[str, str]], list[dict[str, Any]]]:
    """The currently published affected range, from the applicability DB.

    Replaces upstream ``extract_cpe_ranges``; the bound semantics
    (``versionStartExcluding`` -> next release, ``versionEndExcluding`` ->
    previous release) are kept identical.
    """
    wanted = normalize_key(repo_name)
    rows = conn.execute(
        """SELECT p.product_key, s.status, s.exact_value,
                  s.lower_bound, s.lower_inclusive, s.upper_bound, s.upper_inclusive
           FROM source_claim c
           JOIN version_expression e ON e.source_claim_id = c.source_claim_id
           JOIN version_segment   s ON s.expression_id   = e.expression_id
           LEFT JOIN product_entity p ON p.product_id = c.product_id
           WHERE c.cve_id = ?""",
        (cve_id,),
    ).fetchall()

    raw: list[dict[str, Any]] = []
    ranges: list[tuple[str, str]] = []
    for product_key, status, exact, low, low_inc, high, high_inc in rows:
        if status != "affected":
            continue
        # Keep only claims about this repository's product when we can tell.
        if product_key and normalize_key(product_key) != wanted:
            continue
        raw.append(
            {
                "product_key": product_key,
                "exact_value": exact,
                "lower_bound": low,
                "lower_inclusive": low_inc,
                "upper_bound": high,
                "upper_inclusive": high_inc,
            }
        )

        if exact and exact not in {"*", "-"}:
            value = extract_numeric_version(exact) or exact
            ranges.append((value, value))
            continue

        start = extract_numeric_version(low) if low else None
        end = extract_numeric_version(high) if high else None
        if start and not low_inc:
            start = next_version_in_list(start, all_versions, exclude=True)
        if end and not high_inc:
            end = prev_version_in_list(end, all_versions, exclude=True)
        if not start and not end:
            continue
        # Upstream substitutes the corpus endpoints for an open bound.  With no
        # release list (an all-safe CVE) there is nothing to substitute, so the
        # open side stays open rather than being invented.
        if not start:
            if not all_versions:
                continue
            start = all_versions[0]
        if not end:
            if not all_versions:
                continue
            end = all_versions[-1]
        ranges.append((start, end))

    return merge_ranges(ranges, all_versions), raw


# ----------------------------------------------------------------------- comparison


def compare_ranges(
    derived: Sequence[tuple[str, str]], published: Sequence[tuple[str, str]]
) -> dict[str, Any]:
    """Upstream ``compare_CPE`` semantics, ordered by ``version_key``."""
    result: dict[str, Any] = {
        "Start_Problem": False,
        "End_Problem": False,
        "Middle_Problem": False,
    }
    if not derived or not published:
        return result

    if version_key(derived[0][0]) < version_key(published[0][0]):
        result["Start_Problem"] = "derived_starts_earlier"
    elif version_key(derived[0][0]) > version_key(published[0][0]):
        result["Start_Problem"] = "derived_starts_later"

    if version_key(derived[-1][-1]) < version_key(published[-1][-1]):
        result["End_Problem"] = "derived_ends_earlier"
    elif version_key(derived[-1][-1]) > version_key(published[-1][-1]):
        result["End_Problem"] = "derived_ends_later"

    for pub_start, pub_end in published:
        overlapped = any(
            version_key(start) <= version_key(pub_end)
            and version_key(end) >= version_key(pub_start)
            for start, end in derived
        )
        if not overlapped:
            result["Middle_Problem"] = True
            break
    return result


def propose_range(
    derived: Sequence[tuple[str, str]],
    published: Sequence[tuple[str, str]],
    all_versions: Sequence[str],
    commit_fixed: Mapping[str, str] | None,
) -> dict[str, Any]:
    """Build the range to publish, and say what it rests on.

    Clovery says which releases still carry the vulnerable code; the patch
    commit says which release first carried the fix.  When the two agree - the
    release after Clovery's last vulnerable one is the commit-derived fixed
    version - the boundary is corroborated twice and can be trusted.
    """
    basis: list[str] = []
    proposed: list[dict[str, Any]] = []

    fixed_by_series: dict[str, str] = {}
    for series, tag in (commit_fixed or {}).items():
        numeric = extract_numeric_version(tag)
        if numeric:
            fixed_by_series[series] = numeric

    for start, end in derived:
        basis.append("clovery_tags")
        entry: dict[str, Any] = {
            "introduced": start,
            "last_affected": end,
            "fixed": None,
            "fixed_source": None,
        }
        successor = next_version_in_list(end, all_versions, exclude=True)
        if successor != end:
            entry["fixed"] = successor
            entry["fixed_source"] = "clovery_next_release"

        series = end.split(".")[0]
        commit_fix = fixed_by_series.get(series)
        if commit_fix:
            if entry["fixed"] and version_key(commit_fix) == version_key(entry["fixed"]):
                entry["fixed_source"] = "clovery+patch_commit"
                basis.append("patch_commit")
            elif entry["fixed"] is None:
                entry["fixed"] = commit_fix
                entry["fixed_source"] = "patch_commit"
                basis.append("patch_commit")
                if version_key(commit_fix) <= version_key(end):
                    # The tag scan calls a release vulnerable that already
                    # contains the patch commit. One of the two signals is
                    # wrong, so the range must not be published as if only
                    # a single uncorroborated signal existed.
                    entry["fixed_conflict"] = {
                        "clovery_last_affected": end,
                        "patch_commit": commit_fix,
                    }
            else:
                entry["fixed_conflict"] = {
                    "clovery_next_release": entry["fixed"],
                    "patch_commit": commit_fix,
                }
        proposed.append(entry)

    corroborated = any(e.get("fixed_source") == "clovery+patch_commit" for e in proposed)
    conflicted = any("fixed_conflict" in e for e in proposed)
    if conflicted:
        confidence = "low"
    elif corroborated:
        confidence = "high"
    elif proposed:
        confidence = "medium"
    else:
        confidence = "none"

    published_text = [f"{start} - {end}" for start, end in published]
    proposed_text = [
        f"{entry['introduced']} - {entry['last_affected']}" for entry in proposed
    ]
    return {
        "ranges": proposed,
        "basis": sorted(set(basis)),
        "confidence": confidence,
        "changed": published_text != proposed_text,
        "published_text": published_text,
        "proposed_text": proposed_text,
    }


# -------------------------------------------------------------------------- driver


def verify_repo(results_dir: Path, database: Path) -> dict[str, Any]:
    """Verify every CVE Clovery produced results for in one repository."""
    summary_path = results_dir / "summary.json"
    repo = json.loads(summary_path.read_text(encoding="utf-8"))["repo"] if summary_path.exists() else results_dir.name
    repo_name = repo.partition("@")[2] or repo

    fixed_path = results_dir / "fixed_versions.json"
    commit_fixed: dict[str, dict[str, str]] = {}
    if fixed_path.exists():
        payload = json.loads(fixed_path.read_text(encoding="utf-8"))
        commit_fixed = {
            cve: data.get("fixed", {}) for cve, data in payload.get("results", {}).items()
        }

    conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    entries: list[dict[str, Any]] = []
    try:
        for sub in ("tagCombi", "tagCombi_allSafe"):
            folder = results_dir / sub
            if not folder.is_dir():
                continue
            for path in sorted(folder.glob("*_TAG_merged.json")):
                cve_id = path.name.split("_")[0]
                verdicts = json.loads(path.read_text(encoding="utf-8"))
                unknown_tags = sum(
                    1
                    for status in verdicts.values()
                    if status not in ("Vulnerable", "Safe")
                )
                derived, all_versions = extract_vulnerable_ranges(verdicts)

                if derived == "Safe" or all_versions is None:
                    published, raw = db_ranges(conn, cve_id, repo_name, [])
                    entries.append(
                        {
                            "cve": cve_id,
                            "repo": repo,
                            "state": "no_vulnerable_release",
                            "tag_count": len(verdicts),
                            "evaluated_tags": len(verdicts) - unknown_tags,
                            "unknown_tags": unknown_tags,
                            "derived_ranges": [],
                            "published_ranges": [list(r) for r in published],
                            "published_raw": raw,
                            "commit_fixed": commit_fixed.get(cve_id, {}),
                            "comparison": {},
                            "proposal": {
                                "ranges": [],
                                "basis": ["clovery_tags"],
                                # "no release is vulnerable" drawn from partial tag
                                # coverage is the weakest claim this tool can make.
                                "confidence": "low" if unknown_tags else "medium",
                                "changed": bool(published),
                                "published_text": [f"{s} - {e}" for s, e in published],
                                "proposed_text": [],
                            },
                        }
                    )
                    continue

                published, raw = db_ranges(conn, cve_id, repo_name, all_versions)
                proposal = propose_range(
                    derived, published, all_versions, commit_fixed.get(cve_id)
                )
                # Missing tags do not undermine a range the patch commit already
                # corroborates - that agreement is an independent signal. They do
                # undermine one resting on tag coverage alone.
                if unknown_tags and proposal["confidence"] != "high":
                    proposal["confidence"] = "low"
                entries.append(
                    {
                        "cve": cve_id,
                        "repo": repo,
                        "state": "verified",
                        "tag_count": len(verdicts),
                        "evaluated_tags": len(verdicts) - unknown_tags,
                        "unknown_tags": unknown_tags,
                        "release_count": len(all_versions),
                        "derived_ranges": [list(r) for r in derived],
                        "published_ranges": [list(r) for r in published],
                        "published_raw": raw,
                        "commit_fixed": commit_fixed.get(cve_id, {}),
                        "comparison": compare_ranges(derived, published),
                        "proposal": proposal,
                    }
                )
    finally:
        conn.close()

    changed = sum(1 for entry in entries if entry["proposal"]["changed"])
    return {
        "repo": repo,
        "database": str(database),
        "cve_count": len(entries),
        "changed_count": changed,
        "results": entries,
    }


def default_database() -> Path:
    candidates = sorted(
        (REPO_ROOT / "workspace").glob("nvd_applicability_v*.sqlite"),
        key=lambda path: (
            int(match.group(1)) if (match := re.search(r"_v(\d+)", path.name)) else 0,
            path.name,
        ),
    )
    if not candidates:
        raise VerifyError("no applicability DB under workspace/")
    return candidates[-1]


def render_text(payload: Mapping[str, Any]) -> str:
    lines = [f"# {payload['repo']}  ({payload['cve_count']} CVE, "
             f"{payload['changed_count']} would change)"]
    for entry in payload["results"]:
        proposal = entry["proposal"]
        lines.append(f"\n{entry['cve']}  [{entry['state']}]  confidence={proposal['confidence']}")
        lines.append(f"  published : {', '.join(proposal['published_text']) or '(none)'}")
        lines.append(f"  derived   : {', '.join(proposal['proposed_text']) or '(no vulnerable release)'}")
        for item in proposal["ranges"]:
            fixed = item.get("fixed") or "?"
            lines.append(
                f"    {item['introduced']} <= affected <= {item['last_affected']}"
                f"   fixed in {fixed}  ({item.get('fixed_source')})"
            )
            if "fixed_conflict" in item:
                lines.append(f"    ! conflict: {item['fixed_conflict']}")
        problems = {k: v for k, v in (entry.get("comparison") or {}).items() if v}
        if problems:
            lines.append(f"  diff      : {problems}")
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and update CVE version ranges from Clovery results"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--results", type=Path, help="one workspace/clovery/results/<pack> dir")
    source.add_argument("--all-results", type=Path, help="the results root; verify every repo")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--changed-only", action="store_true", help="report only CVEs whose range would change"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        database = args.db or default_database()
        directories = (
            [args.results]
            if args.results
            else sorted(path for path in args.all_results.iterdir() if path.is_dir())
        )
        payloads = [verify_repo(directory, database) for directory in directories]
        if args.changed_only:
            for payload in payloads:
                payload["results"] = [
                    entry for entry in payload["results"] if entry["proposal"]["changed"]
                ]
    except (VerifyError, OSError, sqlite3.Error, json.JSONDecodeError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.format == "json":
        body = payloads[0] if len(payloads) == 1 else {"repos": payloads}
        content = json.dumps(body, indent=2, sort_keys=True) + "\n"
    else:
        content = "\n".join(render_text(payload) for payload in payloads)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
