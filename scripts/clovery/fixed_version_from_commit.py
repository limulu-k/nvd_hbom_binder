#!/usr/bin/env python3
"""Derive the fixed version of a CVE from the patch commit in its references.

Clovery tags each *git tag* Safe/Vulnerable by re-analysing code, which is
expensive.  When a CVE reference already points at the patch commit, the release
boundary can be read straight out of the repository - and that boundary is what
the SBOM database needs.

The naive reading of a GitHub commit page is wrong.  GitHub shows a *range* of
tags containing the commit, e.g. ``7.1.2-29 … 7.0.4-4`` for CVE-2017-5506:

  * ``7.1.2-29`` is merely the newest tag that still contains the patch,
  * ``7.0.4-4`` is the oldest tag that contains it - the actual fixed version.

Nor is "smallest version string wins" safe: a repository maintains several
release series in parallel, and each series has its own fixed version.  So:

    patch commit
      -> tags containing it            (git tag --contains)
      -> keep real release tags only   (drop rc/beta/archive refs)
      -> split by version series       (7.x, 6.x, ...)
      -> earliest tag per series       (git's v:refname ordering)
      -> verify the preceding release does NOT contain it
      -> fixed version per series

Yielding, for CVE-2017-5506 / ImageMagick:

    series 7: introduced <= 7.0.4-3, fixed 7.0.4-4   (verified)

Usage
-----
    python scripts/clovery/fixed_version_from_commit.py \
        --clone /path/to/ImageMagick \
        --commit 9a069e0f2e027ec5138f998023cf9cb62c04889f

    # every CVE/commit pair Clovery would collect for one repository
    python scripts/clovery/fixed_version_from_commit.py \
        --clone <clone> --feed workspace/clovery/feeds/owner##repo.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

# A tag we would publish a fixed version against.  Pre-release and branch-ish
# refs are excluded: a fix landing in 7.0.4-4rc1 does not make 7.0.4-4rc1 the
# answer a consumer can act on.
# The version must be *anchored*: an optional project-name or `v` prefix, then a
# dotted/underscored version with at least two numeric components.
#
# Searching for any digit run instead (the obvious first cut) misreads project
# names and internal tags. Exiv2 ships `testIPO_3` and
# `testIPO_exiv2-xmp-OBJECT`; a loose search takes the `3`, and the `2` out of
# "exiv2", inventing 3.x and 2.x release series that never existed and reporting
# "no affected release" against them.
#
# Requiring two components is what rejects those, at the cost of tags like `v1`
# or `release-2` - which real projects effectively never use for a release.
RELEASE_TAG = re.compile(
    # A project-name prefix is separated by `_`/`-` only. Allowing `.` here lets
    # the name swallow the major version: `v0.28.8` would parse as name "v0"
    # plus version "28.8".
    r"^(?:[A-Za-z][A-Za-z0-9]*[_-]|[vVrR])?"    # `exiv2-`, `R_`, `v`, or nothing
    r"(?P<core>\d+(?:[._]\d+)+(?:-\d+)?)"       # 0.28.8 / 2_2_1 / 7.0.4-4
    r"(?P<rest>.*)$"
)
# Anything trailing the version that marks it as not-a-release: `v0.18-pre1`,
# `v0.27.2-RC1`, `thunar-0.3.0beta1`.
PRERELEASE = re.compile(
    r"(rc|alpha|beta|pre|dev|snapshot|nightly|preview|test|milestone)", re.IGNORECASE
)
COMMIT_URL = re.compile(
    r"(?:github\.com|gitlab[^/]*|cgit[^/]*|gitweb[^/]*)/.*?commit[/=]([0-9a-f]{7,40})",
    re.IGNORECASE,
)


class GitError(RuntimeError):
    pass


def git(clone: Path, *args: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", "-C", str(clone), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {completed.stderr.strip()}")
    return completed.stdout


def git_ok(clone: Path, *args: str) -> bool:
    """Run a git predicate; True when it exits 0."""
    completed = subprocess.run(
        ["git", "-C", str(clone), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode == 0


def version_core(tag: str) -> str | None:
    """The release version a tag names, or None when it does not name one."""
    match = RELEASE_TAG.match(tag or "")
    return match.group("core").replace("_", ".") if match else None


def is_release_tag(tag: str, *, allow_slash: bool = False) -> bool:
    if not tag:
        return False
    if "/" in tag and not allow_slash:
        # e.g. thunar's archive/BenediktMeurer/... refs
        return False
    match = RELEASE_TAG.match(tag)
    if match is None:
        return False
    # Only what trails the version can demote it; the prefix is the project
    # name, and "testIPO"-style names must not be read as a version at all -
    # that is handled by the anchoring above, not here.
    return not PRERELEASE.search(match.group("rest"))


def series_of(tag: str, depth: int) -> str | None:
    core = version_core(tag)
    if core is None:
        return None
    head = core.split("-")[0]
    return ".".join(head.split(".")[:depth])


def release_tags(clone: Path, *, depth: int, allow_slash: bool) -> list[str]:
    """All release tags, in git's own version order (oldest first)."""
    raw = git(clone, "tag", "--sort=v:refname").splitlines()
    return [tag.strip() for tag in raw if is_release_tag(tag.strip(), allow_slash=allow_slash)]


def resolve_commit(clone: Path, commit: str) -> str | None:
    """Full SHA if the commit exists in this clone, else None."""
    completed = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "--verify", f"{commit}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def analyse_commit(
    clone: Path,
    commit: str,
    *,
    depth: int = 1,
    allow_slash: bool = False,
    verify: bool = True,
) -> dict[str, Any]:
    """Fixed version per release series for one patch commit."""

    result: dict[str, Any] = {
        "commit": commit,
        "resolved": None,
        "state": "unknown",
        "series": {},
        "latest_containing_tag": None,
        "branches": [],
    }

    full = resolve_commit(clone, commit)
    if full is None:
        result["state"] = "commit_not_in_clone"
        return result
    result["resolved"] = full

    ordered = release_tags(clone, depth=depth, allow_slash=allow_slash)
    order_index = {tag: index for index, tag in enumerate(ordered)}

    containing_raw = git(clone, "tag", "--contains", full, check=False).splitlines()
    containing = {
        tag.strip()
        for tag in containing_raw
        if tag.strip() in order_index
    }
    result["branches"] = [
        line.strip().lstrip("* ").strip()
        for line in git(clone, "branch", "-a", "--contains", full, check=False).splitlines()
        if line.strip()
    ][:10]

    if not containing:
        # The patch exists but no release carries it yet.
        result["state"] = "unreleased"
        return result

    result["latest_containing_tag"] = max(containing, key=lambda tag: order_index[tag])

    by_series: dict[str, list[str]] = {}
    for tag in containing:
        key = series_of(tag, depth)
        if key is None:
            continue
        by_series.setdefault(key, []).append(tag)

    for key, tags in sorted(by_series.items()):
        earliest = min(tags, key=lambda tag: order_index[tag])
        index = order_index[earliest]
        previous = None
        for candidate in reversed(ordered[:index]):
            if series_of(candidate, depth) == key:
                previous = candidate
                break

        entry: dict[str, Any] = {
            "fixed": earliest,
            "previous_release": previous,
            "latest_containing": max(tags, key=lambda tag: order_index[tag]),
            "containing_count": len(tags),
            "verified": None,
            "verification": None,
        }
        if verify:
            # The fix must be in `fixed` and absent from the release before it,
            # otherwise the boundary is wrong (rebase, cherry-pick, retag...).
            in_fixed = git_ok(clone, "merge-base", "--is-ancestor", full, earliest)
            in_previous = (
                git_ok(clone, "merge-base", "--is-ancestor", full, previous)
                if previous
                else False
            )
            entry["verified"] = bool(in_fixed and not in_previous)
            if not in_fixed:
                entry["verification"] = "commit_not_ancestor_of_fixed"
            elif in_previous:
                entry["verification"] = "commit_already_in_previous_release"
            elif previous is None:
                # The oldest release of this series already carries the patch,
                # so no released version of the series is affected.  That is a
                # different statement from "fixed in <oldest tag>".
                entry["verification"] = "no_affected_release_in_series"
                entry["fixed"] = None
            else:
                entry["verification"] = "ok"
        result["series"][key] = entry

    result["state"] = "resolved"
    return result


def commits_from_feed(feed: Path) -> dict[str, list[str]]:
    """CVE -> patch commit SHAs, read from a Clovery 1.1 feed."""
    document = json.loads(feed.read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for item in document.get("CVE_Items") or []:
        cve = item["cve"]["CVE_data_meta"]["ID"]
        shas: list[str] = []
        for reference in item["cve"]["references"]["reference_data"]:
            match = COMMIT_URL.search(str(reference.get("url") or ""))
            if match and match.group(1) not in shas:
                shas.append(match.group(1))
        if shas:
            out[cve] = shas
    return out


def analyse_feed(
    clone: Path,
    feed: Path,
    *,
    depth: int = 1,
    allow_slash: bool = False,
    verify: bool = True,
) -> dict[str, Any]:
    per_cve = commits_from_feed(feed)
    results: dict[str, Any] = {}
    cache: dict[str, dict[str, Any]] = {}
    for cve, shas in sorted(per_cve.items()):
        entries = []
        for sha in shas:
            if sha not in cache:
                cache[sha] = analyse_commit(
                    clone, sha, depth=depth, allow_slash=allow_slash, verify=verify
                )
            entries.append(cache[sha])
        results[cve] = {"commits": entries, "fixed": _merge_series(entries)}
    return {
        "clone": str(clone),
        "feed": str(feed),
        "cve_count": len(results),
        "results": results,
    }


def _merge_series(entries: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Per series, the earliest verified fixed version across all commits.

    Multiple patch commits for one CVE must all be present before a release is
    really fixed, so the *latest* of their per-series boundaries wins.
    """
    merged: dict[str, str] = {}
    for entry in entries:
        for key, data in (entry.get("series") or {}).items():
            # Only a boundary that passed both ancestor checks is publishable;
            # "no affected release" and the failure modes carry no fixed version.
            if data.get("verification") not in (None, "ok"):
                continue
            fixed = data.get("fixed")
            if not fixed:
                continue
            current = merged.get(key)
            if current is None or fixed > current:
                merged[key] = fixed
    return merged


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve CVE fixed versions from patch commits in a git clone"
    )
    parser.add_argument("--clone", type=Path, required=True, help="repository checkout")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--commit", action="append", help="patch commit SHA (repeatable)")
    source.add_argument("--feed", type=Path, help="Clovery 1.1 feed to take commits from")
    parser.add_argument(
        "--series-depth",
        type=int,
        default=1,
        help="version components that define a release series (1 = major, 2 = major.minor)",
    )
    parser.add_argument(
        "--allow-slash-tags",
        action="store_true",
        help="treat refs containing '/' as release tags too",
    )
    parser.add_argument("--no-verify", dest="verify", action="store_false", default=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("json", "text"), default="text")
    return parser


def render_text(payload: Mapping[str, Any]) -> str:
    lines = []
    if "results" in payload:
        for cve, data in payload["results"].items():
            fixed = data["fixed"]
            summary = ", ".join(f"{k}.x -> {v}" for k, v in sorted(fixed.items())) or "(none)"
            lines.append(f"{cve}: {summary}")
            for entry in data["commits"]:
                lines.append(f"  commit {entry['commit'][:12]} [{entry['state']}]")
                for key, series in sorted((entry.get("series") or {}).items()):
                    mark = "ok" if series["verified"] else f"CHECK:{series['verification']}"
                    lines.append(
                        f"    series {key}.x: {series['previous_release']} -> "
                        f"{series['fixed']}  ({mark})"
                    )
    else:
        entry = payload
        lines.append(f"commit {entry['commit']} [{entry['state']}]")
        if entry.get("latest_containing_tag"):
            lines.append(f"  latest containing tag: {entry['latest_containing_tag']}")
        for key, series in sorted((entry.get("series") or {}).items()):
            mark = "ok" if series["verified"] else f"CHECK:{series['verification']}"
            lines.append(
                f"  series {key}.x: affected <= {series['previous_release']}, "
                f"fixed = {series['fixed']}  ({mark})"
            )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not (args.clone / ".git").exists() and not (args.clone / "HEAD").exists():
            raise GitError(f"not a git checkout: {args.clone}")
        if args.feed:
            payload: Mapping[str, Any] = analyse_feed(
                args.clone,
                args.feed,
                depth=args.series_depth,
                allow_slash=args.allow_slash_tags,
                verify=args.verify,
            )
        else:
            entries = [
                analyse_commit(
                    args.clone,
                    sha,
                    depth=args.series_depth,
                    allow_slash=args.allow_slash_tags,
                    verify=args.verify,
                )
                for sha in args.commit
            ]
            payload = entries[0] if len(entries) == 1 else {
                "results": {f"commit-{i}": {"commits": [e], "fixed": _merge_series([e])}
                            for i, e in enumerate(entries)}
            }
    except (GitError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    content = (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else render_text(payload)
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
