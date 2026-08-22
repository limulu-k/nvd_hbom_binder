#!/usr/bin/env python3
"""Convert NVD 2.0 data into the 1.1 feed shape Clovery's collector reads.

Clovery (https://github.com/kimdu0/clovery) predates the NVD 1.1 feed
retirement: ``1_cve_collector.py`` loads ``nvdcve-1.1-<year>.json`` and reads

    res["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"]
    res["CVE_Items"][i]["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
    res["CVE_Items"][i]["cve"]["references"]["reference_data"][j]["url"]
    res["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]

so only those four paths have to be reproduced faithfully.  This emits exactly
that from ``nvd-json-2.0/nvdcve-2.0-<year>.json``.

It also applies Clovery's own eligibility filter up front, so the collector is
not handed CVEs it would discard anyway:

  * a reference URL on github.com / cgit / gitlab / gitweb, containing "commit"
  * optionally, that URL points at a repository in a corpus list such as
    ``git/sample_c_git.txt`` (Clovery only keeps diffs touching .c/.cc/.cpp)

Examples
--------
    # every year, C corpus only, straight into Clovery's input directory
    python scripts/nvd2_to_clovery_feed.py --all \
        --repo-list git/sample_c_git.txt \
        --out-dir /path/to/clovery/Evalu/data/nvd

    # one year, no corpus restriction
    python scripts/nvd2_to_clovery_feed.py --year 2020 --out-dir /tmp/feed
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from nvd_normalization.rules import normalize_key  # noqa: E402

DEFAULT_SOURCE = REPO_ROOT / "nvd-json-2.0"
# Mirrors ``gitlist`` in Clovery's 1_cve_collector.py.
GITLIST = ("github.com", "cgit", "gitlab", "gitweb")
GH_REPO = re.compile(r"github\.com/([A-Za-z0-9._-]{1,64})/([A-Za-z0-9._-]{1,64})")


class FeedError(RuntimeError):
    pass


def load_repo_corpus(path: Path) -> set[tuple[str, str]]:
    """``owner@repo`` lines -> normalized (owner, repo) keys."""

    corpus = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        owner, _, name = line.partition("@")
        corpus.add((normalize_key(owner), normalize_key(name or owner)))
    if not corpus:
        raise FeedError(f"{path} contains no owner@repo entries")
    return corpus


def eligible_urls(
    references: Iterable[Mapping[str, Any]], corpus: set[tuple[str, str]] | None
) -> list[str]:
    """Reference URLs Clovery's collector would keep."""

    kept = []
    for reference in references:
        url = str(reference.get("url") or "")
        lowered = url.lower()
        if not any(host in lowered for host in GITLIST):
            continue
        if "commit" not in url:
            continue
        if corpus is not None:
            match = GH_REPO.search(url)
            if not match:
                # cgit/gitweb/gitlab hosts carry no owner/repo we can check
                # against a GitHub corpus; drop them under corpus mode.
                continue
            name = match.group(2)
            if name.endswith(".git"):
                name = name[:-4]
            if (normalize_key(match.group(1)), normalize_key(name)) not in corpus:
                continue
        kept.append(url)
    return kept


def to_v11_item(cve: Mapping[str, Any], urls: Sequence[str]) -> dict[str, Any]:
    """Build one 1.1 ``CVE_Items`` entry from a 2.0 ``cve`` object."""

    cwe = "CWE-000"
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "")
            if value.startswith("CWE-"):
                cwe = value
                break
        if cwe != "CWE-000":
            break

    base_score = 0.0
    for metric in (cve.get("metrics") or {}).get("cvssMetricV2") or []:
        data = metric.get("cvssData") or {}
        if "baseScore" in data:
            base_score = data["baseScore"]
            break

    english = ""
    for description in cve.get("descriptions") or []:
        if description.get("lang") == "en":
            english = str(description.get("value") or "")
            break

    by_url = {
        str(reference.get("url")): reference for reference in cve.get("references") or []
    }
    reference_data = [
        {
            "url": url,
            "name": url,
            "refsource": str(by_url.get(url, {}).get("source") or ""),
            "tags": list(by_url.get(url, {}).get("tags") or []),
        }
        for url in urls
    ]

    return {
        "cve": {
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "4.0",
            "CVE_data_meta": {"ID": cve["id"], "ASSIGNER": cve.get("sourceIdentifier", "")},
            "problemtype": {
                "problemtype_data": [{"description": [{"lang": "en", "value": cwe}]}]
            },
            "references": {"reference_data": reference_data},
            "description": {"description_data": [{"lang": "en", "value": english}]},
        },
        "impact": {"baseMetricV2": {"cvssV2": {"baseScore": base_score}}},
        "publishedDate": cve.get("published", ""),
        "lastModifiedDate": cve.get("lastModified", ""),
    }


def convert_year(
    source: Path, year: int, corpus: set[tuple[str, str]] | None
) -> tuple[dict[str, Any], int, int]:
    path = source / f"nvdcve-2.0-{year}.json"
    if not path.exists():
        raise FeedError(f"missing source feed: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))

    items = []
    total = 0
    for entry in document.get("vulnerabilities") or []:
        cve = entry.get("cve")
        if not isinstance(cve, Mapping) or not cve.get("id"):
            continue
        total += 1
        urls = eligible_urls(cve.get("references") or [], corpus)
        if urls:
            items.append(to_v11_item(cve, urls))

    feed = {
        "CVE_data_type": "CVE",
        "CVE_data_format": "MITRE",
        "CVE_data_version": "4.0",
        "CVE_data_numberOfCVEs": str(len(items)),
        "CVE_data_timestamp": document.get("timestamp", ""),
        "CVE_Items": items,
    }
    return feed, total, len(items)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit Clovery-compatible NVD 1.1 feeds from NVD 2.0 data"
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--year", type=int, action="append", default=[])
    parser.add_argument("--all", action="store_true", help="every year found in --source")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--repo-list",
        type=Path,
        help="restrict to repositories in this owner@repo list (e.g. git/sample_c_git.txt)",
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="emit every CVE, not just the git-commit-referenced ones",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.all:
            years = sorted(
                int(match.group(1))
                for path in args.source.glob("nvdcve-2.0-*.json")
                if (match := re.search(r"nvdcve-2\.0-(\d{4})\.json$", path.name))
            )
        else:
            years = sorted(set(args.year))
        if not years:
            raise FeedError("pass --year YYYY (repeatable) or --all")

        corpus = load_repo_corpus(args.repo_list) if args.repo_list else None
        if args.no_filter and corpus:
            raise FeedError("--no-filter and --repo-list are mutually exclusive")
        args.out_dir.mkdir(parents=True, exist_ok=True)

        grand_total = grand_kept = 0
        for year in years:
            if args.no_filter:
                feed, total, kept = convert_year(args.source, year, None)
                feed["CVE_Items"] = feed["CVE_Items"]
            else:
                feed, total, kept = convert_year(args.source, year, corpus)
            target = args.out_dir / f"nvdcve-1.1-{year}.json"
            temporary = target.with_name(f".{target.name}.tmp")
            temporary.write_text(json.dumps(feed), encoding="utf-8")
            temporary.replace(target)
            grand_total += total
            grand_kept += kept
            print(f"{year}: {kept:>6} eligible / {total:>6} CVE  -> {target}")

        print(f"\ntotal: {grand_kept} eligible / {grand_total} CVE across {len(years)} year(s)")
    except (FeedError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
