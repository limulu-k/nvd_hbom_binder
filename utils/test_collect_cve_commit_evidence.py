#!/usr/bin/env python3

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

from utils.collect_cve_commit_evidence import (
    collect_git_cache_records,
    collect_osv_records,
    collect_reference_commits,
    is_probable_commit_cache_file,
)


def write_normalized_fixture(db_path: Path, jsonl_path: Path) -> None:
    values = [
        {
            "cve": {
                "id": "CVE-2024-9999",
                "references": [
                    {
                        "url": "https://github.com/acme/widget/commit/abcdef0123456789",
                        "source": "vendor",
                        "tags": ["Patch"],
                    },
                    {"url": "https://github.com/acme/widget/issues/7"},
                ],
            }
        },
        {"cve": {"id": "CVE-2023-10000", "references": []}},
    ]
    offsets = []
    offset = 0
    with jsonl_path.open("wb") as handle:
        for value in values:
            raw = (json.dumps(value) + "\n").encode()
            handle.write(raw)
            offsets.append((offset, len(raw)))
            offset += len(raw)
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE source_snapshot_manifest (
            snapshot_id INTEGER PRIMARY KEY,
            source_path TEXT NOT NULL
        );
        CREATE TABLE raw_cve (
            cve_id TEXT PRIMARY KEY,
            snapshot_id INTEGER NOT NULL,
            line_number INTEGER NOT NULL,
            byte_offset INTEGER NOT NULL,
            byte_length INTEGER NOT NULL
        );
        """
    )
    connection.execute(
        "INSERT INTO source_snapshot_manifest(snapshot_id,source_path) VALUES (1,?)",
        (str(jsonl_path),),
    )
    for index, (value, (offset, length)) in enumerate(zip(values, offsets), 1):
        connection.execute(
            "INSERT INTO raw_cve VALUES (?,?,?,?,?)",
            (value["cve"]["id"], 1, index, offset, length),
        )
    connection.commit()
    connection.close()


def test_collect_reference_commits(tmp_path: Path) -> None:
    db_path = tmp_path / "normalized.sqlite"
    jsonl_path = tmp_path / "nvd.jsonl"
    write_normalized_fixture(db_path, jsonl_path)

    records, stats = collect_reference_commits(db_path, None, 0)

    assert [row["cve_id"] for row in records] == ["CVE-2024-9999"]
    assert records[0]["commit_id"] == "abcdef0123456789"
    assert records[0]["repository"] == "acme@widget"
    assert records[0]["reference_tags"] == ["Patch"]
    assert stats["reference_commit_records"] == 1


def test_collect_osv_requires_versions_repo_and_cve(tmp_path: Path) -> None:
    good = {
        "id": "GHSA-abcd-efgh-ijkl",
        "aliases": ["CVE-2022-10000"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "widget"},
                "versions": ["1.0.0", "1.0.1"],
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/acme/widget.git",
                        "events": [{"introduced": "0"}, {"fixed": "abc1234"}],
                    }
                ],
            }
        ],
    }
    missing_versions = {
        "id": "GHSA-no-versions",
        "aliases": ["CVE-2022-9999"],
        "affected": [{"versions": [], "ranges": [{"type": "GIT", "repo": "x"}]}],
    }
    (tmp_path / "good.json").write_text(json.dumps(good), encoding="utf-8")
    (tmp_path / "bad.json").write_text(json.dumps(missing_versions), encoding="utf-8")

    records, stats, errors = collect_osv_records([tmp_path], 0, True)

    assert errors == []
    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2022-10000"
    assert records[0]["repository"] == "acme@widget"
    assert records[0]["exact_versions"] == ["1.0.0", "1.0.1"]
    assert stats["osv_exact_version_repo_records"] == 1


def test_collect_json_and_local_git_cache(tmp_path: Path) -> None:
    api_cache = tmp_path / "api"
    api_cache.mkdir()
    api_value = [
        {
            "sha": "a" * 40,
            "html_url": "https://github.com/acme/widget/commit/" + "a" * 40,
            "commit": {
                "message": "Fix CVE-2021-9999 and cve-2020-10000",
                "committer": {"date": "2024-01-01T00:00:00Z"},
            },
        }
    ]
    (api_cache / "acme__widget__commits__page_1.json").write_text(
        json.dumps(api_value), encoding="utf-8"
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    (repo / "README").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "Resolve CVE-2019-12345"], cwd=repo, check=True)

    records, stats, errors = collect_git_cache_records([tmp_path], True)

    assert errors == []
    assert [row["cve_id"] for row in records] == [
        "CVE-2019-12345",
        "CVE-2020-10000",
        "CVE-2021-9999",
    ]
    assert stats["git_api_commits_seen"] == 1
    assert stats["git_repositories_seen"] == 1


def test_commit_word_in_owner_is_not_a_commit_cache_file() -> None:
    assert not is_probable_commit_cache_file(Path("the-commit-company__raven__tags__page_1.json"))
    assert is_probable_commit_cache_file(Path("acme__widget__commits__page_1.json"))
