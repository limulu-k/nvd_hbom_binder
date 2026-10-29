"""Regression checks for evidence counting and conservative package identity."""
import json
import sqlite3
from pathlib import Path

import pytest
from http.client import IncompleteRead

from scripts import analyze_cve_poc_static as scan


def test_issue_is_candidate_not_confirmed_poc():
    row = scan.reference_signals([
        {"url": "https://github.com/acme/widget/issues/12"},
        {"url": "https://github.com/acme/widget/issues/12#issuecomment-1"},
        {"url": "https://github.com/acme/widget/commit/abcdef"},
        {"url": "https://github.com.evil.invalid/acme/widget/issues/1"},
        {"url": "https://github.com/acme/widget/pull/2"},
    ])
    assert row["github_issue_urls"] == ["https://github.com/acme/widget/issues/12"]
    assert len(row["commit_urls"]) == 1
    result = scan.classify(row, {})
    assert result["poc_static_candidate"] is True
    assert result["poc_reference_or_index_evidence"] is False
    assert result["evidence_class"] == "ISSUE_REFERENCE_ONLY"


def test_exploit_is_exact_reference_tag_not_description():
    row = scan.reference_signals([
        {"url": "https://example.org/exploit", "tags": ["Patch"]},
        {"url": "https://example.org/2", "tags": ["Exploit", "Patch"]},
    ])
    assert row["exploit_reference_urls"] == ["https://example.org/2"]
    assert scan.classify(row, {})["evidence_class"] == "EXPLOIT_REFERENCE"


def test_scoped_npm_and_explicit_maven_only():
    refs = [
        {"url": "https://www.npmjs.com/package/@scope/widget/v/1.0.0"},
        {"url": "https://registry.npmjs.org/%40scope%2Fwidget"},
        {"url": "https://mvnrepository.com/artifact/org.example/widget/1.0"},
        {"url": "https://github.com/acme/widget"},
    ]
    assert scan.package_coordinates(refs) == [("Maven", "org.example:widget"), ("npm", "@scope/widget")]
    assert scan.package_coordinates([{"url": "https://github.com/npm/widget"}]) == []


def test_indexes_bind_exact_cve_and_exclude_scanner_modules():
    ids = {"CVE-2024-1234", "CVE-2024-9999"}
    csv_text = 'id,file,codes\n1,exploits/test.py,CVE-2024-1234;CVE-2024-9999\n'
    result = scan.parse_exploitdb(csv_text, ids)
    assert set(result) == ids
    modules = {
        "scanner": {"type": "auxiliary", "references": ["CVE-2024-1234"], "path": "/modules/a.rb"},
        "exploit": {"type": "exploit", "references": ["CVE-2024-9999"], "path": "/modules/exploits/b.rb"},
    }
    assert set(scan.parse_metasploit(modules, ids)) == {"CVE-2024-9999"}
    readme = '### CVE-2024-1234 (date)\n- [a](https://github.com/a/poc)\n### CVE-2024-9999\nNo links\n'
    assert set(scan.parse_nomisec(readme, ids)) == {"CVE-2024-1234"}


def test_summary_deduplicates_cves_across_sources():
    a = scan.classify(scan.reference_signals([{"url": "https://x.test", "tags": ["Exploit"]}]), {"exploitdb": [{"url": "https://e.test"}]})
    b = scan.classify(scan.reference_signals([{"url": "https://github.com/a/b/issues/1"}]), {})
    d = scan.classify(scan.reference_signals([]), {})
    result = scan.summarize([a, b, d])
    assert result["total_cves"] == 3
    assert result["poc_static_candidate_cves"] == 2
    assert result["poc_reference_or_index_evidence_cves"] == 1
    assert result["issue_reference_only_cves"] == 1
    assert result["no_evidence_found_cves"] == 1


def test_registry_response_must_match_exact_coordinate():
    assert scan.validate_package("npm", "@scope/a", {"name": "a"})["status"] == "identity_mismatch"
    assert scan.validate_package("npm", "@scope/a", {"name": "@scope/a", "repository": {"url": "git+https://github.com/acme/a.git"}})["status"] == "confirmed"
    assert scan.validate_package("Maven", "org.example:a", {"response": {"docs": [{"g": "other", "a": "a"}]}})["status"] == "identity_mismatch"


def test_source_snapshot_mismatch_is_not_silently_counted(tmp_path):
    path = tmp_path / "source.sqlite"
    con = sqlite3.connect(path)
    con.executescript('CREATE TABLE source_snapshot_manifest(source_path TEXT,payload_sha256 TEXT);')
    con.execute('INSERT INTO source_snapshot_manifest VALUES(?,?)', ("/original/nvd.jsonl", "expected"))
    con.commit(); con.close()
    metadata = {"source_db": str(path), "nvd_jsonl": "/original/nvd.jsonl"}
    with pytest.raises(ValueError, match="snapshot"):
        scan.source_snapshot_check(metadata, "different")
    assert scan.source_snapshot_check(metadata, "expected")["status"] == "matched"


def test_api_cache_miss_and_budget_are_not_negative_evidence(tmp_path):
    client = scan.HttpCache(tmp_path / "http.sqlite", offline=True)
    assert client.get("https://registry.npmjs.org/a/latest")["status"] == "offline_cache_miss"
    client.offline = False
    client.github_budget = 0
    assert client.get("https://api.github.com/repos/acme/a")["status"] == "request_budget_exhausted"
    assert client.github_used == 0
    client.db.close()


def test_valid_indexes_with_zero_overlap_are_successful():
    bodies = {
        scan.INDEX_URLS["exploitdb"]: b'id,file,codes\n1,exploits/test.py,CVE-2020-1234\n',
        scan.INDEX_URLS["metasploit"]: json.dumps({"a": {"type": "exploit", "references": ["CVE-2020-1234"]}}).encode(),
        scan.INDEX_URLS["nomisec"]: b'### CVE-2020-1234\n- [a](https://github.com/a/poc)\n',
    }
    class Cache:
        def get(self, url):
            return {"status": "ok", "body": bodies[url]}
    indexes, reports = scan.fetch_indexes(Cache(), {"CVE-2024-1234"})
    assert all(r["status"] == "ok" and r["matched_cves"] == 0 for r in reports.values())
    assert not any(indexes.values())


def test_truncated_http_body_does_not_abort_census(tmp_path, monkeypatch):
    def interrupted(*args, **kwargs):
        raise IncompleteRead(b'partial', 100)
    monkeypatch.setattr(scan, "urlopen", interrupted)
    client = scan.HttpCache(tmp_path / "http.sqlite")
    assert client.get("https://registry.npmjs.org/a/latest")["status"] == "request_error"
    client.db.close()


def test_outputs_and_cache_cannot_overwrite_sources_or_hardlinks(tmp_path):
    db = tmp_path / "repo.sqlite"
    db.write_bytes(b'original database')
    alias = tmp_path / "alias.sqlite"
    alias.hardlink_to(db)
    with pytest.raises(ValueError):
        scan.validate_paths([db], alias, [])
    with pytest.raises(ValueError):
        scan.validate_paths([db], tmp_path / "cache.sqlite", [db])
    with pytest.raises(ValueError):
        scan.validate_paths([db], tmp_path / "cache.sqlite", [tmp_path / "cache.sqlite"])
    assert db.read_bytes() == b'original database'


def test_full_offline_run_preserves_missing_source_and_unknown_ecosystem(tmp_path):
    db = tmp_path / "repo.sqlite"
    source = tmp_path / "nvd.jsonl"
    con = sqlite3.connect(db)
    con.executescript('CREATE TABLE cve_info(cve_id TEXT PRIMARY KEY); CREATE TABLE build_metadata(key TEXT,value TEXT); CREATE TABLE repo_product_map(mapping_id INTEGER,repo_key TEXT,languages TEXT,product_key TEXT,vendor_key TEXT); CREATE TABLE repo2cve(cve_id TEXT,mapping_id INTEGER);')
    con.executemany('INSERT INTO cve_info VALUES(?)', [("CVE-2024-1234",), ("CVE-2024-9999",)])
    con.execute('INSERT INTO build_metadata VALUES(?,?)', ("nvd_jsonl", json.dumps(str(source))))
    con.commit(); con.close()
    source.write_text(json.dumps({"cve": {"id": "CVE-2024-1234", "references": [{"url": "https://github.com/acme/a/issues/1"}]}}) + '\n')
    out = tmp_path / "out"
    assert scan.main(["--db", str(db), "--output-dir", str(out), "--cache", str(tmp_path / "cache.sqlite"), "--offline"]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["total_cves"] == 2
    assert summary["missing_nvd_cves"] == 1
    assert summary["poc_static_candidate_cves"] == 1
    rows = [json.loads(x) for x in (out / "cves.jsonl").read_text().splitlines()]
    assert rows[1]["evidence_class"] == "SOURCE_MISSING"
    assert all(r["ecosystem_status"] == "unknown" for r in rows)
