#!/usr/bin/env python3
"""CVE-level, metadata-only PoC candidate census. Never executes collected code.

Input DB is read-only. Raw NVD references come from build_metadata.nvd_jsonl.
Outputs and HTTP cache are separate from the input. See guide_book/poc_static.md.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import threading
import time
from http.client import HTTPException
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
INDEX_URLS = {
    "exploitdb": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "metasploit": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
    "nomisec": "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def source_snapshot_check(metadata, actual_hash):
    path = metadata.get("source_db")
    if not path or not Path(path).is_file():
        return {"status": "manifest_unavailable"}
    with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("SELECT payload_sha256 FROM source_snapshot_manifest WHERE source_path=?", (metadata["nvd_jsonl"],)).fetchall()
    hashes = {r[0] for r in rows if r[0]}
    if not hashes:
        return {"status": "hash_unavailable"}
    if hashes != {actual_hash}:
        raise ValueError("NVD source snapshot SHA256 differs from the database build manifest")
    return {"status": "matched", "expected_sha256": actual_hash}


def validate_paths(sources, cache, outputs):
    def same(a, b):
        return a.resolve() == b.resolve() or (a.exists() and b.exists() and a.samefile(b))
    if any(same(cache, source) for source in sources):
        raise ValueError("HTTP cache must not overwrite an input source")
    if any(same(out, source) for out in outputs for source in [*sources, cache]):
        raise ValueError("Report paths must not overwrite an input source or HTTP cache")


def reference_signals(references):
    buckets = {k: set() for k in ("reference_urls", "exploit_reference_urls", "github_issue_urls", "github_repos", "commit_urls")}
    for ref in references:
        if not isinstance(ref, dict) or not isinstance(ref.get("url"), str):
            continue
        url = ref["url"]
        buckets["reference_urls"].add(url)
        if isinstance(ref.get("tags"), list) and "Exploit" in ref["tags"]:
            buckets["exploit_reference_urls"].add(url)
        try:
            u = urlsplit(url)
        except ValueError:
            continue
        if re.search(r"/(?:commit|commits|changeset|revision)/[0-9a-f]{6,64}(?:/|$)", u.path, re.I):
            buckets["commit_urls"].add(url)
        if u.hostname != "github.com":
            continue
        parts = u.path.strip("/").split("/")
        if len(parts) >= 2 and all(parts[:2]):
            buckets["github_repos"].add("/".join(parts[:2]).removesuffix(".git").lower())
        if len(parts) == 4 and parts[2] == "issues" and parts[3].isdigit():
            buckets["github_issue_urls"].add(urlunsplit(("https", "github.com", u.path.rstrip("/"), "", "")))
    return {key: sorted(value) for key, value in buckets.items()}


def package_coordinates(references):
    """Only explicit registry coordinates; never guess from a product/repo name."""
    found = set()
    for ref in references:
        try:
            u = urlsplit(ref.get("url", ""))
        except (ValueError, AttributeError):
            continue
        parts = unquote(u.path).strip("/").split("/")
        host = u.hostname
        if host in {"npmjs.com", "www.npmjs.com"} and len(parts) >= 2 and parts[0] == "package":
            name = "/".join(parts[1:3]) if parts[1].startswith("@") else parts[1]
            if re.fullmatch(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+", name):
                found.add(("npm", name))
        elif host == "registry.npmjs.org" and parts and parts[0]:
            name = "/".join(parts[:2]) if parts[0].startswith("@") else parts[0]
            if re.fullmatch(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+", name):
                found.add(("npm", name))
        elif host in {"mvnrepository.com", "search.maven.org", "central.sonatype.com"} and len(parts) >= 3 and parts[0] == "artifact":
            if all(re.fullmatch(r"[a-zA-Z0-9_.-]+", p) for p in parts[1:3]):
                found.add(("Maven", parts[1] + ":" + parts[2]))
    return sorted(found)


def parse_exploitdb(text, target_ids):
    rows = csv.DictReader(io.StringIO(text))
    if not {"id", "file", "codes"} <= set(rows.fieldnames or []):
        raise ValueError("Exploit-DB CSV has no expected columns")
    result = defaultdict(list)
    for row in rows:
        for cid in set(CVE_RE.findall(row["codes"] or "")) & target_ids:
            result[cid].append({"url": "https://www.exploit-db.com/exploits/" + row["id"], "artifact_path": row["file"]})
    return dict(result)


def parse_metasploit(modules, target_ids):
    if not isinstance(modules, dict):
        raise ValueError("Metasploit index must be an object")
    result = defaultdict(list)
    for name, module in modules.items():
        if not isinstance(module, dict) or module.get("type") != "exploit":
            continue
        for cid in set(CVE_RE.findall(json.dumps(module.get("references", [])))) & target_ids:
            result[cid].append({"module": name, "url": "https://github.com/rapid7/metasploit-framework/blob/master/" + module.get("path", "").lstrip("/")})
    return dict(result)


def parse_nomisec(text, target_ids):
    if not re.search(r"^### CVE-\d{4}-\d{4,}\b", text, re.M):
        raise ValueError("PoC-in-GitHub README has no CVE sections")
    result = defaultdict(list)
    cid = None
    for line in text.splitlines():
        if line.startswith("### "):
            m = re.match(r"### (CVE-\d{4}-\d{4,})\b", line)
            cid = m.group(1) if m and m.group(1) in target_ids else None
        if cid and line.startswith("- ["):
            for url in re.findall(r"\]\((https://github\.com/[^\s)]+)\)", line):
                result[cid].append({"url": url})
    return dict(result)


def classify(signals, indexes):
    indexed = any(indexes.values())
    exploit = bool(signals["exploit_reference_urls"])
    issue = bool(signals["github_issue_urls"])
    return {
        "has_exploit_reference": exploit,
        "has_github_issue_reference": issue,
        "has_poc_index_entry": indexed,
        "poc_reference_or_index_evidence": exploit or indexed,
        "poc_static_candidate": exploit or indexed or issue,
        "evidence_class": "POC_INDEXED" if indexed else "EXPLOIT_REFERENCE" if exploit else "ISSUE_REFERENCE_ONLY" if issue else "NO_EVIDENCE_FOUND",
        "execution_status": "NOT_RUN",
    }


def summarize(rows):
    return {
        "total_cves": len(rows),
        "exploit_reference_cves": sum(r["has_exploit_reference"] for r in rows),
        "github_issue_reference_cves": sum(r["has_github_issue_reference"] for r in rows),
        "exploit_or_issue_reference_cves": sum(r["has_exploit_reference"] or r["has_github_issue_reference"] for r in rows),
        "exploit_and_issue_reference_cves": sum(r["has_exploit_reference"] and r["has_github_issue_reference"] for r in rows),
        "poc_index_entry_cves": sum(r["has_poc_index_entry"] for r in rows),
        "poc_reference_or_index_evidence_cves": sum(r["poc_reference_or_index_evidence"] for r in rows),
        "poc_static_candidate_cves": sum(r["poc_static_candidate"] for r in rows),
        "issue_reference_only_cves": sum(r["evidence_class"] == "ISSUE_REFERENCE_ONLY" for r in rows),
        "no_evidence_found_cves": sum(r["evidence_class"] == "NO_EVIDENCE_FOUND" for r in rows),
        "evidence_class_counts": dict(Counter(r["evidence_class"] for r in rows)),
    }


def validate_package(ecosystem, name, data):
    if ecosystem == "npm":
        valid = data.get("name") == name
        metadata = {key: data.get(key) for key in ("name", "repository", "homepage", "dist-tags")}
    else:
        group, artifact = name.split(":", 1)
        docs = data.get("response", {}).get("docs", [])
        matches = [d for d in docs if d.get("g") == group and d.get("a") == artifact]
        valid = bool(matches)
        metadata = {"matches": matches}
    return {"status": "confirmed" if valid else "identity_mismatch", "metadata": metadata}


class HttpCache:
    """Persistent successful responses. Errors remain observable and retryable."""
    def __init__(self, path, offline=False, timeout=15, github_budget=45, max_age_hours=24):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS response(url TEXT PRIMARY KEY, fetched_at TEXT, fetched_epoch REAL, body BLOB, sha256 TEXT)")
        self.db.commit()
        self.lock = threading.Lock()
        self.offline, self.timeout = offline, timeout
        self.max_age = max_age_hours * 3600
        self.github_budget = github_budget
        self.github_used = 0
        self.github_blocked = False
        self.token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    def get(self, url):
        with self.lock:
            row = self.db.execute("SELECT fetched_at,fetched_epoch,body,sha256 FROM response WHERE url=?", (url,)).fetchone()
        if row and (self.offline or time.time() - row[1] <= self.max_age):
            return {"status": "ok", "url": url, "fetched_at": row[0], "sha256": row[3], "cached": True, "body": row[2]}
        if self.offline:
            return {"status": "offline_cache_miss", "url": url}
        github = urlsplit(url).hostname == "api.github.com"
        if github:
            with self.lock:
                if self.github_blocked:
                    return {"status": "rate_limited", "url": url}
                if self.github_used >= self.github_budget:
                    return {"status": "request_budget_exhausted", "url": url}
                self.github_used += 1
        headers = {"User-Agent": "CVE-static-evidence-census/1.0", "Accept": "application/json"}
        if github and self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            with urlopen(Request(url, headers=headers), timeout=self.timeout) as response:
                body = response.read(32 * 1024 * 1024 + 1)
            if len(body) > 32 * 1024 * 1024:
                return {"status": "response_too_large", "url": url}
            now = utc_now()
            sha = hashlib.sha256(body).hexdigest()
            with self.lock:
                self.db.execute("INSERT OR REPLACE INTO response VALUES(?,?,?,?,?)", (url, now, time.time(), body, sha))
                self.db.commit()
            return {"status": "ok", "url": url, "fetched_at": now, "sha256": sha, "cached": False, "body": body}
        except HTTPError as exc:
            limited = exc.code == 429 or (github and exc.code == 403 and (exc.headers.get("X-RateLimit-Remaining") == "0" or exc.headers.get("Retry-After")))
            if github and limited:
                with self.lock:
                    self.github_blocked = True
            return {"status": "rate_limited" if limited else "http_error", "http_status": exc.code, "url": url}
        except (OSError, ValueError, HTTPException) as exc:
            return {"status": "request_error", "error": str(exc), "url": url}


def fetch_indexes(client, ids):
    indexes, reports = {}, {}
    for name, url in INDEX_URLS.items():
        response = client.get(url)
        report = {k: v for k, v in response.items() if k != "body"}
        indexes[name] = {}
        if response["status"] == "ok":
            try:
                text = response["body"].decode("utf-8-sig")
                parsed = parse_exploitdb(text, ids) if name == "exploitdb" else parse_metasploit(json.loads(text), ids) if name == "metasploit" else parse_nomisec(text, ids)
                indexes[name] = parsed
                report["matched_cves"] = len(parsed)
            except (ValueError, KeyError, TypeError) as exc:
                report.update(status="parse_error", error=str(exc))
        reports[name] = report
        print(json.dumps({"stage": "index", "source": name, **report}), flush=True)
    return indexes, reports


def enrich(client, packages, repos, workers):
    tasks = []
    for ecosystem, name in sorted(packages):
        if ecosystem == "npm":
            url = "https://registry.npmjs.org/" + quote(name, safe="") + "/latest"
        else:
            group, artifact = name.split(":", 1)
            url = "https://central.sonatype.com/solrsearch/select?" + urlencode({"q": f'g:"{group}" AND a:"{artifact}"', "rows": 20, "wt": "json"})
        tasks.append((ecosystem, name, url))
    # Deterministic priority: repositories associated with most CVEs first.
    for repo in sorted(repos, key=lambda r: (-repos[r], r)):
        tasks.append(("GitHub", repo, "https://api.github.com/repos/" + repo))

    def fetch(task):
        ecosystem, name, url = task
        response = client.get(url)
        result = {"ecosystem": ecosystem, "coordinate": name, **{k: v for k, v in response.items() if k != "body"}}
        if response["status"] == "ok":
            try:
                data = json.loads(response["body"])
                if ecosystem == "GitHub":
                    valid = isinstance(data.get("full_name"), str) and data["full_name"].lower() == name.lower()
                    result.update(status="confirmed" if valid else "identity_mismatch", metadata={k: data.get(k) for k in ("full_name", "language", "html_url", "archived", "default_branch")})
                else:
                    result.update(validate_package(ecosystem, name, data))
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                result.update(status="parse_error", error=str(exc))
        return (ecosystem, name), result

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for i, (key, result) in enumerate(pool.map(fetch, tasks), 1):
            results[key] = result
            if i % 100 == 0 or i == len(tasks):
                print(json.dumps({"stage": "ecosystem_api", "completed": i, "total": len(tasks)}), flush=True)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("workspace/repo_cve.sqlite"))
    parser.add_argument("--nvd-jsonl", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("workspace") / ("poc_static_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    parser.add_argument("--cache", type=Path, default=Path("workspace/poc_static_http_cache.sqlite"))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--github-max-requests", type=int, default=45, help="New GitHub requests per run; cache hits are free. Increase with authenticated quota.")
    parser.add_argument("--cache-max-age-hours", type=float, default=24)
    args = parser.parse_args(argv)
    if args.workers < 1 or args.timeout <= 0 or args.github_max_requests < 0 or args.cache_max_age_hours < 0:
        parser.error("invalid workers/timeout/budget/cache age")
    output_paths = [args.output_dir / name for name in ("summary.json", "cves.jsonl", "cves.csv", "api_results.jsonl")]
    try:
        validate_paths([args.db], args.cache, [*output_paths, args.output_dir])
    except ValueError as exc:
        parser.error(str(exc))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if any(path.exists() for path in output_paths):
        parser.error("output directory already has a report; choose a fresh directory")
    db = sqlite3.connect(args.db.resolve().as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    metadata = {r[0]: json.loads(r[1]) for r in db.execute("SELECT key,value FROM build_metadata")}
    source = args.nvd_jsonl or Path(metadata["nvd_jsonl"])
    sources = [args.db, source]
    if metadata.get("source_db"):
        sources.append(Path(metadata["source_db"]))
    try:
        validate_paths(sources, args.cache, [*output_paths, args.output_dir])
    except ValueError as exc:
        parser.error(str(exc))
    rows = {r["cve_id"]: dict(r) for r in db.execute("SELECT * FROM cve_info ORDER BY cve_id")}
    mapped = defaultdict(list)
    for r in db.execute("SELECT DISTINCT r.cve_id,p.repo_key,p.languages,p.vendor_key,p.product_key FROM repo2cve r JOIN repo_product_map p ON p.mapping_id=r.mapping_id"):
        mapped[r["cve_id"]].append({k: r[k] for k in r.keys() if k != "cve_id"})
    db.close()
    ids = set(rows)
    seen = set()
    source_hash = hashlib.sha256()
    for row in rows.values():
        row.update(nvd_source_found=False, mapped_products=mapped[row["cve_id"]], references=[], package_coordinates=[])
    print(json.dumps({"stage": "nvd_scan_start", "db_cves": len(ids), "source": str(source)}), flush=True)
    with source.open("rb") as handle:
        for line_number, line in enumerate(handle, 1):
            source_hash.update(line)
            if line_number % 100000 == 0:
                print(json.dumps({"stage": "nvd_scan", "source_lines": line_number, "found": len(seen)}), flush=True)
            record = json.loads(line)
            cve = record.get("cve", record)
            cid = cve.get("id")
            if cid not in ids:
                continue
            if cid in seen:
                raise ValueError(f"Duplicate target CVE in NVD source: {cid}")
            seen.add(cid)
            references = cve.get("references", [])
            rows[cid].update(nvd_source_found=True, references=references, package_coordinates=package_coordinates(references))
    snapshot_check = source_snapshot_check(metadata, source_hash.hexdigest())
    print(json.dumps({"stage": "nvd_parsed", "db_cves": len(ids), "found": len(seen), "snapshot_check": snapshot_check}), flush=True)
    client = HttpCache(args.cache, args.offline, args.timeout, args.github_max_requests, args.cache_max_age_hours)
    indexes, index_reports = fetch_indexes(client, ids)
    package_set, repo_counts = set(), Counter()
    for cid, row in rows.items():
        signals = reference_signals(row["references"])
        row.update(signals)
        row["poc_indexes"] = {name: data[cid] for name, data in indexes.items() if cid in data}
        row.update(classify(signals, row["poc_indexes"]))
        if not row["nvd_source_found"]:
            row["evidence_class"] = "INDEX_ONLY_SOURCE_MISSING" if row["has_poc_index_entry"] else "SOURCE_MISSING"
        package_set.update(tuple(x) for x in row["package_coordinates"])
        repos = {r["repo_key"].replace("@", "/", 1).lower() for r in row["mapped_products"]}
        repo_counts.update(repos)
    print(json.dumps({"stage": "ecosystem_candidates", "explicit_packages": len(package_set), "mapped_github_repos": len(repo_counts)}), flush=True)
    api_results = enrich(client, package_set, repo_counts, args.workers)
    with (args.output_dir / "api_results.jsonl").open("w") as handle:
        for key in sorted(api_results):
            handle.write(json.dumps(api_results[key], ensure_ascii=False) + "\n")
    ecosystem_counts = Counter()
    for row in rows.values():
        packages = [api_results[tuple(p)] for p in row["package_coordinates"]]
        row["package_api_evidence"] = packages
        row["ecosystems"] = sorted({p["ecosystem"] for p in packages if p["status"] == "confirmed"})
        row["ecosystem_status"] = "api_confirmed" if row["ecosystems"] else "unconfirmed" if packages else "unknown"
        # GitHub is a source host, not a package ecosystem.
        row["repo_metadata_keys"] = sorted({p["repo_key"].replace("@", "/", 1).lower() for p in row["mapped_products"]})
        ecosystem_counts.update(row["ecosystems"])
    values = list(rows.values())
    summary = {
        **summarize(values),
        "schema_version": 1,
        "generated_at": utc_now(),
        "db": str(args.db.resolve()), "db_built_at": metadata.get("built_at"),
        "source_jsonl": str(source.resolve()), "source_sha256": source_hash.hexdigest(),
        "matched_nvd_cves": len(seen), "missing_nvd_cves": len(ids - seen),
        "index_sources": index_reports,
        "all_configured_indexes_loaded": all(r["status"] == "ok" for r in index_reports.values()),
        "api_result_counts": {ecosystem: dict(Counter(r["status"] for (e, _), r in api_results.items() if e == ecosystem)) for ecosystem in ("npm", "Maven", "GitHub")},
        "api_confirmed_ecosystem_cves": dict(ecosystem_counts),
        "ecosystem_status_cves": dict(Counter(r["ecosystem_status"] for r in values)),
        "github_requests_used": client.github_used,
        "run_config": {"offline": args.offline, "workers": args.workers, "timeout_seconds": args.timeout, "github_max_requests": args.github_max_requests, "cache_max_age_hours": args.cache_max_age_hours},
        "input_db_opened_read_only": True,
        "counting_policy": {
            "poc_reference_or_index_evidence": "NVD Exploit reference OR public PoC/exploit index mapping; not a verified artifact",
            "poc_static_candidate": "Exploit reference OR public index mapping OR GitHub Issue reference; issue-only is a discovery candidate",
            "ecosystem": "reference-associated registry coordinate with matching API response; not proof of affected package identity; source languages/host do not imply package ecosystem",
            "absence": "NO_EVIDENCE_FOUND is not proof of no PoC; source/API failures are separate",
            "payload_oracle": "not extracted; no collected code is executed",
        },
    }
    summary["source_snapshot_check"] = snapshot_check
    with (args.output_dir / "cves.jsonl").open("w") as handle:
        for row in values:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    fields = ["cve_id", "nvd_source_found", "has_exploit_reference", "has_github_issue_reference", "has_poc_index_entry", "poc_reference_or_index_evidence", "poc_static_candidate", "evidence_class", "ecosystems", "ecosystem_status", "execution_status"]
    with (args.output_dir / "cves.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in values:
            writer.writerow({**row, "ecosystems": ";".join(row["ecosystems"])})
    (args.output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    client.db.close()
    print(json.dumps({"stage": "complete", "output_dir": str(args.output_dir.resolve()), **summary}, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
