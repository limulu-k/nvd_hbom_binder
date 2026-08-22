#!/usr/bin/env python3
"""Run Clovery over the C corpus one repository at a time.

Clovery keeps every clone and every intermediate under ``Evalu/``, so running
it across hundreds of projects would need hundreds of GB at once.  This drives
it as a cycle instead:

    clone -> steps 1..7 -> harvest tagCombi -> purge everything -> next repo

so peak disk is one repository plus its intermediates, and progress survives
interruption.

Targets come from the applicability DB built by ``scripts.nvd_normalization``. Each corpus
repository is resolved to DB products (exact pair, NVD's ``<name>_project``
convention, then strict identity-cluster expansion), and its CVEs are read from
``current_binding`` - so the work set is exactly what the DB binds, not whatever
a full NVD scan turns up.

The DB does not materialize reference URLs, and Clovery needs the patch commit.
``raw_cve`` stores a byte offset/length index into the snapshot the DB was built
from, so those specific records are seeked directly out of the source JSONL
instead of re-parsing the whole corpus.

Usage
-----
    # 1. build the work plan (DB-driven; writes a feed per repo)
    python scripts/clovery/clovery_cycle.py plan

    # 2. run the cycle (resumable; Ctrl-C and re-run to continue)
    python scripts/clovery/clovery_cycle.py run --limit 20

    # 3. see where it got to
    python scripts/clovery/clovery_cycle.py status

``run`` needs a Joern server started **from the Clovery directory**, otherwise
its ``workspace/`` projects do not resolve:

    cd clovery && joern --server --server-host localhost --server-port 8080 \
        --server-auth-username username --server-auth-password password
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import socket
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from nvd2_to_clovery_feed import (  # noqa: E402
    GH_REPO,
    GITLIST,
    load_repo_corpus,
    to_v11_item,
)
from clovery_resilience import (  # noqa: E402
    QUERY_TIMEOUT_EXIT,
    RECYCLE_EXIT,
    abandoned_functions,
    set_ledger_dir,
)
from fixed_version_from_commit import GitError, analyse_feed  # noqa: E402
from verify_version_range import verify_repo  # noqa: E402
from recover_patch_commits import build_validated_feed, osv_target_hints  # noqa: E402
from nvd_normalization.rules import normalize_key  # noqa: E402

DEFAULT_CLOVERY = Path(
    os.environ.get("CLOVERY_DIR", str(REPO_ROOT.parent / "clovery"))
).expanduser()
DEFAULT_CORPUS = REPO_ROOT / "git" / "sample_c_git.txt"
DEFAULT_WORK = REPO_ROOT / "workspace" / "clovery"
DEFAULT_DB_GLOB = "nvd_applicability_v*.sqlite"

# Everything Clovery writes per run, relative to Evalu/.  Purged between repos
# so the next repository starts from a clean state (tagInfo in particular is
# skipped when a stale file already exists).
INTERMEDIATE_DIRS = (
    "diffs",
    "clones",
    "vulFunc",
    "vulFuncs",
    "newFunc",
    "patFunc",
    "CombiPatchFunc",
    "Joern_result",
    "Lineage",
    # Step 5's per-entry completion markers. Purged with Lineage and never
    # apart from it: a marker that outlives the lineage it vouches for makes
    # the entry skip and produce nothing.
    "LineageDone",
    "tagInfo",
    "tagCombi",
    "tagCombi_allSafe",
    "garbage",
)
HARVEST_DIRS = ("tagCombi", "tagCombi_allSafe")

# Where a CVE has to appear to have survived each stage, and the marker step 7
# writes for CVEs no function of which produced a verdict.
COVERAGE_STAGES: tuple[tuple[str, str], ...] = (
    ("with_diff", "diffs"),
    ("with_functions", "CombiPatchFunc"),
    ("with_tag_info", "tagInfo"),
)
UNABLE_MARKER = "tagCombiStep_Unable_tag_extract.txt"
# Whose intermediates currently sit under Evalu/. `--retry-failed` may only
# resume on top of them when they belong to the repository being retried, and
# a cycle for any other repository in between has already replaced them.
CYCLE_MARKER = ".cycle_pack"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

STEPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("1_collect", ("1_cve_collector.py", "-direct", "{feed}")),
    ("2_getFile", ("2_clovery.py", "-getFile", "GETFILE")),
    ("3_getLine", ("3_clovery_cpg.py", "-getLine", "GETLINE")),
    ("4_getCPG", ("3_clovery_cpg.py", "-I_getCPG", "I_GETCPG")),
    ("5_history", ("3_clovery_cpg.py", "-II_getHistory", "II_GETHISTORY")),
    ("6_checkTag", ("3_clovery_cpg.py", "-III_2_checkTag", "III_2_CHECKTAG")),
    ("7_tagCombi", ("3_clovery_cpg.py", "-IV_TagCombi", "IV_TAGCOMBI")),
)


class CycleError(RuntimeError):
    pass


# --------------------------------------------------------------------------- plan


def default_database() -> Path:
    candidates = sorted(
        (REPO_ROOT / "workspace").glob(DEFAULT_DB_GLOB),
        key=lambda path: (
            int(match.group(1)) if (match := re.search(r"_v(\d+)", path.name)) else 0,
            path.name,
        ),
    )
    if not candidates:
        raise CycleError(f"no {DEFAULT_DB_GLOB} under {REPO_ROOT / 'workspace'}")
    return candidates[-1]


def pack_name(owner: str, name: str) -> str:
    """Clovery names a checkout ``owner##repo``; mirror that exactly."""
    return f"{owner}##{name}"


def resolve_repo_products(
    conn: sqlite3.Connection, corpus: Mapping[tuple[str, str], str], *, repo_name_match: bool
) -> dict[tuple[str, str], tuple[list[int], str]]:
    """Repo -> the DB products that repo denotes, via the applicability DB.

    Three tiers, most conservative first, mirroring how the DB actually spells
    things: an exact ``owner/name`` pair, NVD's ``<name>_project`` vendor
    convention, and - only with ``repo_name_match`` - any vendor publishing that
    product name.  The last tier is off by default because generic repo names
    ("linux", "core", "server") collide with large unrelated products.

    Seeds are then widened along strict accepted identity clusters, since
    ``product_entity`` deliberately keeps one row per observed spelling and the
    merged view lives in ``identity_cluster``.
    """

    by_pair: dict[tuple[str, str], list[int]] = defaultdict(list)
    by_product: dict[str, list[int]] = defaultdict(list)
    for product_id, vendor_key, product_key in conn.execute(
        "SELECT product_id,vendor_key,product_key FROM product_entity"
    ):
        by_pair[(vendor_key, product_key)].append(product_id)
        by_product[product_key].append(product_id)

    cluster_of: dict[int, int] = {}
    strict_members: dict[int, list[int]] = defaultdict(list)
    for cluster_id, product_id, strict in conn.execute(
        """SELECT m.cluster_id,m.product_id,
                  (m.strict_eligible AND c.strict_eligible AND c.review_state='ok')
           FROM identity_cluster_member m JOIN identity_cluster c USING(cluster_id)
           WHERE c.scope_kind='product' AND m.product_id IS NOT NULL"""
    ):
        cluster_of[product_id] = cluster_id
        if strict:
            strict_members[cluster_id].append(product_id)

    resolved: dict[tuple[str, str], tuple[list[int], str]] = {}
    for key in corpus:
        owner, name = key
        if (owner, name) in by_pair:
            seeds, tier = by_pair[(owner, name)], "exact_pair"
        elif (f"{name}_project", name) in by_pair:
            seeds, tier = by_pair[(f"{name}_project", name)], "vendor_project_suffix"
        elif repo_name_match and name in by_product:
            seeds, tier = by_product[name], "product_name_only"
        else:
            continue
        widened = set(seeds)
        for product_id in seeds:
            cluster_id = cluster_of.get(product_id)
            if cluster_id is not None:
                widened.update(strict_members.get(cluster_id, ()))
        resolved[key] = (sorted(widened), tier)
    return resolved


def cves_for_products(
    conn: sqlite3.Connection, product_ids: Sequence[int]
) -> list[str]:
    conn.execute("DELETE FROM cycle_scope")
    conn.executemany(
        "INSERT OR IGNORE INTO cycle_scope VALUES(?)", [(p,) for p in product_ids]
    )
    return [
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT b.cve_id FROM current_binding b JOIN cycle_scope s USING(product_id)"
        )
    ]


def source_jsonl(conn: sqlite3.Connection, override: Path | None) -> Path:
    """The snapshot the DB's ``raw_cve`` byte offsets actually index.

    Every read here is a seek to an offset recorded when the DB was built, so a
    file that merely sits at the recorded *path* is not good enough: refreshing
    the corpus (``01-1_update_nvd_data.sh``) shifts every offset after the first
    changed record, and the seek then lands mid-record. That failure is silent -
    the JSON fails to parse and the record is skipped - so it surfaces as CVEs
    quietly going missing rather than as an error. The manifest records the
    snapshot's size; check it, and prefer whichever candidate matches.
    """

    row = conn.execute(
        """SELECT source_path, byte_size FROM source_snapshot_manifest
           ORDER BY snapshot_id DESC LIMIT 1"""
    ).fetchone()
    recorded = Path(row[0]) if row and row[0] else None
    expected = row[1] if row else None

    if override:
        if expected and override.exists() and override.stat().st_size != expected:
            print(f"    warning: --source-jsonl {override} is "
                  f"{override.stat().st_size} B, manifest recorded {expected} B; "
                  "byte offsets will not line up", flush=True)
        return override

    # The manifest records the path used at build time, which may not exist on
    # this machine; the copy alongside this checkout is the other candidate.
    candidates = [path for path in (recorded, REPO_ROOT / "data" / "nvd-cves.current.jsonl")
                  if path and path.exists()]
    if not candidates:
        raise CycleError(
            f"source JSONL not found (manifest says {recorded}); pass --source-jsonl"
        )
    if expected:
        for candidate in candidates:
            if candidate.stat().st_size == expected:
                return candidate
        sizes = ", ".join(f"{path} = {path.stat().st_size} B" for path in candidates)
        raise CycleError(
            f"source JSONL does not match the snapshot the DB indexes "
            f"(manifest: {expected} B; {sizes}). The offsets are stale, so "
            "records would be read from the wrong bytes. Restore that snapshot "
            "or pass --source-jsonl."
        )
    return candidates[0]


def read_cve_records(
    conn: sqlite3.Connection, cve_ids: Iterable[str], jsonl: Path
) -> dict[str, Mapping[str, Any]]:
    """Read just these CVEs out of the source, using raw_cve byte offsets.

    The DB stores an offset/length index into the snapshot it was built from, so
    the records Clovery needs can be seeked directly instead of re-parsing the
    whole NVD corpus.
    """

    wanted = sorted(set(cve_ids))
    if not wanted:
        return {}
    conn.execute("DELETE FROM cycle_cves")
    conn.executemany("INSERT OR IGNORE INTO cycle_cves VALUES(?)", [(c,) for c in wanted])
    rows = conn.execute(
        """SELECT r.cve_id, r.byte_offset, r.byte_length
           FROM raw_cve r JOIN cycle_cves c ON c.cve_id = r.cve_id
           ORDER BY r.byte_offset"""
    ).fetchall()

    out: dict[str, Mapping[str, Any]] = {}
    with jsonl.open("rb") as handle:
        for cve_id, offset, length in rows:
            handle.seek(offset)
            try:
                document = json.loads(handle.read(length))
            except json.JSONDecodeError:
                continue
            node = document.get("cve", document)
            if isinstance(node, Mapping) and node.get("id"):
                out[cve_id] = node
    return out


def eligible_urls_for_repo(
    cve: Mapping[str, Any], owner: str, name: str
) -> list[str]:
    """Reference URLs Clovery accepts, restricted to this repository.

    A CVE routinely references several projects (advisories, forks, PoCs); only
    a commit in this repo can be turned into its patch functions.
    """
    urls = []
    for reference in cve.get("references") or []:
        url = str(reference.get("url") or "")
        lowered = url.lower()
        if not any(host in lowered for host in GITLIST):
            continue
        if "commit" not in url:
            continue
        match = GH_REPO.search(url)
        if not match:
            continue
        repo_name = match.group(2)
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        if (normalize_key(match.group(1)), normalize_key(repo_name)) != (owner, name):
            continue
        if url not in urls:
            urls.append(url)
    return urls


def build_feed(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "CVE_data_type": "CVE",
        "CVE_data_format": "MITRE",
        "CVE_data_version": "4.0",
        "CVE_data_numberOfCVEs": str(len(items)),
        "CVE_Items": list(items),
    }


def discover_osv_dir(
    source: Path, explicit: Path | None
) -> Path | None:
    if explicit is not None:
        return explicit if explicit.is_dir() else None
    sibling = source.parent / "osv"
    return sibling if sibling.is_dir() else None


def cmd_plan(args: argparse.Namespace) -> int:
    corpus_labels: dict[tuple[str, str], str] = {}
    for line in args.corpus.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        owner, _, name = line.partition("@")
        corpus_labels[(normalize_key(owner), normalize_key(name or owner))] = line
    load_repo_corpus(args.corpus)  # validates the file shape
    print(f"corpus repos: {len(corpus_labels)}")

    database = args.db or default_database()
    conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    conn.execute("CREATE TEMP TABLE cycle_scope(product_id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TEMP TABLE cycle_cves(cve_id TEXT PRIMARY KEY)")

    resolved = resolve_repo_products(
        conn, corpus_labels, repo_name_match=args.repo_name_match
    )
    print(f"DB {database.name}: {len(resolved)} corpus repos resolve to a product")

    jsonl = source_jsonl(conn, args.source_jsonl)
    print(f"reference source: {jsonl}")
    osv_dir = discover_osv_dir(jsonl, args.osv_dir)
    print(f"OSV source: {osv_dir if osv_dir else 'unavailable'}")

    # Read bindings once. Calling cves_for_products() per repository makes the
    # current_binding view and its published-revision join execute 1,176 times.
    # The same product can also belong to several strict identity expansions,
    # so cache the source records across every target as well.
    all_product_ids = sorted(
        {product_id for product_ids, _ in resolved.values() for product_id in product_ids}
    )
    conn.execute("DELETE FROM cycle_scope")
    conn.executemany(
        "INSERT OR IGNORE INTO cycle_scope VALUES(?)",
        [(product_id,) for product_id in all_product_ids],
    )
    cves_by_product: dict[int, set[str]] = defaultdict(set)
    for product_id, cve_id in conn.execute(
        """SELECT b.product_id,b.cve_id
           FROM current_binding b JOIN cycle_scope s USING(product_id)"""
    ):
        cves_by_product[int(product_id)].add(str(cve_id))
    bound_by_repo = {
        key: sorted(
            {cve for product_id in product_ids for cve in cves_by_product[product_id]}
        )
        for key, (product_ids, _) in resolved.items()
    }
    all_bound_cves = {
        cve for cves in bound_by_repo.values() for cve in cves
    }
    all_records = read_cve_records(conn, all_bound_cves, jsonl)

    feeds_dir = args.work / "feeds"
    feeds_dir.mkdir(parents=True, exist_ok=True)
    for stale in feeds_dir.glob("*.json"):
        stale.unlink()

    targets = []
    no_patch = 0
    direct_repo_count = 0
    osv_repo_count = 0
    for key, (product_ids, tier) in sorted(resolved.items()):
        label = corpus_labels[key]
        owner, _, name = label.partition("@")
        owner_key, name_key = key

        bound_cves = bound_by_repo[key]
        if not bound_cves:
            continue
        records = {
            cve_id: all_records[cve_id]
            for cve_id in bound_cves
            if cve_id in all_records
        }

        items = []
        direct_cves: set[str] = set()
        osv_cves: set[str] = set()
        for cve_id in sorted(records):
            urls = eligible_urls_for_repo(records[cve_id], owner_key, name_key)
            if urls:
                direct_cves.add(cve_id)
            hints = osv_target_hints(
                cve_id, owner, name or owner, osv_dir
            )
            hint_urls = [
                str(candidate["url"])
                for candidate in hints
                if candidate.get("url")
            ]
            if hint_urls:
                osv_cves.add(cve_id)
            candidate_urls = list(dict.fromkeys(urls + hint_urls))
            if candidate_urls:
                items.append(
                    to_v11_item(records[cve_id], candidate_urls)
                )
        if not items:
            no_patch += 1
            continue
        if len(items) < args.min_cves:
            continue
        if direct_cves:
            direct_repo_count += 1
        if osv_cves:
            osv_repo_count += 1

        pack = pack_name(owner, name or owner)
        feed_path = feeds_dir / f"{pack}.json"
        feed_path.write_text(
            json.dumps(build_feed(items)), encoding="utf-8"
        )
        try:
            stored_feed = str(feed_path.relative_to(REPO_ROOT))
        except ValueError:
            stored_feed = str(feed_path)
        cve_ids = [item["cve"]["CVE_data_meta"]["ID"] for item in items]
        targets.append(
            {
                "repo": label,
                "owner": owner,
                "name": name or owner,
                "pack": pack,
                "identity_tier": tier,
                "product_ids": product_ids,
                "cve_count": len(cve_ids),
                "direct_cve_count": len(direct_cves),
                "osv_candidate_cve_count": len(osv_cves),
                "db_cve_count": len(bound_cves),
                "cves": sorted(cve_ids),
                "db_cves": sorted(bound_cves),
                "feed": stored_feed,
            }
        )
    conn.close()
    print(
        f"{no_patch} resolved repos have DB CVEs but no direct/OSV patch hint"
    )

    targets.sort(key=lambda item: (-item["cve_count"], -item["db_cve_count"], item["repo"]))
    candidate_pairs = sum(t["cve_count"] for t in targets)
    bound_pairs = sum(t["db_cve_count"] for t in targets)
    distinct_candidates = {cve for target in targets for cve in target["cves"]}
    distinct_bound = {cve for target in targets for cve in target["db_cves"]}
    plan_path = args.work / "targets.json"
    plan_path.write_text(
        json.dumps(
            {
                "database": str(database),
                "corpus": str(args.corpus),
                "repo_count": len(targets),
                "cve_count": candidate_pairs,
                "distinct_cve_count": len(distinct_candidates),
                "db_cve_count": bound_pairs,
                "db_distinct_cve_count": len(distinct_bound),
                "direct_repo_count": direct_repo_count,
                "osv_candidate_repo_count": osv_repo_count,
                "osv_dir": str(osv_dir) if osv_dir else None,
                "targets": targets,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        f"\nplan: {len(targets)} repos, {candidate_pairs} repo-CVE candidates "
        f"({len(distinct_candidates)} distinct CVE); {bound_pairs} bound repo-CVE "
        f"pairs ({len(distinct_bound)} distinct CVE)"
    )
    print(
        f"direct-reference repos: {direct_repo_count}; "
        f"OSV-hint repos: {osv_repo_count}"
    )
    print(f"written: {plan_path}")
    print("\ntop 10 targets:")
    for target in targets[:10]:
        print(f"  {target['db_cve_count']:>5} db / {target['cve_count']:>5} cve  {target['repo']}")
    return 0


# ---------------------------------------------------------------------------- run


def load_state(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"done": {}, "failed": {}, "skipped": {}}


def save_state(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temporary.replace(path)


def joern_is_up(host: str, port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(2)
        return probe.connect_ex((host, port)) == 0


def stop_joern(host: str, port: int, *, wait: int = 60) -> bool:
    """Stop the Joern server so its project store can be reset."""
    subprocess.run(
        ["pkill", "-f", "io.joern.joerncli.console.ReplBridge"],
        check=False,
        capture_output=True,
    )
    for _ in range(wait):
        if not joern_is_up(host, port):
            return True
        time.sleep(1)
    return False


def start_joern(command: str, clovery: Path, host: str, port: int, *, wait: int = 600) -> bool:
    """Start Joern from the Clovery directory so its workspace/ resolves."""
    log = clovery.parent / "workspace" / "clovery" / "logs" / "joern.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        subprocess.Popen(
            [
                command,
                "--server",
                "--server-host",
                host,
                "--server-port",
                str(port),
                "--server-auth-username",
                "username",
                "--server-auth-password",
                "password",
            ],
            cwd=clovery,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    for _ in range(wait):
        if joern_is_up(host, port):
            return True
        time.sleep(1)
    return False


def recycle_joern(args: argparse.Namespace) -> bool:
    """Restart Joern with an empty project store.

    Completed function projects are deleted, but the long-lived Scala REPL and
    JVM still retain compiler/heap state. Restarting between repositories and
    periodically within step 4 resets both, while clearing any project left by
    an interrupted query.
    """
    if not args.joern_cmd:
        return True
    print("    joern: restarting with a clean workspace", flush=True)
    if not stop_joern(args.joern_host, args.joern_port):
        print("    joern: did not stop; leaving the existing server", flush=True)
        return joern_is_up(args.joern_host, args.joern_port)
    removed = purge_joern_workspace(args.clovery)
    if not start_joern(args.joern_cmd, args.clovery, args.joern_host, args.joern_port):
        print("    joern: failed to restart", flush=True)
        return False
    print(f"    joern: up again ({removed} project(s) dropped)", flush=True)
    return True


def purge(clovery: Path) -> None:
    """Delete Clovery's per-run artifacts so the next repository starts clean.

    ``clovery/workspace`` is deliberately left alone: that is Joern's project
    store, and the server holds it open. Removing it under a live server leaves
    the next ``importCode`` hanging. Use ``purge_joern_workspace`` while the
    server is stopped instead.
    """

    evalu = clovery / "Evalu"
    for name in INTERMEDIATE_DIRS:
        target = evalu / name
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True, exist_ok=True)


def purge_joern_workspace(clovery: Path) -> int:
    """Drop Joern's accumulated projects. Only safe with the server stopped."""

    workspace = clovery / "workspace"
    if not workspace.exists():
        return 0
    removed = 0
    for project in workspace.iterdir():
        if project.is_dir():
            shutil.rmtree(project, ignore_errors=True)
            removed += 1
    return removed


def directory_size_gb(path: Path) -> float:
    total = 0
    for root, _, files in os.walk(path, onerror=lambda _: None):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total / (1024 ** 3)


def run_step(
    clovery: Path,
    script_args: Sequence[str],
    *,
    env: Mapping[str, str],
    log: Path,
    timeout: int,
    python: str,
) -> tuple[bool, str]:
    command = [python, *script_args]
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"\n$ {' '.join(command)}\n")
        handle.flush()
        try:
            completed = subprocess.run(
                command,
                cwd=clovery,
                env=dict(env),
                stdout=handle,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            handle.write(f"[timeout after {timeout}s]\n")
            return False, f"timeout after {timeout}s"
    if completed.returncode != 0:
        return False, f"exit {completed.returncode}"
    return True, ""


def cpg_pair_progress(clovery: Path) -> tuple[int, int]:
    """Return step 4's total and durably completed function-pair counts."""

    pairs = clovery / "Evalu" / "CombiPatchFunc"
    merged = clovery / "Evalu" / "Joern_result" / "mergeRES"
    total = sum(1 for path in pairs.rglob("*.json") if path.is_file()) if pairs.is_dir() else 0
    completed = (
        sum(1 for path in merged.rglob("*_merged_DEP.json") if path.is_file())
        if merged.is_dir()
        else 0
    )
    return total, completed


def recycle_budget_for_workload(configured: int, pending: int, batch_limit: int) -> int:
    """Raise a healthy-recycle budget enough to drain a function-limited step.

    A batch that lands exactly on ``batch_limit`` exits 43 before it can observe
    that the input is exhausted, so ``pending // batch_limit`` (not ceil - 1) is
    the number of restarts that must be allowed.
    """

    if batch_limit <= 0:
        return configured
    return max(configured, max(0, pending) // batch_limit)


def recycle_budget_after_progress(
    current: int, recycles: int, remaining: int, completed_this_run: int
) -> int:
    """Adapt the budget when project/RSS pressure yields before the batch limit."""

    if completed_this_run <= 0:
        return current
    projected = recycles + 1 + max(0, remaining) // completed_this_run
    return max(current, projected)


def find_clone(clovery: Path, pack: str) -> Path | None:
    """Locate the checkout Clovery made for this repository.

    Clovery derives the directory name from the reference URL, so its casing
    follows whatever NVD published (``davegamble##cjson``), not the corpus
    entry (``DaveGamble##cJSON``).  Only one repository is in flight per cycle,
    so falling back to the single present directory is safe.
    """

    clones = clovery / "Evalu" / "clones"
    if not clones.is_dir():
        return None
    exact = clones / pack
    if exact.is_dir():
        return exact
    wanted = pack.lower()
    directories = [path for path in clones.iterdir() if path.is_dir()]
    for path in directories:
        if path.name.lower() == wanted:
            return path
    return directories[0] if len(directories) == 1 else None


def write_commit_graph(clone: Path) -> bool:
    """Build the clone's commit-graph, once, right after it appears.

    Everything downstream of the clone is a history walk - the patch-commit
    recovery greps it, the release boundaries walk `git tag --contains`, step 5
    runs `git log --follow` per file and `git log -L` per commit - and git
    answers all of them by decompressing commit objects unless a commit-graph
    is present. `git clone` does not write one. On tensorflow's 197k commits
    that is the same cost paid over and over across ~72k invocations.

    Best effort: an older git without the subcommand, or a repository it
    refuses to index, just leaves the walks as slow as they were.
    """

    try:
        completed = subprocess.run(
            ["git", "commit-graph", "write", "--reachable"],
            cwd=clone,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=3600,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def validate_and_recover_patches(
    args: argparse.Namespace,
    target: Mapping[str, Any],
    feed_target: Path,
    database: Path,
) -> dict[str, Any] | None:
    """Validate every patch candidate and rewrite the run feed with evidence.

    The plan intentionally contains an upper bound: direct NVD references plus
    local OSV hints. Some OSV ``fixed`` events are converted version boundaries
    rather than patch commits, while some references point at docs, tests,
    another repository, or a language Clovery cannot parse. None of those may
    become analysis input merely because its URL contains ``commit``.
    """

    clone = find_clone(args.clovery, target["pack"])
    if clone is None:
        print("    patch-evidence: SKIPPED - repository clone unavailable", flush=True)
        return None

    conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        conn.execute("CREATE TEMP TABLE cycle_cves(cve_id TEXT PRIMARY KEY)")
        jsonl = source_jsonl(conn, args.source_jsonl)
        records = read_cve_records(conn, target.get("db_cves", []), jsonl)
    except CycleError as error:
        print(f"    patch-evidence: SKIPPED - {error}", flush=True)
        return None
    finally:
        conn.close()

    destination = args.work / "results" / target["pack"]
    return build_validated_feed(
        feed_target,
        records,
        target.get("db_cves", []),
        target["owner"],
        target["name"],
        clone,
        recover=args.recover,
        osv_dir=discover_osv_dir(jsonl, args.osv_dir),
        manifest_path=destination / "patch_evidence.json",
    )


def clear_collected_diffs(clovery: Path) -> None:
    """Discard the unvalidated bootstrap collector output before rerunning it."""

    root = clovery / "Evalu" / "diffs"
    if not root.is_dir():
        return
    for path in root.iterdir():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.is_file() or path.is_symlink():
            path.unlink()


def resolve_fixed_versions(
    clovery: Path,
    pack: str,
    feed: Path,
    destination: Path,
    *,
    series_depth: int = 1,
) -> dict[str, Any] | None:
    """Read the fixed release per version series straight out of the clone.

    A CVE reference that points at the patch commit already carries the release
    boundary; ``git tag --contains`` plus a check that the preceding release
    lacks the commit turns it into a concrete ``fixed`` version.  This is far
    cheaper than tagging every release by re-analysing code, and it is the value
    the SBOM database consumes, so it runs regardless of how the later Clovery
    steps go.
    """

    clone = find_clone(clovery, pack)
    if clone is None:
        return None
    try:
        payload = analyse_feed(clone, feed, depth=series_depth)
    except (GitError, OSError, json.JSONDecodeError) as error:
        print(f"    fixed-versions: skipped ({error})", flush=True)
        return None

    resolved = sum(1 for data in payload["results"].values() if data["fixed"])
    payload["resolved_cves"] = resolved
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "fixed_versions.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return payload


def load_fixed_versions(results_dir: Path) -> dict[str, Any] | None:
    """Read back the boundaries a previous attempt at this repository wrote."""
    path = results_dir / "fixed_versions.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if "resolved_cves" in payload else None


def verify_version_ranges(results_dir: Path, database: Path) -> dict[str, Any] | None:
    """Compare the derived evidence with the published range and propose an update."""
    try:
        payload = verify_repo(results_dir, database)
    except (OSError, sqlite3.Error, json.JSONDecodeError, KeyError) as error:
        print(f"    version-ranges: skipped ({error})", flush=True)
        return None
    (results_dir / "version_ranges.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return payload


def stage_coverage(clovery: Path, feed: Path) -> dict[str, Any]:
    """Count the CVEs surviving each stage, and name the ones that drop out.

    Clovery drops a CVE by simply not writing its next artifact - a diff whose
    hunks all fall outside a function body yields no function pair, and nothing
    reports it. Only the final count was otherwise visible, which makes "could
    not be analysed" and "analysed, nothing found" look identical in the output.
    """

    try:
        items = json.loads(feed.read_text(encoding="utf-8")).get("CVE_Items") or []
    except (OSError, json.JSONDecodeError, AttributeError):
        items = []
    feed_cves = set()
    for item in items:
        cve_id = ((item.get("cve") or {}).get("CVE_data_meta") or {}).get("ID")
        if cve_id:
            feed_cves.add(str(cve_id))

    stages: dict[str, set[str]] = {}
    for label, name in COVERAGE_STAGES:
        found: set[str] = set()
        root = clovery / "Evalu" / name
        if root.is_dir():
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                match = CVE_PATTERN.search(path.name)
                if match:
                    found.add(match.group())
        stages[label] = found

    # Step 7 lists the CVEs whose every function failed to produce a verdict.
    unanalysable: set[str] = set()
    marker = clovery / "Evalu" / UNABLE_MARKER
    if marker.is_file():
        unanalysable = {
            line.strip()
            for line in marker.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        }

    no_diff = feed_cves - stages["with_diff"]
    no_function = stages["with_diff"] - stages["with_functions"]
    no_tag_info = stages["with_functions"] - stages["with_tag_info"]
    return {
        "feed_cves": len(feed_cves),
        **{label: len(found) for label, found in stages.items()},
        "no_patch_diff": sorted(no_diff),
        "no_function_extracted": sorted(no_function),
        "no_tag_info": sorted(no_tag_info),
        "unanalysable": sorted(unanalysable),
    }


def harvest(clovery: Path, destination: Path) -> dict[str, Any]:
    """Copy tagCombi output out of Evalu and summarize the version verdicts."""

    destination.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"files": [], "cve_count": 0, "vulnerable_versions": 0}
    for name in HARVEST_DIRS:
        source = clovery / "Evalu" / name
        if not source.is_dir():
            continue
        for path in sorted(source.rglob("*.json")):
            target = destination / name / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            vulnerable = sum(1 for value in data.values() if value == "Vulnerable")
            summary["files"].append(
                {
                    "file": f"{name}/{path.name}",
                    "versions": len(data),
                    "vulnerable": vulnerable,
                    "all_safe": name == "tagCombi_allSafe",
                }
            )
            summary["cve_count"] += 1
            summary["vulnerable_versions"] += vulnerable
    collector_status = clovery / "Evalu" / "collector_status.jsonl"
    if collector_status.is_file():
        shutil.copy2(collector_status, destination / "collector_status.jsonl")
    return summary


def cmd_run(args: argparse.Namespace) -> int:
    plan_path = args.work / "targets.json"
    if not plan_path.exists():
        raise CycleError(f"no plan at {plan_path}; run `plan` first")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    targets: list[dict[str, Any]] = plan["targets"]
    if args.rerun_done and not args.only:
        raise CycleError("--rerun-done requires at least one --only repository")

    if not joern_is_up(args.joern_host, args.joern_port) and args.joern_cmd:
        print("joern: not running; starting it", flush=True)
        if not start_joern(
            args.joern_cmd, args.clovery, args.joern_host, args.joern_port
        ):
            raise CycleError(f"could not start Joern via {args.joern_cmd}")
    if not joern_is_up(args.joern_host, args.joern_port):
        raise CycleError(
            f"no Joern server on {args.joern_host}:{args.joern_port}. Start it from "
            f"{args.clovery} so its workspace/ resolves:\n"
            f"  cd {args.clovery} && joern --server --server-host {args.joern_host} "
            f"--server-port {args.joern_port} --server-auth-username username "
            f"--server-auth-password password"
        )

    ctags = shutil.which(args.ctags) or args.ctags
    env = {
        **os.environ,
        "CTAGS_PATH": ctags,
        # Blobless, checkout-free clone (see apply_compat_patch.py). Trades disk
        # for network: every historical file read becomes a promisor fetch, so
        # it wins on large repositories and loses on small ones.
        "CLOVERY_LEAN_CLONE": "0" if args.full_clone else "1",
        "CLOVERY_QUERY_TIMEOUT": str(args.query_timeout),
        # Only meaningful when the cycle can actually restart the server; with
        # no --joern-cmd a step that yielded would just yield again, so the
        # limits are switched off rather than honoured pointlessly.
        "CLOVERY_MAX_JOERN_FUNCTIONS": str(
            args.max_joern_functions if args.joern_cmd else 0
        ),
        "CLOVERY_MAX_JOERN_PROJECTS": str(
            args.max_joern_projects if args.joern_cmd else 0
        ),
        "CLOVERY_MAX_JOERN_RSS_MB": str(
            args.max_joern_rss_mb if args.joern_cmd else 0
        ),
        # Step 5 fans out per CombiPatchFunc entry over this many processes.
        # 0 means "the cores this process is allowed to use", which is the
        # right answer unless memory is the binding constraint: each worker
        # peaks near 650MB inside `git log -L` on a repository tensorflow's
        # size, so ~0.7GB per worker is the budget to check against.
        "CLOVERY_HISTORY_WORKERS": str(args.history_workers),
    }
    args.db_path = args.db or default_database()
    state_path = args.work / "state.json"
    state = load_state(state_path)
    results_root = args.work / "results"
    logs_root = args.work / "logs"
    logs_root.mkdir(parents=True, exist_ok=True)
    feed_dir = args.clovery / "Evalu" / "data" / "nvd"
    feed_dir.mkdir(parents=True, exist_ok=True)

    legacy_done = {
        target["pack"]
        for target in targets
        if target["pack"] in state["done"]
        and not (results_root / target["pack"] / "patch_evidence.json").is_file()
    }
    selected = []
    for target in targets:
        rerun_done = bool(
            args.rerun_done
            and args.only
            and target["repo"] in args.only
            and target["pack"] in state["done"]
        )
        revalidate_legacy = bool(
            args.revalidate_legacy and target["pack"] in legacy_done
        )
        if (
            (target["pack"] not in state["done"] or rerun_done or revalidate_legacy)
            and (args.retry_failed or target["pack"] not in state["failed"])
            and target["pack"] not in state["skipped"]
            and (not args.only or target["repo"] in args.only)
        ):
            selected.append(target)
    if args.limit:
        selected = selected[: args.limit]
    if not selected:
        print("nothing to do (all targets done, or filtered out)")
        return 0

    print(f"{len(selected)} repo(s) queued; results -> {results_root}")
    for index, target in enumerate(selected, start=1):
        pack = target["pack"]
        if (args.rerun_done or args.revalidate_legacy) and pack in state["done"]:
            state["done"].pop(pack, None)
            state["failed"].pop(pack, None)
            state["skipped"].pop(pack, None)
        started = time.time()
        print(f"\n[{index}/{len(selected)}] {target['repo']}  "
              f"({target['cve_count']} CVE, {target['db_cve_count']} in DB)", flush=True)

        # Resuming means keeping what the failed run built - the whole point of
        # --retry-failed, since the steps skip work that already exists. Purging
        # first would throw away the clone and every CPG and make the retry a
        # rerun. Only this repository's own intermediates qualify: the marker
        # says whose they are, and the augmented feed has to still be there, or
        # the recovered CVEs are gone and the stages below disagree about which
        # CVEs are in the run.
        marker = args.clovery / "Evalu" / CYCLE_MARKER
        feed_target = feed_dir / f"nvdcve-1.1-{pack}.json"
        resuming = (
            args.retry_failed
            and pack in state["failed"]
            and marker.is_file()
            and marker.read_text(encoding="utf-8").strip() == pack
            and feed_target.is_file()
        )
        if resuming:
            print("    resuming: intermediates of the failed run kept", flush=True)
        else:
            purge(args.clovery)
        if not recycle_joern(args):
            state["failed"][pack] = {
                "repo": target["repo"],
                "reason": "joern unavailable",
                "log": "",
                "elapsed_s": 0,
            }
            save_state(state_path, state)
            break
        if not resuming:
            for stale in feed_dir.glob("*.json"):
                stale.unlink()
            # Step 7 writes this straight under Evalu/, where purge() does not
            # reach, so a previous repository's copy would be read as this one's.
            stale_marker = args.clovery / "Evalu" / UNABLE_MARKER
            if stale_marker.exists():
                stale_marker.unlink()
            # `-direct` walks every file in Evalu/data/nvd, so exactly one feed
            # must be present for the cycle to stay scoped to this repository.
            shutil.copy2(REPO_ROOT / target["feed"], feed_target)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(pack, encoding="utf-8")

        log = logs_root / f"{pack}.log"
        if log.exists() and not resuming:
            log.unlink()

        failure = ""
        fixed_versions: dict[str, Any] | None = None
        patch_manifest: dict[str, Any] | None = None
        for step_name, template in STEPS:
            script_args = [
                part.format(feed=str(feed_target.relative_to(args.clovery)))
                for part in template
            ]
            # Two exit codes mean "restart Joern and run me again", and they are
            # budgeted apart because they say opposite things. RECYCLE_EXIT is
            # the step stopping while healthy, so a large repository is expected
            # to spend several; QUERY_TIMEOUT_EXIT is the server having already
            # stopped answering, and a server that keeps doing that after a
            # restart is not going to be fixed by a third one. Either way the
            # rerun resumes: functions already merged are skipped.
            stalls = recycles = 0
            recycle_budget = args.max_recycles
            cpg_total = cpg_completed = 0
            if step_name == "4_getCPG":
                cpg_total, cpg_completed = cpg_pair_progress(args.clovery)
                if args.max_cpg_pairs and cpg_total > args.max_cpg_pairs:
                    failure = (
                        f"{step_name}: function-pair workload {cpg_total} exceeds "
                        f"--max-cpg-pairs {args.max_cpg_pairs}; inspect patch evidence "
                        "or override the limit explicitly"
                    )
                    print(f"    {step_name}: FAILED {failure.split(': ', 1)[1]}",
                          flush=True)
                    break
                recycle_budget = recycle_budget_for_workload(
                    recycle_budget,
                    cpg_total - cpg_completed,
                    args.max_joern_functions,
                )
                if recycle_budget > args.max_recycles:
                    print(
                        f"    {step_name}: recycle budget raised "
                        f"{args.max_recycles} -> {recycle_budget} for "
                        f"{cpg_total - cpg_completed} pending function pair(s)",
                        flush=True,
                    )
            while True:
                completed_before = cpg_completed
                ok, detail = run_step(
                    args.clovery,
                    script_args,
                    env=env,
                    log=log,
                    timeout=args.step_timeout,
                    python=args.python,
                )
                planned = detail == f"exit {RECYCLE_EXIT}"
                stalled = detail == f"exit {QUERY_TIMEOUT_EXIT}"
                if ok or not (planned or stalled):
                    break
                if step_name == "4_getCPG":
                    _, cpg_completed = cpg_pair_progress(args.clovery)
                if planned:
                    completed_this_run = cpg_completed - completed_before
                    if step_name == "4_getCPG" and completed_this_run <= 0:
                        detail = "asked for a clean Joern without durable CPG progress"
                        break
                    recycle_budget = recycle_budget_after_progress(
                        recycle_budget,
                        recycles,
                        cpg_total - cpg_completed,
                        completed_this_run,
                    )
                    if recycles >= recycle_budget:
                        detail = (
                            f"asked for more than {recycle_budget} healthy "
                            "Joern restarts"
                        )
                        break
                if stalled and stalls >= args.step_retries:
                    detail = f"Joern stopped answering {stalls + 1}x"
                    break
                if planned:
                    recycles += 1
                    print(f"    {step_name}: yielding for a clean Joern "
                          f"({recycles}/{recycle_budget}, "
                          f"completed={cpg_completed}/{cpg_total})", flush=True)
                else:
                    stalls += 1
                    print(f"    {step_name}: Joern stopped answering; "
                          f"resuming after a restart ({stalls}/{args.step_retries})",
                          flush=True)
                if not args.joern_cmd:
                    print("    (no --joern-cmd, so the server is reused as-is)",
                          flush=True)
                elif not recycle_joern(args):
                    ok, detail = False, "joern restart failed"
                    break
            counts = " ".join(
                f"{short}={len(list((args.clovery / 'Evalu' / name).rglob('*')))}"
                for short, name in (
                    ("diff", "diffs"),
                    ("comb", "CombiPatchFunc"),
                    ("lin", "Lineage"),
                    ("tag", "tagInfo"),
                )
                if (args.clovery / "Evalu" / name).is_dir()
            )
            print(f"    {step_name}: {'ok' if ok else 'FAILED ' + detail}  [{counts}]",
                  flush=True)
            if not ok:
                failure = f"{step_name}: {detail}"
                break
            if step_name == "1_collect" and resuming:
                # Both of these ran to completion before the failure, and both
                # are expensive enough to dominate a retry: recovery greps the
                # whole history once per CVE, and the boundaries cost a
                # `git tag --contains` walk each - over five hours together on
                # tensorflow. The feed still holds the recovered CVEs and the
                # boundaries are already written, so reuse them.
                fixed_versions = load_fixed_versions(results_root / pack)
                if fixed_versions:
                    print(f"    fixed-versions: reused {fixed_versions['resolved_cves']}"
                          f"/{fixed_versions['cve_count']} CVE from the failed run",
                          flush=True)
            elif step_name == "1_collect":
                if args.max_clone_gb:
                    size = directory_size_gb(args.clovery / "Evalu" / "clones")
                    if size > args.max_clone_gb:
                        failure = f"clone {size:.1f}GB exceeds --max-clone-gb {args.max_clone_gb}"
                        print(f"    skipping: {failure}", flush=True)
                        state["skipped"][pack] = {"repo": target["repo"], "reason": failure}
                        break
                # Before recovery, not after: recovery is itself one of the
                # history walks the graph exists to speed up.
                clone = find_clone(args.clovery, pack)
                if clone is not None:
                    started_graph = time.time()
                    if write_commit_graph(clone):
                        print(f"    commit-graph: built in "
                              f"{time.time() - started_graph:.0f}s", flush=True)
                    else:
                        print("    commit-graph: unavailable, walks stay slow",
                              flush=True)
                patch_manifest = validate_and_recover_patches(
                    args, target, feed_target, args.db_path
                )
                if patch_manifest is None:
                    failure = "patch evidence validation unavailable"
                    break
                selected_cves = int(patch_manifest["selected_cves"])
                status_text = ", ".join(
                    f"{key}={value}"
                    for key, value in sorted(
                        patch_manifest.get("status_counts", {}).items()
                    )
                )
                print(
                    f"    patch-evidence: {selected_cves}/"
                    f"{len(target.get('db_cves', []))} CVE selected"
                    f" [{status_text}]",
                    flush=True,
                )
                if not selected_cves:
                    reason = "no validated C/C++ patch commit"
                    state["skipped"][pack] = {
                        "repo": target["repo"],
                        "reason": reason,
                    }
                    print(f"    skipping: {reason}", flush=True)
                    break

                # Step 1's first pass exists to obtain the repository checkout.
                # Its inputs are the unvalidated upper bound, so none of its
                # diffs may survive into the actual analysis.
                clear_collected_diffs(args.clovery)
                ok, detail = run_step(
                    args.clovery,
                    [
                        "1_cve_collector.py",
                        "-direct",
                        str(feed_target.relative_to(args.clovery)),
                    ],
                    env=env,
                    log=log,
                    timeout=args.step_timeout,
                    python=args.python,
                )
                print(f"    1_collect (validated): {'ok' if ok else 'FAILED ' + detail}",
                      flush=True)
                if not ok:
                    failure = f"1_collect (validated): {detail}"
                    break
                # Release boundaries only need the clone, so resolve them now:
                # they survive even if the expensive Joern steps later fail.
                # Read the run's own feed, not the plan's: recovered CVEs exist
                # only in this copy, and reading the plan feed left every one of
                # them without the commit boundary that cross-checks Clovery's
                # tag verdicts - which is exactly where a wrong verdict goes
                # unchallenged and comes out as `confidence: medium`.
                fixed_versions = resolve_fixed_versions(
                    args.clovery, pack, feed_target, results_root / pack,
                    series_depth=args.series_depth,
                )
                if fixed_versions:
                    print(f"    fixed-versions: {fixed_versions['resolved_cves']}"
                          f"/{fixed_versions['cve_count']} CVE resolved", flush=True)

        elapsed = round(time.time() - started, 1)
        # Functions traded away to keep the step moving. Naming them is the
        # point: a count alone cannot be told apart from a clean run.
        set_ledger_dir(str(args.clovery / "Evalu" / "Joern_result"))
        abandoned = abandoned_functions()
        if abandoned:
            shown = ", ".join(abandoned[:3])
            more = f" (+{len(abandoned) - 3})" if len(abandoned) > 3 else ""
            print(f"    abandoned to query timeouts: {len(abandoned)} function(s)  "
                  f"{shown}{more}", flush=True)
        if pack in state["skipped"]:
            pass
        elif failure:
            state["failed"][pack] = {
                "repo": target["repo"],
                "reason": failure,
                "log": str(log),
                "elapsed_s": elapsed,
            }
            print(f"    -> failed after {elapsed}s ({failure})")
        else:
            summary = harvest(args.clovery, results_root / pack)
            coverage = stage_coverage(args.clovery, feed_target)
            summary.update(
                {
                    "repo": target["repo"],
                    "elapsed_s": elapsed,
                    "planned_cves": target["cve_count"],
                    "db_cves": target["db_cve_count"],
                    "fixed_version_cves": (
                        fixed_versions["resolved_cves"] if fixed_versions else 0
                    ),
                    "coverage": coverage,
                    "patch_evidence": (
                        patch_manifest.get("status_counts", {})
                        if patch_manifest else {}
                    ),
                    "abandoned_functions": abandoned,
                }
            )
            for label, dropped in (
                ("no patch diff", coverage["no_patch_diff"]),
                ("no function extracted", coverage["no_function_extracted"]),
                ("no tag information", coverage["no_tag_info"]),
                ("no verdict on any tag", coverage["unanalysable"]),
            ):
                if dropped:
                    shown = ", ".join(dropped[:4])
                    more = f" (+{len(dropped) - 4})" if len(dropped) > 4 else ""
                    print(f"    {label}: {len(dropped)} CVE  {shown}{more}", flush=True)
            (results_root / pack / "summary.json").write_text(
                json.dumps(summary, indent=2), encoding="utf-8"
            )
            # Reconcile the per-tag verdicts and the commit boundary against the
            # range the DB currently publishes, and record the proposed update.
            verification = verify_version_ranges(results_root / pack, args.db_path)
            if verification:
                summary["range_changes"] = verification["changed_count"]
                (results_root / pack / "summary.json").write_text(
                    json.dumps(summary, indent=2), encoding="utf-8"
                )
                print(f"    version-ranges: {verification['changed_count']}"
                      f"/{verification['cve_count']} CVE would change", flush=True)
            state["done"][pack] = {
                "repo": target["repo"],
                "patch_evidence_schema": 2,
                "cve_results": summary["cve_count"],
                "vulnerable_versions": summary["vulnerable_versions"],
                "fixed_version_cves": summary["fixed_version_cves"],
                "dropped_cves": (
                    len(coverage["no_patch_diff"])
                    + len(coverage["no_function_extracted"])
                    + len(coverage["no_tag_info"])
                ),
                "unanalysable_cves": len(coverage["unanalysable"]),
                "elapsed_s": elapsed,
            }
            state["failed"].pop(pack, None)
            state["skipped"].pop(pack, None)
            print(f"    -> {summary['cve_count']} CVE result(s), "
                  f"{summary['vulnerable_versions']} vulnerable version tag(s), {elapsed}s")

        save_state(state_path, state)
        # Keep a failed repo's intermediates: the steps skip work that already
        # exists, so an immediate --retry-failed resumes instead of redoing
        # hours of CPG building. Disk is still bounded, because the next repo
        # purges at the start of its own cycle.
        if not args.keep_last and not failure:
            purge(args.clovery)
            for stale in feed_dir.glob("*.json"):
                stale.unlink()

    print(f"\ndone: {len(state['done'])}  failed: {len(state['failed'])}  "
          f"skipped: {len(state['skipped'])}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    plan_path = args.work / "targets.json"
    if not plan_path.exists():
        raise CycleError(f"no plan at {plan_path}; run `plan` first")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    state = load_state(args.work / "state.json")

    target_packs = {target["pack"] for target in plan["targets"]}
    total = len(target_packs)
    done, failed, skipped = state["done"], state["failed"], state["skipped"]
    done_packs = target_packs & set(done)
    failed_packs = target_packs & set(failed)
    skipped_packs = target_packs & set(skipped)
    validated_done = {
        pack
        for pack in done_packs
        if (args.work / "results" / pack / "patch_evidence.json").is_file()
    }
    legacy_done = done_packs - validated_done
    pending = target_packs - done_packs - failed_packs - skipped_packs
    print(
        f"plan     : {total} repos, {plan['cve_count']} repo-CVE candidates "
        f"({plan.get('distinct_cve_count', plan['cve_count'])} distinct); "
        f"{plan['db_cve_count']} bound pairs "
        f"({plan.get('db_distinct_cve_count', plan['db_cve_count'])} distinct)"
    )
    print(f"done     : {len(validated_done)} evidence-validated")
    print(f"legacy   : {len(legacy_done)} done before patch validation")
    print(f"failed   : {len(failed_packs)}")
    print(f"skipped  : {len(skipped_packs)}")
    print(f"pending  : {len(pending)} new + {len(legacy_done)} revalidation")

    if done:
        cves = sum(item["cve_results"] for item in done.values())
        vulnerable = sum(item["vulnerable_versions"] for item in done.values())
        boundaries = sum(item.get("fixed_version_cves", 0) for item in done.values())
        elapsed = sum(item["elapsed_s"] for item in done.values())
        print(f"\nharvested: {cves} CVE result(s), {vulnerable} vulnerable version tag(s)")
        print(f"fixed-version boundaries resolved from patch commits: {boundaries} CVE")
        print(f"wall time: {elapsed / 3600:.2f}h  ({elapsed / max(len(done), 1):.0f}s per repo)")
    if failed and args.verbose:
        print("\nfailures:")
        for pack, item in failed.items():
            print(f"  {item['repo']}: {item['reason']}")
    if skipped and args.verbose:
        print("\nskipped:")
        for pack, item in skipped.items():
            print(f"  {item['repo']}: {item['reason']}")
    return 0



def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK)
    parser.add_argument("--clovery", type=Path, default=DEFAULT_CLOVERY)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="build the per-repo work plan and feeds")
    plan.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    plan.add_argument("--db", type=Path, help="applicability DB (default: newest in workspace/)")
    plan.add_argument(
        "--source-jsonl",
        type=Path,
        help="NVD JSONL the DB indexes; default comes from source_snapshot_manifest",
    )
    plan.add_argument(
        "--osv-dir",
        type=Path,
        help="local OSV mirror; defaults to an osv directory beside --source-jsonl",
    )
    plan.add_argument("--min-cves", type=int, default=1)
    plan.add_argument(
        "--repo-name-match",
        action="store_true",
        help="also accept repos matched by product name alone (any vendor); "
        "generic names like 'linux' or 'core' collide, so this is off by default",
    )

    run = commands.add_parser("run", help="clone -> analyse -> harvest -> purge, per repo")
    run.add_argument("--limit", type=int, help="process at most N repos this invocation")
    run.add_argument("--only", action="append", help="restrict to these owner@repo entries")
    run.add_argument("--retry-failed", action="store_true")
    run.add_argument(
        "--rerun-done",
        action="store_true",
        help="allow --only repositories already in state.done to be revalidated",
    )
    run.add_argument(
        "--revalidate-legacy",
        action="store_true",
        help="also rerun completed repositories that predate patch_evidence.json",
    )
    run.add_argument("--step-timeout", type=int, default=7200)
    run.add_argument(
        "--history-workers",
        type=int,
        default=0,
        help="processes for step 5's per-entry fan-out (default 0 = one per "
        "usable core; lower it if ~0.7GB per worker does not fit)",
    )
    run.add_argument(
        "--step-retries",
        type=int,
        default=5,
        help="how many times to restart Joern and resume a step that ended "
        "because the server stopped answering (default 5)",
    )
    run.add_argument(
        "--max-recycles",
        type=int,
        default=20,
        help="minimum healthy-restart budget per repository; step 4 raises it "
        "from pending/observed function-pair throughput (default 20)",
    )
    run.add_argument(
        "--max-joern-functions",
        type=int,
        default=100,
        help="restart Joern after this many completed function pairs to reset "
        "long-lived compiler state (default 100, 0 disables). Needs --joern-cmd",
    )
    run.add_argument(
        "--max-cpg-pairs",
        type=int,
        default=5000,
        help="refuse step 4 when extracted function pairs exceed this anomaly "
        "budget (default 5000, 0 disables); use an explicit override for a "
        "known legitimate large patch",
    )
    run.add_argument(
        "--max-joern-projects",
        type=int,
        default=400,
        help="restart Joern once its store holds this many in-flight/stale "
        "projects (default 400, 0 disables). Needs --joern-cmd",
    )
    run.add_argument(
        "--max-joern-rss-mb",
        type=int,
        default=0,
        help="restart Joern once the JVM is this resident, in MB "
        "(default 0, disabled). Needs --joern-cmd",
    )
    run.add_argument(
        "--max-clone-gb",
        type=float,
        default=20.0,
        help="skip a repo whose clone exceeds this size (0 disables)",
    )
    run.add_argument("--keep-last", action="store_true",
                     help="leave the final repo's intermediates in place for debugging")
    run.add_argument(
        "--series-depth",
        type=int,
        default=1,
        help="version components defining a release series for fixed-version resolution",
    )
    run.add_argument(
        "--full-clone",
        action="store_true",
        help="clone whole repositories instead of blobless partial clones "
        "(faster per repo, much more disk)",
    )
    run.add_argument("--db", type=Path, help="applicability DB to verify ranges against")
    run.add_argument(
        "--source-jsonl",
        type=Path,
        help="NVD JSONL the DB indexes; default comes from source_snapshot_manifest",
    )
    run.add_argument(
        "--osv-dir",
        type=Path,
        help="local OSV mirror; defaults to an osv directory beside --source-jsonl",
    )
    run.add_argument(
        "--recover",
        choices=("none", "gitlog", "osv", "both"),
        default="both",
        help="find patch commits NVD never referenced: OSV fix events and/or "
        "commit messages naming the CVE (default: both)",
    )
    run.add_argument("--python", default=sys.executable)
    run.add_argument("--ctags", default="ctags")
    run.add_argument("--joern-host", default="localhost")
    run.add_argument("--joern-port", type=int, default=8080)
    run.add_argument(
        "--joern-cmd",
        help="path to the joern binary; when given, the cycle restarts the server "
        "with an empty project store before each repo (recommended for batches); "
        "otherwise an already running Joern server is used",
        default=os.environ.get("CLOVERY_JOERN_CMD") or shutil.which("joern"),
    )
    run.add_argument(
        "--query-timeout",
        type=int,
        default=1800,
        help="seconds a single Joern query may take before the step fails "
        "instead of hanging (default 1800)",
    )

    status = commands.add_parser("status", help="show cycle progress")
    status.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    args.work.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "plan":
            return cmd_plan(args)
        if args.command == "run":
            return cmd_run(args)
        if args.command == "status":
            return cmd_status(args)
    except (CycleError, OSError, sqlite3.Error, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
