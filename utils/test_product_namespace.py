"""Scoped products retain exact coordinates inside the existing schema/CLI."""
import contextlib
import io
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from scripts.nvd_normalization.builder import build_database
from utils.query2nvddb import main


def record(number, product, *, package_name=None):
    claim = {
        "vendor": "Example Vendor",
        "product": product,
        "defaultStatus": "unaffected",
        "versions": [
            {
                "version": "1.0.0",
                "lessThan": "2.0.0",
                "versionType": "semver",
                "status": "affected",
            }
        ],
    }
    if package_name:
        claim.update(
            packageName=package_name, collectionURL="https://registry.npmjs.org"
        )
    return {
        "id": f"CVE-2026-{number}",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Product identity fixture."}],
        "affected": [claim],
    }


@pytest.fixture
def built(tmp_path):
    source = tmp_path / "source.jsonl"
    records = [
        record(99001, "@scope/core"),
        record(99002, "scope-core"),
        record(99003, "@scope/helper-one"),
        record(99004, "@scope/helper_one"),
        record(99005, "@other/core"),
        record(99006, "@scope-other/core"),
        record(99007, "@scope/other-core"),
        record(99008, "scope", package_name="@scope/extra"),
    ]
    source.write_text("".join(json.dumps({"cve": r}) + "\n" for r in records))
    path = tmp_path / "nvd.sqlite"
    build_database(
        input_path=source,
        database_path=path,
        llm_path=None,
        llm_fail_path=None,
        replace_existing=False,
        limit=None,
        progress_every=0,
    )
    return path


def query(path, product, version="1.5.0", vendor="Example Vendor"):
    args = [product, version, "--db", str(path), "--format", "json", "--all-states"]
    if vendor:
        args += ["--vendor", vendor]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(args)
    return code, json.loads(out.getvalue())


def test_scoped_products_are_separate_entities_without_schema_extension(built):
    with sqlite3.connect(built) as c:
        rows = list(
            c.execute("SELECT canonical_vendor,canonical_product FROM product_entity")
        )
        assert len(rows) == 8
        assert ("Example Vendor", "@scope/core") in rows
        assert ("Example Vendor", "scope-core") in rows
        assert ("Example Vendor", "@scope/extra") in rows
        baseline = sqlite3.connect(":memory:")
        baseline.executescript(
            (
                Path(__file__).parents[1]
                / "scripts/nvd_normalization/migrations/0005_schema_v5.sql"
            ).read_text()
        )
        names = lambda db: {
            r[0]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert names(c) == names(baseline)
        for table in names(baseline):
            assert list(c.execute(f"PRAGMA table_info({table})")) == list(
                baseline.execute(f"PRAGMA table_info({table})")
            )


@pytest.mark.parametrize(
    "product,number",
    [
        ("@scope/core", 99001),
        ("scope-core", 99002),
        ("@scope/helper-one", 99003),
        ("@scope/helper_one", 99004),
        ("@other/core", 99005),
        ("@scope-other/core", 99006),
        ("@scope/other-core", 99007),
        ("@scope/extra", 99008),
    ],
)
def test_existing_vendor_product_options_find_only_exact_scoped_product(
    built, product, number
):
    code, p = query(built, product)
    assert code == 0
    assert p["mode"] == "product_version"
    assert [r["cve_id"] for r in p["returned_results"]] == [f"CVE-2026-{number}"]


def test_product_only_lookup_and_range_boundary(built):
    code, p = query(built, "@scope/core", vendor=None)
    assert code == 0 and p["candidate_count"] == 1
    code, p = query(built, "@scope/core", "2.0.0")
    assert code == 0 and p["positive_count"] == 0 and p["candidate_count"] == 1


def test_scoped_typo_cannot_match_sibling_or_namespace(built):
    for name in ["@scope/corz", "@scop/core", "@scope/missing"]:
        code, p = query(built, name)
        assert code == 3 and p["candidate_count"] == 0
    assert query(built, "scope")[1]["candidate_count"] == 0


def test_shared_query_engine_cache_does_not_merge_scoped_and_flat_products(built):
    from scripts.nvd_normalization.query_engine import QueryEngine, ApplicabilityQuery

    with QueryEngine(built) as engine:
        for name, cve in [
            ("scope-core", "CVE-2026-99002"),
            ("@scope/core", "CVE-2026-99001"),
        ]:
            p = engine.query(
                ApplicabilityQuery(
                    vendor="Example Vendor", product=name, version="1.5.0"
                )
            )
            assert [r["cve_id"] for r in p["results"]] == [cve]


def test_query_options_match_original_contract():
    root = Path(__file__).parents[1]
    source = subprocess.check_output(
        ["git", "show", "HEAD:utils/query2nvddb.py"], cwd=root, text=True
    )
    # Compare the actual argument parser, not source text.
    import types

    baseline = types.ModuleType("scripts.baseline_query")
    baseline.__file__ = str(root / "utils/query2nvddb.py")
    exec(compile(source, baseline.__file__, "exec"), baseline.__dict__)
    from utils.query2nvddb import _args

    arguments = ["@scope/core", "1.5.0", "--vendor", "Example Vendor", "--all-states"]
    assert vars(_args(arguments)) == vars(baseline._args(arguments))
