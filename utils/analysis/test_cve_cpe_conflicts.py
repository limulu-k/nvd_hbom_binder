#!/usr/bin/env python3
"""Tests for the CNA/CPE conflict counter's interval algebra and verdicts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cve_cpe_conflicts import (  # noqa: E402
    Interval,
    Report,
    analyze_record,
    compare_interval_sets,
    interval_state,
    match_identity,
    merge_intervals,
    parse_cpe_criteria,
    run,
)


def closed(lower: str | None, upper: str | None) -> Interval:
    return Interval(lower, lower is not None, upper, upper is not None)


def half_open(lower: str | None, upper: str | None) -> Interval:
    return Interval(lower, lower is not None, upper, False)


# --------------------------------------------------------------------------
# merging
# --------------------------------------------------------------------------


def test_merge_coalesces_overlapping_ranges():
    merged = merge_intervals(
        [half_open("1.0", "2.0"), half_open("1.5", "3.0")], "dotted_numeric"
    )
    assert merged == [half_open("1.0", "3.0")]


def test_merge_coalesces_ranges_touching_at_a_shared_endpoint():
    merged = merge_intervals(
        [half_open("1.0", "2.0"), closed("2.0", "3.0")], "dotted_numeric"
    )
    assert merged == [closed("1.0", "3.0")]


def test_merge_keeps_ranges_with_a_gap_between_them_apart():
    intervals = [half_open("1.0", "2.0"), half_open("2.1", "3.0")]
    assert merge_intervals(intervals, "dotted_numeric") == intervals


def test_merge_keeps_an_interval_nested_inside_another_as_one():
    merged = merge_intervals(
        [half_open("1.0", "9.0"), closed("2.0", "3.0")], "dotted_numeric"
    )
    assert merged == [half_open("1.0", "9.0")]


def test_merge_treats_a_missing_upper_bound_as_unbounded():
    merged = merge_intervals(
        [half_open("1.0", None), half_open("2.0", "3.0")], "dotted_numeric"
    )
    assert merged == [half_open("1.0", None)]


# --------------------------------------------------------------------------
# verdicts
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cna", "cpe", "expected"),
    [
        ([half_open("1.0", "2.0")], [half_open("1.0", "2.0")], "equal"),
        # Same extent, expressed as one range versus two adjacent ranges.
        (
            [half_open("1.0", "3.0")],
            [half_open("1.0", "2.0"), half_open("2.0", "3.0")],
            "equal",
        ),
        ([half_open("1.0", "2.0")], [half_open("1.0", "5.0")], "cpe_broader"),
        ([half_open("1.0", "5.0")], [half_open("1.0", "2.0")], "cna_broader"),
        ([half_open("1.0", "3.0")], [half_open("2.0", "5.0")], "partial_overlap"),
        ([half_open("1.0", "2.0")], [half_open("3.0", "4.0")], "disjoint"),
        # The user's example: CNA omits the lower bound NVD supplies.
        (
            [half_open("7.0.0", "7.1.0-7"), half_open(None, "6.9.12-22")],
            [half_open("6.9.12-0", "6.9.12-22"), half_open("7.1.0-0", "7.1.0-7")],
            "cna_broader",
        ),
        # Build numbers versus a marketing name are not on one scale.
        (
            [half_open("10.0.0", "10.0.19042.1706")],
            [closed("20h2", "20h2")],
            "scheme_mismatch",
        ),
    ],
)
def test_interval_set_verdicts(cna, cpe, expected):
    assert compare_interval_sets(cna, cpe, "dotted_numeric") == expected


def test_an_unbounded_cpe_axis_swallows_any_cna_range():
    unbounded = Interval(None, False, None, False)
    assert compare_interval_sets([half_open("1.0", "2.0")], [unbounded], "opaque") == (
        "cpe_broader"
    )


# --------------------------------------------------------------------------
# decidability gate
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("interval", "expected"),
    [
        (half_open("1.0", "2.0"), "ok"),
        (closed("1.0", "1.0"), "ok"),
        (half_open(None, "2.0"), "ok"),
        # Google CNAs emit version == lessThan, which spans nothing.
        (half_open("1.3.2", "1.3.2"), "degenerate_empty_range"),
        # Microsoft CNAs emit lessThan: "publication".
        (half_open("10.0.0", "publication"), "inverted_bounds"),
        (half_open("2.0", "1.0"), "inverted_bounds"),
        # Free text sitting in the version field.
        (closed("before 1.5.20-7", "before 1.5.20-7"), "unsupported_version_token"),
    ],
)
def test_interval_state_fences_off_uncomparable_input(interval, expected):
    assert interval_state(interval, "dotted_numeric") == expected


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------


def test_parse_cpe_criteria_unescapes_and_splits():
    parsed = parse_cpe_criteria(
        r"cpe:2.3:a:zope:plone\:\:api:1.0:*:*:*:*:*:*:*"
    )
    assert parsed == ("a", "zope", "plone::api", "1.0")


def test_parse_cpe_criteria_rejects_a_non_cpe_string():
    assert parse_cpe_criteria("not-a-cpe") is None


def _record(vendor: str, product: str, criteria: str) -> dict:
    return {
        "id": "CVE-0000-0001",
        "affected": [
            {
                "source": "cna@example.test",
                "affectedData": [
                    {
                        "vendor": vendor,
                        "product": product,
                        "versions": [
                            {"version": "1.0", "lessThan": "2.0", "status": "affected"}
                        ],
                    }
                ],
            }
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": criteria,
                                "versionStartIncluding": "1.0",
                                "versionEndExcluding": "2.0",
                            }
                        ],
                    }
                ]
            }
        ],
    }


@pytest.mark.parametrize(
    ("vendor", "product", "criteria", "expected", "conflict_class"),
    [
        (
            "ImageMagick",
            "ImageMagick",
            "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
            "exact",
            "none",
        ),
        (
            "n/a",
            "Spring Framework",
            "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
            "product_only",
            "vendor_only",
        ),
        (
            "Apache Software Foundation",
            "Tomcat",
            "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
            "product_only",
            "vendor_only",
        ),
        (
            "ImageMagick",
            "Image Magic",
            "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
            "vendor_only",
            "product_only",
        ),
        # The vendor name is folded into the CNA product name.
        (
            "Apache Software Foundation",
            "Apache HTTP Server",
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "loose",
            "vendor_and_product",
        ),
        (
            "Red Hat",
            "Red Hat Enterprise Linux 8",
            "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*",
            "none",
            "vendor_and_product",
        ),
    ],
)
def test_identity_match_levels(vendor, product, criteria, expected, conflict_class):
    record = _record(vendor, product, criteria)
    analysis = analyze_record(record)
    assert analysis["identity_level"] == expected
    assert analysis["identity_conflict"] is (expected != "exact")
    assert analysis["identity_conflict_class"] == conflict_class
    assert analysis["vendor_conflict"] is (
        conflict_class in {"vendor_only", "vendor_and_product"}
    )
    assert analysis["product_conflict"] is (
        conflict_class in {"product_only", "vendor_and_product"}
    )


def test_identity_none_leaves_the_version_ranges_uncompared():
    record = _record(
        "Red Hat", "Red Hat Enterprise Linux 8", "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*"
    )
    analysis = analyze_record(record)
    assert analysis["version_verdict"] is None
    assert analysis["version_conflict"] is False


def test_matched_identity_compares_the_version_ranges():
    record = _record(
        "ImageMagick", "ImageMagick", "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*"
    )
    analysis = analyze_record(record)
    assert analysis["version_verdict"] == "equal"
    assert analysis["version_conflict"] is False


def test_a_placeholder_product_is_not_comparable():
    record = _record("n/a", "n/a", "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")
    analysis = analyze_record(record)
    assert analysis["comparable"] is False
    assert analysis["skip_reason"] == "no_named_cna_product"


def test_inverted_default_status_is_not_counted_as_a_conflict():
    record = _record(
        "ImageMagick", "ImageMagick", "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*"
    )
    record["affected"][0]["affectedData"][0]["defaultStatus"] = "affected"
    analysis = analyze_record(record)
    assert analysis["version_verdict"] is None
    assert analysis["version_undecidable"] is True
    assert analysis["undecidable_reasons"]["cna_inverted_default_status"] == 1


def test_non_vulnerable_cpe_matches_are_ignored():
    record = _record(
        "ImageMagick", "ImageMagick", "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*"
    )
    record["configurations"][0]["nodes"][0]["cpeMatch"][0]["vulnerable"] = False
    analysis = analyze_record(record)
    assert analysis["comparable"] is False
    assert analysis["skip_reason"] == "no_cpe"


def test_match_identity_prefers_the_strongest_available_level():
    from cve_cpe_conflicts import extract_cna_products, extract_cpe_products

    record = _record(
        "ImageMagick", "ImageMagick", "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*"
    )
    record["configurations"][0]["nodes"][0]["cpeMatch"].append(
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:other:imagemagick:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "9.0",
        }
    )
    cna = extract_cna_products(record)[0]
    level, matched = match_identity(cna, extract_cpe_products(record))
    assert level == "exact"
    assert [item.vendor_key for item in matched] == ["imagemagick"]


def test_report_counts_axis_conflicts_and_the_full_intersection():
    record = _record(
        "Other Vendor",
        "ImageMagick",
        "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
    )
    # CNA [1.0, 2.0) versus CPE [1.0, 3.0): a version conflict plus a
    # vendor-only identifier conflict.
    record["configurations"][0]["nodes"][0]["cpeMatch"][0][
        "versionEndExcluding"
    ] = "3.0"
    report = Report()
    report.add(analyze_record(record))
    totals = report.counters["totals"]
    assert totals["version_conflict"] == 1
    assert totals["identity_vendor_only"] == 1
    assert totals["version_and_identity_vendor_only"] == 1
    assert totals["all_three_conflicts"] == 0


def test_run_selects_latest_cve_revision_by_default(tmp_path):
    source = tmp_path / "nvd.jsonl"
    older = _record(
        "Other Vendor",
        "ImageMagick",
        "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
    )
    older["id"] = "CVE-2099-0001"
    older["lastModified"] = "2099-01-01T00:00:00.000"
    newer = _record(
        "ImageMagick",
        "ImageMagick",
        "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*",
    )
    newer["id"] = "CVE-2099-0001"
    newer["lastModified"] = "2099-02-01T00:00:00.000"
    source.write_text(
        "\n".join(json.dumps({"cve": row}) for row in (older, newer)) + "\n",
        encoding="utf-8",
    )

    report = run(
        source,
        limit=None,
        jobs=1,
        sample_size=0,
        details_out=None,
    )
    totals = report.counters["totals"]
    assert totals["source_rows"] == 2
    assert totals["records"] == 1
    assert totals["duplicate_revision_rows_skipped"] == 1
    assert totals["duplicate_cves"] == 1
    assert totals["identity_conflict"] == 0
