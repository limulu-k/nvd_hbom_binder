from __future__ import annotations

import json
from pathlib import Path
import unittest

from utils.analysis.cross_cve_identifier_cases import (
    CATEGORIES,
    _product_alias_class,
    _vendor_alias_class,
)


class InclusiveIdentifierTaxonomyTests(unittest.TestCase):
    def test_product_candidates_keep_their_alias_taxonomy(self) -> None:
        self.assertEqual(
            _product_alias_class("B2_BRAND_ALIAS", "candidate", "inclusive"),
            ("P1", "inclusive_candidate"),
        )
        self.assertEqual(
            _product_alias_class("A1_SEPARATOR", "provisional", "inclusive"),
            ("P1", "inclusive_provisional"),
        )
        self.assertEqual(
            _product_alias_class("B1_ACRONYM", "candidate", "inclusive"),
            ("P5", "inclusive_candidate"),
        )

    def test_strict_policy_retains_nonaccepted_review_bucket(self) -> None:
        self.assertEqual(
            _product_alias_class("B2_BRAND_ALIAS", "candidate", "strict"),
            ("P0", "review_candidate"),
        )
        self.assertEqual(
            _vendor_alias_class("A1_SEPARATOR", "provisional", "strict"),
            ("V0", "review_candidate"),
        )

    def test_vendor_candidates_are_split_by_alias_semantics(self) -> None:
        self.assertEqual(
            _vendor_alias_class("A1_SEPARATOR", "provisional", "inclusive"),
            ("V1", "inclusive_provisional"),
        )
        self.assertEqual(
            _vendor_alias_class("B2_BRAND_ALIAS", "candidate", "inclusive"),
            ("V2", "inclusive_candidate"),
        )

    def test_rejected_edges_are_never_inclusively_promoted(self) -> None:
        self.assertEqual(
            _product_alias_class("B1_ACRONYM", "rejected", "inclusive"),
            ("P0", "review_candidate"),
        )
        self.assertEqual(
            _vendor_alias_class("B2_BRAND_ALIAS", "superseded", "inclusive"),
            ("V0", "review_candidate"),
        )

    def test_product_taxonomy_contains_requested_p1_through_p5(self) -> None:
        self.assertEqual(
            [
                code
                for code, definition in CATEGORIES.items()
                if definition["axis"] == "product"
            ],
            ["P1", "P2", "P3", "P4", "P5", "P0"],
        )

    def test_registry_examples_use_the_expanded_product_classes(self) -> None:
        registry_path = Path(__file__).with_name("identifier_case_registry_v1.json")
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        by_subtype = {
            item["subtype"]: item["class_code"]
            for item in payload["classifications"]
            if item["axis"] == "product"
        }
        self.assertEqual(by_subtype["server"], "P2")
        self.assertEqual(by_subtype["commercial_edition"], "P3")
        self.assertEqual(by_subtype["distinct_product"], "P4")
        self.assertEqual(by_subtype["acronym"], "P5")
        self.assertEqual(by_subtype["context_dependent"], "P0")


if __name__ == "__main__":
    unittest.main()
