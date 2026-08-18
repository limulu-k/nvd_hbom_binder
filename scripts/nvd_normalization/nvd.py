"""Streaming NVD/CNA parsing with raw pointers and compact CPE graphs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import unquote

from .rules import canonical_json


CPE_NAMES = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


class ParseError(ValueError):
    def __init__(self, code: str, message: str, pointer: str) -> None:
        self.code = code
        self.pointer = pointer
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class CPE23:
    raw: str
    raw_components: tuple[str, ...]
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str

    def raw_value(self, name: str) -> str:
        return self.raw_components[CPE_NAMES.index(name)]

    def as_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in CPE_NAMES}


@dataclass(frozen=True, slots=True)
class CPEMatch:
    configuration_index: int
    node_path: str
    node_operator: str
    match_path: str
    match_criteria_id: str | None
    vulnerable: bool
    criteria: str
    cpe: CPE23
    version_start_including: str | None
    version_start_excluding: str | None
    version_end_including: str | None
    version_end_excluding: str | None
    pointer: str
    raw: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ParsedConfiguration:
    configuration_index: int
    graph: Mapping[str, Any]
    matches: tuple[CPEMatch, ...]
    issues: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True, slots=True)
class CNAAffected:
    pointer: str
    source_identifier: str | None
    vendor: str
    product: str
    default_status: str | None
    package_name: str | None
    collection_url: str | None
    modules: tuple[str, ...]
    platforms: tuple[str, ...]
    cpes: tuple[str, ...]
    versions: tuple[Mapping[str, Any], ...]
    raw: Mapping[str, Any]


def _split_cpe(raw: str) -> tuple[str, ...]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in raw:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current.clear()
        else:
            current.append(char)
    if escaped:
        raise ValueError("CPE ends in an unpaired escape")
    fields.append("".join(current))
    return tuple(fields)


def _unescape(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            output.append(value[index])
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise ValueError("CPE component ends in an unpaired escape")
        output.append(value[index])
        index += 1
    return "".join(output)


def parse_cpe23(raw: str) -> CPE23:
    fields = _split_cpe(raw)
    if len(fields) != 13 or fields[0].casefold() != "cpe" or fields[1] != "2.3":
        raise ValueError("expected a CPE 2.3 formatted string with 11 components")
    raw_components = fields[2:]
    decoded = tuple(
        _unescape(unquote(item, encoding="utf-8", errors="strict"))
        for item in raw_components
    )
    if decoded[0].casefold() not in {"a", "o", "h", "*", "-"}:
        raise ValueError("invalid CPE part")
    return CPE23(raw, raw_components, decoded[0].casefold(), *decoded[1:])


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value != "" else None


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def parse_configurations(cve: Mapping[str, Any]) -> Iterator[ParsedConfiguration]:
    configurations = cve.get("configurations")
    if not isinstance(configurations, list):
        return
    for configuration_index, raw_configuration in enumerate(configurations):
        issues: list[tuple[str, str, str]] = []
        matches: list[CPEMatch] = []
        pointer = f"$/cve/configurations/{configuration_index}"
        if not isinstance(raw_configuration, Mapping):
            issues.append(("expected_object", pointer, "configuration is not an object"))
            yield ParsedConfiguration(configuration_index, {}, (), tuple(issues))
            continue

        def parse_node(
            node: Mapping[str, Any], node_pointer: str, node_path: str
        ) -> dict[str, Any]:
            operator_value = node.get("operator")
            operator = (
                operator_value.strip().upper()
                if isinstance(operator_value, str)
                else "OR"
            )
            if operator not in {"AND", "OR"}:
                issues.append(
                    ("invalid_operator", node_pointer, f"unsupported operator {operator!r}")
                )
                operator = "OR"
            negate = node.get("negate", False)
            if not isinstance(negate, bool):
                issues.append(
                    ("invalid_negate", node_pointer, "negate is not a boolean")
                )
                negate = False
            graph_matches: list[dict[str, Any]] = []
            raw_matches = node.get("cpeMatch", node.get("cpe_match", []))
            if raw_matches is None:
                raw_matches = []
            if not isinstance(raw_matches, list):
                issues.append(
                    ("invalid_cpe_matches", node_pointer, "cpeMatch is not a list")
                )
                raw_matches = []
            for match_index, raw_match in enumerate(raw_matches):
                match_pointer = f"{node_pointer}/cpeMatch/{match_index}"
                match_path = f"{node_path}/m{match_index}"
                if not isinstance(raw_match, Mapping):
                    issues.append(
                        ("expected_object", match_pointer, "cpeMatch is not an object")
                    )
                    continue
                vulnerable = raw_match.get("vulnerable")
                criteria = raw_match.get(
                    "criteria",
                    raw_match.get("cpe23Uri", raw_match.get("cpe23uri")),
                )
                if not isinstance(vulnerable, bool) or not isinstance(criteria, str):
                    issues.append(
                        (
                            "invalid_cpe_match",
                            match_pointer,
                            "vulnerable boolean and criteria string are required",
                        )
                    )
                    continue
                try:
                    cpe = parse_cpe23(criteria)
                except (ValueError, UnicodeError) as error:
                    issues.append(("invalid_cpe23", match_pointer, str(error)))
                    continue
                start_including = _optional_string(
                    raw_match.get("versionStartIncluding")
                )
                start_excluding = _optional_string(
                    raw_match.get("versionStartExcluding")
                )
                end_including = _optional_string(raw_match.get("versionEndIncluding"))
                end_excluding = _optional_string(raw_match.get("versionEndExcluding"))
                if start_including and start_excluding:
                    issues.append(
                        (
                            "conflicting_lower_bounds",
                            match_pointer,
                            "both inclusive and exclusive lower bounds are present",
                        )
                    )
                if end_including and end_excluding:
                    issues.append(
                        (
                            "conflicting_upper_bounds",
                            match_pointer,
                            "both inclusive and exclusive upper bounds are present",
                        )
                    )
                parsed = CPEMatch(
                    configuration_index=configuration_index,
                    node_path=node_path,
                    node_operator=operator,
                    match_path=match_path,
                    match_criteria_id=_optional_string(
                        raw_match.get("matchCriteriaId")
                    ),
                    vulnerable=vulnerable,
                    criteria=criteria,
                    cpe=cpe,
                    version_start_including=start_including,
                    version_start_excluding=start_excluding,
                    version_end_including=end_including,
                    version_end_excluding=end_excluding,
                    pointer=match_pointer,
                    raw=raw_match,
                )
                matches.append(parsed)
                graph_leaf: dict[str, Any] = {
                    "id": match_path,
                    "vulnerable": vulnerable,
                }
                if not vulnerable:
                    # A selected vulnerable leaf only needs its stable ID.
                    # Platform-condition leaves retain the fields evaluated by
                    # the read path.
                    graph_leaf.update(
                        {
                            "part": cpe.part,
                            "vendor": cpe.vendor,
                            "product": cpe.product,
                            "version": cpe.version,
                            "update": cpe.update,
                            "edition": cpe.edition,
                            "language": cpe.language,
                            "sw_edition": cpe.sw_edition,
                            "target_sw": cpe.target_sw,
                            "target_hw": cpe.target_hw,
                            "other": cpe.other,
                            "versionStartIncluding": start_including,
                            "versionStartExcluding": start_excluding,
                            "versionEndIncluding": end_including,
                            "versionEndExcluding": end_excluding,
                        }
                    )
                graph_matches.append(graph_leaf)
            graph_children: list[dict[str, Any]] = []
            raw_children = node.get("nodes", node.get("children", []))
            if raw_children is None:
                raw_children = []
            if not isinstance(raw_children, list):
                issues.append(
                    ("invalid_children", node_pointer, "node children are not a list")
                )
                raw_children = []
            for child_index, raw_child in enumerate(raw_children):
                child_pointer = f"{node_pointer}/nodes/{child_index}"
                if not isinstance(raw_child, Mapping):
                    issues.append(
                        ("expected_object", child_pointer, "child node is not an object")
                    )
                    continue
                graph_children.append(
                    parse_node(
                        raw_child,
                        child_pointer,
                        f"{node_path}/n{child_index}",
                    )
                )
            return {
                "operator": operator,
                "negate": negate,
                "matches": graph_matches,
                "children": graph_children,
            }

        semantic_root = any(
            key in raw_configuration
            for key in ("operator", "cpeMatch", "cpe_match")
        )
        if semantic_root:
            graph = parse_node(raw_configuration, pointer, f"c{configuration_index}")
        else:
            children = raw_configuration.get(
                "nodes", raw_configuration.get("children", [])
            )
            if not isinstance(children, list):
                issues.append(
                    ("empty_configuration", pointer, "no semantic root or node list")
                )
                children = []
            graph_children = []
            for child_index, raw_child in enumerate(children):
                child_pointer = f"{pointer}/nodes/{child_index}"
                if not isinstance(raw_child, Mapping):
                    issues.append(
                        ("expected_object", child_pointer, "root child is not an object")
                    )
                    continue
                graph_children.append(
                    parse_node(
                        raw_child,
                        child_pointer,
                        f"c{configuration_index}/n{child_index}",
                    )
                )
            graph = {
                "operator": "OR",
                "negate": False,
                "matches": [],
                "children": graph_children,
                "synthetic_root": True,
            }
        yield ParsedConfiguration(
            configuration_index,
            graph,
            tuple(matches),
            tuple(issues),
        )


def _provider(section: Mapping[str, Any], fallback: str | None) -> str | None:
    metadata = section.get("providerMetadata")
    if not isinstance(metadata, Mapping):
        return fallback
    for key in ("orgId", "shortName"):
        value = metadata.get(key)
        if isinstance(value, str) and value:
            return value
    return fallback


def _sections(
    cve: Mapping[str, Any],
) -> tuple[tuple[str, Mapping[str, Any], str | None], ...]:
    default_source = _optional_string(cve.get("sourceIdentifier"))
    output: list[tuple[str, Mapping[str, Any], str | None]] = [
        ("$/cve", cve, default_source)
    ]
    containers = cve.get("containers")
    if not isinstance(containers, Mapping):
        return tuple(output)
    cna = containers.get("cna")
    if isinstance(cna, Mapping):
        output.append(
            (
                "$/cve/containers/cna",
                cna,
                _provider(cna, default_source),
            )
        )
    adp = containers.get("adp")
    if isinstance(adp, list):
        for index, item in enumerate(adp):
            if isinstance(item, Mapping):
                output.append(
                    (
                        f"$/cve/containers/adp/{index}",
                        item,
                        _provider(item, default_source),
                    )
                )
    return tuple(output)


def iter_cna_affected(cve: Mapping[str, Any]) -> Iterator[CNAAffected]:
    for base_pointer, section, source_identifier in _sections(cve):
        if base_pointer not in {"$/cve", "$/cve/containers/cna"}:
            continue
        raw_collection = section.get("affected")
        if not isinstance(raw_collection, list):
            continue
        for outer_index, outer in enumerate(raw_collection):
            if not isinstance(outer, Mapping):
                continue
            wrapper_source = _optional_string(outer.get("source")) or source_identifier
            nested = outer.get("affectedData")
            if isinstance(nested, list):
                items: Iterable[tuple[int, Mapping[str, Any]]] = (
                    (inner_index, item)
                    for inner_index, item in enumerate(nested)
                    if isinstance(item, Mapping)
                )
                prefix = f"{base_pointer}/affected/{outer_index}/affectedData"
            else:
                items = ((outer_index, outer),)
                prefix = f"{base_pointer}/affected"
            for item_index, item in items:
                vendor, product = item.get("vendor"), item.get("product")
                if not isinstance(vendor, str) or not isinstance(product, str):
                    continue
                versions_value = item.get("versions")
                versions = (
                    tuple(
                        version
                        for version in versions_value
                        if isinstance(version, Mapping)
                    )
                    if isinstance(versions_value, list)
                    else ()
                )
                yield CNAAffected(
                    pointer=f"{prefix}/{item_index}",
                    source_identifier=_optional_string(item.get("source"))
                    or wrapper_source,
                    vendor=vendor,
                    product=product,
                    default_status=_optional_string(item.get("defaultStatus")),
                    package_name=_optional_string(item.get("packageName")),
                    collection_url=_optional_string(
                        item.get("collectionURL", item.get("repo"))
                    ),
                    modules=_strings(item.get("modules")),
                    platforms=_strings(item.get("platforms")),
                    cpes=_strings(item.get("cpes")),
                    versions=versions,
                    raw=item,
                )


def descriptions(
    cve_id: str, cve: Mapping[str, Any]
) -> tuple[tuple[str, str | None, bytes, str], ...]:
    output: list[tuple[str, str | None, bytes, str]] = []
    seen: set[tuple[str | None, bytes]] = set()
    for base_pointer, section, _ in _sections(cve):
        values = section.get("descriptions")
        if not isinstance(values, list):
            continue
        for index, item in enumerate(values):
            if not isinstance(item, Mapping):
                continue
            value = item.get("value")
            if not isinstance(value, str):
                continue
            language = item.get("lang", item.get("language"))
            language = language if isinstance(language, str) else None
            raw_bytes = value.encode("utf-8")
            key = (language, raw_bytes)
            if key in seen:
                continue
            seen.add(key)
            description_id = hashlib.sha256(
                cve_id.encode("utf-8")
                + (language or "").encode("utf-8")
                + raw_bytes
            ).hexdigest()
            output.append(
                (
                    description_id,
                    language,
                    raw_bytes,
                    f"{base_pointer}/descriptions/{index}",
                )
            )
    return tuple(output)


def raw_fragment_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def parse_json_line(raw: bytes, *, line_number: int) -> Mapping[str, Any]:
    try:
        root = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ParseError("invalid_json", str(error), "$") from error
    if not isinstance(root, Mapping):
        raise ParseError("expected_object", "top-level JSON is not an object", "$")
    cve = root.get("cve", root)
    if not isinstance(cve, Mapping):
        raise ParseError("missing_cve", "cve object is missing", "$/cve")
    cve_id = cve.get("id", cve.get("cveId", cve.get("cve_id")))
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise ParseError("invalid_cve_id", "valid CVE ID is required", "$/cve/id")
    return cve
