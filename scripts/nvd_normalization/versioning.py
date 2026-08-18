"""Version syntax, profiles, branch gates, and three-valued evaluation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from functools import lru_cache
import re
import unicodedata
from typing import Any, Iterable, Sequence

from .rules import (
    PROFILE_VERSION,
    canonical_json,
    is_placeholder,
    normalize_key,
    stable_hash,
)


class Tri(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Segment:
    status: str
    lower: str | None = None
    lower_inclusive: bool | None = None
    lower_arity: str = "not_applicable"
    upper: str | None = None
    upper_inclusive: bool | None = None
    upper_arity: str = "not_applicable"
    exact: str | None = None
    branch_key: str | None = None
    transition_source: str = "literal"
    closure_origin: str | None = None
    breadth_class: str = "bounded"


@dataclass(frozen=True, slots=True)
class CompiledExpression:
    raw_expression: str
    version_kind: str
    version_class: str
    parse_status: str
    parse_error: str | None
    profile: str
    segments: tuple[Segment, ...]
    evidence_tier: str = "primary"
    status: str = "active"
    nvd_range_fields_present: int = 0

    @property
    def semantic_fingerprint(self) -> str:
        return stable_hash(
            {
                "kind": self.version_kind,
                "class": self.version_class,
                "segments": [
                    {
                        "status": item.status,
                        "lower": item.lower,
                        "lower_inclusive": item.lower_inclusive,
                        "lower_arity": item.lower_arity,
                        "upper": item.upper,
                        "upper_inclusive": item.upper_inclusive,
                        "upper_arity": item.upper_arity,
                        "exact": item.exact,
                        "branch_key": item.branch_key,
                        "transition_source": item.transition_source,
                        "closure_origin": item.closure_origin,
                    }
                    for item in self.segments
                ],
            }
        )

    @property
    def constraint_fingerprint(self) -> str:
        """Version geometry without polarity/status for conflict detection."""

        return stable_hash(
            {
                "kind": self.version_kind,
                "class": self.version_class,
                "segments": [
                    {
                        "lower": item.lower,
                        "lower_inclusive": item.lower_inclusive,
                        "lower_arity": item.lower_arity,
                        "upper": item.upper,
                        "upper_inclusive": item.upper_inclusive,
                        "upper_arity": item.upper_arity,
                        "exact": item.exact,
                        "branch_key": item.branch_key,
                        "transition_source": item.transition_source,
                        "closure_origin": item.closure_origin,
                    }
                    for item in self.segments
                ],
            }
        )


@dataclass(frozen=True, slots=True)
class VersionEvaluation:
    state: Tri
    reason: str
    branch_relation: str | None = None


_COMPARATOR_PREFIX = re.compile(r"^\s*[<>=!]")
_COMPARATOR_PART = re.compile(
    r"\s*(<=|>=|!=|=|<|>)\s*([^\s,;<>!=]+)"
)
_BRANCH_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)\.(?:x|\*)\s*$", re.IGNORECASE)
_DOTTED_RE = re.compile(r"^[vV]?\d+(?:\.\d+)*$")
_SEMVER_RE = re.compile(
    r"^[vV]?(0|[1-9]\d*)"
    r"(?:\.(0|[1-9]\d*))?"
    r"(?:\.(0|[1-9]\d*))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_OPENSSL_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)([a-z]*)$", re.IGNORECASE)
_SCM_RE = re.compile(r"^(?:[0-9a-f]{7,64}|r\d+)$", re.IGNORECASE)
_VERSION_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_VERSION_TOKEN_RE = re.compile(r"\d+|[^\W\d_]+", re.UNICODE)
_PRERELEASE_RANK = {
    "dev": -60,
    "snapshot": -50,
    "alpha": -40,
    "a": -40,
    "beta": -30,
    "b": -30,
    "milestone": -25,
    "candidate": -20,
    "pre": -15,
    "preview": -15,
    "rc": -10,
}
_POSTRELEASE_RANK = {
    "post": 10,
    "patch": 10,
    "p": 10,
    "pl": 10,
    "rev": 10,
    "revision": 10,
    "build": 10,
}
_CONTEXT_WORDS = {
    "community",
    "enterprise",
    "final",
    "for",
    "ga",
    "incubating",
    "release",
    "stable",
}


def version_kind(value: str | None) -> str:
    if value is None or not value.strip():
        return "missing"
    raw = value.strip()
    lowered = raw.casefold()
    if lowered in {"-", "n/a"}:
        return "not_applicable"
    if raw == "*":
        return "any_token"
    if lowered in {"all", "all versions", "any version", "any versions"}:
        return "all_token"
    if _COMPARATOR_PREFIX.match(raw):
        return "range_expression"
    if _BRANCH_RE.fullmatch(raw):
        return "branch_wildcard"
    if raw.isdigit():
        return "exact"
    if _SCM_RE.fullmatch(raw):
        return "source_control"
    if any(char.isspace() for char in raw):
        return "opaque"
    return "exact"


@lru_cache(maxsize=65_536)
def _dotted(value: str) -> tuple[int, ...]:
    candidate = value.strip().lstrip("vV")
    if not _DOTTED_RE.fullmatch(candidate):
        raise ValueError("not dotted numeric")
    return tuple(int(item) for item in candidate.split("."))


@lru_cache(maxsize=65_536)
def _semver(value: str) -> tuple[tuple[int, int, int], tuple[tuple[int, Any], ...]]:
    match = _SEMVER_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError("not semver")
    release = (int(match.group(1)), int(match.group(2) or 0), int(match.group(3) or 0))
    prerelease: list[tuple[int, Any]] = []
    if match.group(4):
        for item in match.group(4).split("."):
            prerelease.append((0, int(item)) if item.isdigit() else (1, item.casefold()))
    else:
        prerelease.append((2, ""))
    return release, tuple(prerelease)


def _openssl_patch_rank(value: str) -> tuple[int, ...]:
    if not value:
        return (0,)
    letters = tuple(ord(char) - 96 for char in value.casefold())
    if len(letters) == 1:
        return (letters[0],)
    # OpenSSL follows z with za, zb, ... for long-lived maintenance branches.
    if letters[0] == 26:
        return (26 + sum(letters[1:]),)
    return letters


@lru_cache(maxsize=65_536)
def _openssl(value: str) -> tuple[int, int, int, tuple[int, ...]]:
    match = _OPENSSL_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError("not an OpenSSL version")
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        _openssl_patch_rank(match.group(4)),
    )


@lru_cache(maxsize=65_536)
def _imagemagick(value: str) -> tuple[int, ...]:
    raw = value.strip().rstrip(".")
    if not raw:
        raise ValueError("not an ImageMagick version")
    parts = re.split(r"[._-]", raw)
    if not parts or any(not item.isdigit() for item in parts):
        raise ValueError("not an ImageMagick version")
    return tuple(int(item) for item in parts)


@lru_cache(maxsize=65_536)
def _deb_split(value: str) -> tuple[int, str, str]:
    raw = value.strip()
    epoch = 0
    if ":" in raw:
        epoch_raw, raw = raw.split(":", 1)
        if not epoch_raw.isdigit():
            raise ValueError("invalid Debian epoch")
        epoch = int(epoch_raw)
    if "-" in raw:
        upstream, revision = raw.rsplit("-", 1)
    else:
        upstream, revision = raw, "0"
    if not upstream:
        raise ValueError("empty Debian upstream version")
    return epoch, upstream, revision


def _deb_order(char: str | None) -> int:
    if char == "~":
        return -1
    if char is None:
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _deb_part_compare(left: str, right: str) -> int:
    li = ri = 0
    while li < len(left) or ri < len(right):
        while (
            (li < len(left) and not left[li].isdigit())
            or (ri < len(right) and not right[ri].isdigit())
        ):
            lc = left[li] if li < len(left) and not left[li].isdigit() else None
            rc = right[ri] if ri < len(right) and not right[ri].isdigit() else None
            lo, ro = _deb_order(lc), _deb_order(rc)
            if lo != ro:
                return -1 if lo < ro else 1
            if lc is not None:
                li += 1
            if rc is not None:
                ri += 1
        lzero = li
        while lzero < len(left) and left[lzero] == "0":
            lzero += 1
        rzero = ri
        while rzero < len(right) and right[rzero] == "0":
            rzero += 1
        lend = lzero
        while lend < len(left) and left[lend].isdigit():
            lend += 1
        rend = rzero
        while rend < len(right) and right[rend].isdigit():
            rend += 1
        llen, rlen = lend - lzero, rend - rzero
        if llen != rlen:
            return -1 if llen < rlen else 1
        ldigits, rdigits = left[lzero:lend], right[rzero:rend]
        if ldigits != rdigits:
            return -1 if ldigits < rdigits else 1
        li = lend
        ri = rend
    return 0


def _compare_versions_strict(left: str, right: str, profile: str) -> int:
    if profile == "dotted_numeric":
        left_value, right_value = _dotted(left), _dotted(right)
        width = max(len(left_value), len(right_value))
        left_key = left_value + (0,) * (width - len(left_value))
        right_key = right_value + (0,) * (width - len(right_value))
    elif profile == "semver":
        left_key, right_key = _semver(left), _semver(right)
    elif profile == "openssl":
        left_key, right_key = _openssl(left), _openssl(right)
    elif profile == "imagemagick":
        left_key, right_key = _imagemagick(left), _imagemagick(right)
        width = max(len(left_key), len(right_key))
        left_key = left_key + (0,) * (width - len(left_key))
        right_key = right_key + (0,) * (width - len(right_key))
    elif profile == "deb":
        le, lu, lr = _deb_split(left)
        re_, ru, rr = _deb_split(right)
        if le != re_:
            return -1 if le < re_ else 1
        upstream_result = _deb_part_compare(lu, ru)
        if upstream_result:
            return upstream_result
        return _deb_part_compare(lr, rr)
    else:
        raise ValueError("scheme_unavailable")
    return (left_key > right_key) - (left_key < right_key)


@lru_cache(maxsize=65_536)
def _fallback_version_parts(
    value: str,
) -> tuple[tuple[int, ...], int, tuple[int, ...], tuple[str, ...]]:
    """Split an arbitrary version into release, qualifier, and text axes."""

    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    words = tuple(_VERSION_WORD_RE.findall(normalized))
    tokens = _VERSION_TOKEN_RE.findall(normalized)
    first_number = next(
        (index for index, item in enumerate(tokens) if item.isdigit()),
        None,
    )
    if first_number is None:
        return (), 0, (), words

    release: list[int] = []
    qualifier_index: int | None = None
    for index in range(first_number, len(tokens)):
        token = tokens[index]
        if token.isdigit():
            release.append(int(token))
            continue
        qualifier_index = index
        break
    if qualifier_index is None:
        return tuple(release), 0, (), ()

    qualifier = tokens[qualifier_index]
    if qualifier in _PRERELEASE_RANK:
        rank = _PRERELEASE_RANK[qualifier]
    elif qualifier in _POSTRELEASE_RANK:
        rank = _POSTRELEASE_RANK[qualifier]
    elif qualifier in _CONTEXT_WORDS:
        rank = 0
    else:
        # Unknown suffixes are deterministic post-release qualifiers. Known
        # packaging/context labels above remain neutral.
        rank = 5
    qualifier_numbers = tuple(
        int(token)
        for token in tokens[qualifier_index + 1 :]
        if token.isdigit()
    )
    return tuple(release), rank, qualifier_numbers, ()


def _fallback_version_compare(left: str, right: str) -> int:
    """Total-order fallback for versions unsupported by a named scheme.

    Numeric components are compared index-by-index after splitting on any
    punctuation or whitespace. Missing numeric axes are zero-padded. Word
    components provide a deterministic tie-break only when all numeric axes
    are equal.
    """

    left_release, left_rank, left_qualifier, left_words = (
        _fallback_version_parts(str(left))
    )
    right_release, right_rank, right_qualifier, right_words = (
        _fallback_version_parts(str(right))
    )
    width = max(len(left_release), len(right_release))
    left_key = left_release + (0,) * (width - len(left_release))
    right_key = right_release + (0,) * (width - len(right_release))
    if left_key != right_key:
        return (left_key > right_key) - (left_key < right_key)
    if left_rank != right_rank:
        return (left_rank > right_rank) - (left_rank < right_rank)
    qualifier_width = max(len(left_qualifier), len(right_qualifier))
    left_qualifier_key = left_qualifier + (0,) * (
        qualifier_width - len(left_qualifier)
    )
    right_qualifier_key = right_qualifier + (0,) * (
        qualifier_width - len(right_qualifier)
    )
    if left_qualifier_key != right_qualifier_key:
        return (
            (left_qualifier_key > right_qualifier_key)
            - (left_qualifier_key < right_qualifier_key)
        )
    return (left_words > right_words) - (left_words < right_words)


def compare_versions(left: str, right: str, profile: str) -> int:
    """Compare every concrete version, using scheme semantics when available."""

    try:
        return _compare_versions_strict(left, right, profile)
    except (TypeError, ValueError):
        return _fallback_version_compare(left, right)


def profile_for(
    values: Iterable[str | None],
    *,
    version_type: str | None,
    product_key: str,
) -> str:
    explicit = normalize_key(version_type)
    if explicit in {"semver", "semantic", "semantic_version"}:
        return "semver"
    if explicit in {"deb", "debian"}:
        return "deb"
    if explicit in {"dotted", "dotted_numeric"}:
        return "dotted_numeric"
    if "openssl" in product_key:
        return "openssl"
    if "imagemagick" in product_key or product_key == "image_magick":
        return "imagemagick"
    concrete = [
        value.strip()
        for value in values
        if isinstance(value, str) and value.strip() and not is_placeholder(value)
    ]
    if concrete and all(_DOTTED_RE.fullmatch(value) for value in concrete):
        return "dotted_numeric"
    return "opaque"


def branch_key(value: str | None, profile: str) -> str | None:
    if value is None:
        return None
    if profile == "openssl":
        match = _OPENSSL_RE.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group(1))
        if major >= 3:
            return f"{major}.{int(match.group(2))}"
        return f"{major}.{int(match.group(2))}.{int(match.group(3))}"
    # ImageMagick's major.minor.patch-revision profile is a total-order
    # release comparator.  Treating each patch as an OpenSSL-style parallel
    # maintenance branch turns a concrete exclusion such as <6.9.4-8 into
    # UNKNOWN for 7.0.10-58.  That UNKNOWN then survives an OR of otherwise
    # false NVD CPE ranges.  ImageMagick ranges therefore use the comparator
    # directly and do not participate in the parallel-branch gate.
    return None


def arity_semantics(value: str | None, profile: str, *, explicit_type: bool) -> str:
    if value is None:
        return "not_applicable"
    if _BRANCH_RE.fullmatch(value.strip()):
        return "branch_prefix"
    canonical = {
        "semver": 3,
        "openssl": 3,
        "imagemagick": 4,
    }.get(profile)
    if explicit_type and canonical is not None:
        try:
            if profile == "semver":
                declared = len(value.strip().lstrip("vV").split("-", 1)[0].split("+", 1)[0].split("."))
            elif profile == "openssl":
                declared = 3
            elif profile == "imagemagick":
                # Legacy ImageMagick endpoints use both 6.0.6.2 and 6.0.6-2
                # for the same release revision, and may omit trailing release
                # components.  Successful normalization always yields the
                # canonical four integer axes.
                _imagemagick(value)
                declared = 4
            else:
                declared = len(_dotted(value))
            if declared == canonical:
                return "exact_point"
        except ValueError:
            pass
    if profile in {"openssl", "imagemagick", "deb"}:
        return "exact_point"
    # Public product/version queries treat a concrete dotted endpoint literally:
    # <=4.2 ends at 4.2 (equivalent to 4.2.0 for ordering), not at 4.2.x.
    if profile == "dotted_numeric":
        return "exact_point"
    return "unknown"


def _parse_comparator_expression(
    raw: str,
) -> tuple[str | None, bool | None, str | None, bool | None, str | None]:
    position = 0
    lower = upper = exact = None
    lower_inclusive = upper_inclusive = None
    while position < len(raw):
        while position < len(raw) and (
            raw[position].isspace() or raw[position] in ",;"
        ):
            position += 1
        if position == len(raw):
            break
        match = _COMPARATOR_PART.match(raw, position)
        if match is None:
            raise ValueError("invalid_comparator_expression")
        operator, value = match.group(1), match.group(2).strip()
        if not value:
            raise ValueError("empty_comparator_operand")
        if value[0] in "<>=!":
            # Examples seen in CNA data include ``==``, ``=<`` and ``=>``.
            # They must not silently become exact versions after consuming
            # only the first "=".  Upstream intent is ambiguous, so preserve
            # the raw expression and fail closed as UNPARSED.
            raise ValueError("nested_comparator_operand")
        if operator == "!=":
            raise ValueError("not_equal_requires_disjoint_segments")
        if operator in {">", ">="}:
            if lower is not None:
                raise ValueError("multiple_lower_bounds")
            lower, lower_inclusive = value, operator == ">="
        elif operator in {"<", "<="}:
            if upper is not None:
                raise ValueError("multiple_upper_bounds")
            upper, upper_inclusive = value, operator == "<="
        else:
            if exact is not None or lower is not None or upper is not None:
                raise ValueError("exact_mixed_with_range")
            exact = value
        position = match.end()
        if (
            position < len(raw)
            and not raw[position].isspace()
            and raw[position] not in ",;"
        ):
            raise ValueError("invalid_comparator_separator")
    return lower, lower_inclusive, upper, upper_inclusive, exact


def _cna_structured_upper(
    less_than: str | None,
    less_than_or_equal: str | None,
) -> tuple[str | None, bool | None, str | None]:
    def normalize(
        value: str | None,
        *,
        expected_operator: str,
        field_name: str,
    ) -> tuple[str | None, str | None]:
        if value is None or is_placeholder(value):
            return None, None
        bound = value.strip()
        if not any(token in bound for token in "<>=!"):
            return bound, None
        match = re.fullmatch(r"\s*(<=|>=|!=|<|>|=)\s*([^<>=!]+?)\s*", bound)
        if match is None:
            return None, f"invalid_comparator_token_in_{field_name}"
        operator, operand = match.group(1), match.group(2).strip()
        if operator != expected_operator:
            return None, f"conflicting_comparator_in_{field_name}"
        if not operand:
            return None, f"empty_{field_name}"
        return operand, None

    exclusive, exclusive_error = normalize(
        less_than,
        expected_operator="<",
        field_name="less_than",
    )
    if exclusive_error is not None:
        return None, None, exclusive_error
    inclusive, inclusive_error = normalize(
        less_than_or_equal,
        expected_operator="<=",
        field_name="less_than_or_equal",
    )
    if inclusive_error is not None:
        return None, None, inclusive_error
    if exclusive is not None and inclusive is not None and exclusive != inclusive:
        return None, None, "conflicting_cna_upper_bounds"
    if exclusive is not None:
        return exclusive, False, None
    if inclusive is not None:
        return inclusive, True, None
    return None, None, None


def _unparsed_cna(
    *,
    raw: str,
    status: str,
    less_than: str | None,
    less_than_or_equal: str | None,
    version_type: str | None,
    changes: Sequence[dict[str, Any]],
    kind: str,
    profile: str,
    error: str,
) -> CompiledExpression:
    return CompiledExpression(
        raw_expression=canonical_json(
            {
                "version": raw,
                "status": status,
                "lessThan": less_than,
                "lessThanOrEqual": less_than_or_equal,
                "versionType": version_type,
                "changes": list(changes),
            }
        ),
        version_kind=kind,
        version_class="UNPARSED",
        parse_status="accepted_unparsed",
        parse_error=error,
        profile=profile,
        segments=(Segment(status="unknown"),),
    )


def compile_nvd(
    *,
    cpe_version: str | None,
    status: str,
    product_key: str,
    version_start_including: str | None,
    version_start_excluding: str | None,
    version_end_including: str | None,
    version_end_excluding: str | None,
) -> CompiledExpression:
    raw_version = cpe_version or ""
    kind = version_kind(raw_version)
    lower = version_start_including or version_start_excluding
    upper = version_end_including or version_end_excluding
    fields_present = sum(
        item is not None
        for item in (
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        )
    )
    profile = profile_for(
        (raw_version, lower, upper), version_type=None, product_key=product_key
    )
    if fields_present:
        resolution = "BOUNDED_RANGE" if lower and upper else "UNBOUNDED_RANGE"
        segment = Segment(
            status=status,
            lower=lower,
            lower_inclusive=version_start_including is not None if lower else None,
            lower_arity=arity_semantics(lower, profile, explicit_type=False),
            upper=upper,
            upper_inclusive=version_end_including is not None if upper else None,
            upper_arity=arity_semantics(upper, profile, explicit_type=False),
            branch_key=branch_key(lower or upper, profile),
            breadth_class="bounded" if lower and upper else "unbounded",
        )
    elif raw_version == "*":
        resolution = "CPE_ANY_UNCORROBORATED"
        segment = Segment(status=status, breadth_class="unbounded")
    elif raw_version.casefold() in {"-", "n/a"}:
        resolution = "NOT_APPLICABLE"
        segment = Segment(status=status)
    elif not raw_version:
        resolution = "UNSPECIFIED"
        segment = Segment(status=status, breadth_class="unbounded")
    else:
        resolution = "EXACT"
        segment = Segment(
            status=status,
            exact=raw_version,
            branch_key=branch_key(raw_version, profile),
        )
    return CompiledExpression(
        raw_expression=canonical_json(
            {
                "cpe_version": raw_version,
                "versionStartIncluding": version_start_including,
                "versionStartExcluding": version_start_excluding,
                "versionEndIncluding": version_end_including,
                "versionEndExcluding": version_end_excluding,
            }
        ),
        version_kind=kind,
        version_class=resolution,
        parse_status="parsed",
        parse_error=None,
        profile=profile,
        segments=(segment,),
        nvd_range_fields_present=fields_present,
    )


def compile_cna(
    *,
    version: str | None,
    status: str,
    product_key: str,
    less_than: str | None,
    less_than_or_equal: str | None,
    version_type: str | None,
    changes: Sequence[dict[str, Any]],
) -> CompiledExpression:
    raw = version or ""
    kind = version_kind(raw)
    explicit_type = bool(version_type and version_type.strip())
    profile = profile_for(
        (raw, less_than, less_than_or_equal, *(item.get("at") for item in changes)),
        version_type=version_type,
        product_key=product_key,
    )
    structured_upper, structured_upper_inclusive, upper_error = (
        _cna_structured_upper(less_than, less_than_or_equal)
    )
    if upper_error is not None:
        return _unparsed_cna(
            raw=raw,
            status=status,
            less_than=less_than,
            less_than_or_equal=less_than_or_equal,
            version_type=version_type,
            changes=changes,
            kind=kind,
            profile=profile,
            error=upper_error,
        )
    if (
        structured_upper is not None
        and kind != "range_expression"
        and not is_placeholder(raw)
        and any(token in raw for token in "<>=!")
    ):
        return _unparsed_cna(
            raw=raw,
            status=status,
            less_than=less_than,
            less_than_or_equal=less_than_or_equal,
            version_type=version_type,
            changes=changes,
            kind=kind,
            profile=profile,
            error="invalid_comparator_token_in_cna_version",
        )
    lowered = raw.casefold().strip()
    if lowered in {"all", "all versions", "*"} and not less_than and not less_than_or_equal:
        base = CompiledExpression(
            raw_expression=canonical_json(
                {
                    "version": raw,
                    "status": status,
                    "versionType": version_type,
                    "changes": list(changes),
                }
            ),
            version_kind="all_token" if raw != "*" else "any_token",
            version_class="EXPLICIT_ALL",
            parse_status="parsed",
            parse_error=None,
            profile=profile,
            segments=(Segment(status=status, breadth_class="unbounded"),),
        )
    elif kind == "range_expression":
        try:
            lower, lower_inc, upper, upper_inc, exact = _parse_comparator_expression(raw)
        except ValueError as error:
            return _unparsed_cna(
                raw=raw,
                status=status,
                less_than=less_than,
                less_than_or_equal=less_than_or_equal,
                version_type=version_type,
                changes=changes,
                kind=kind,
                profile=profile,
                error=str(error),
            )
        if structured_upper is not None:
            if exact is not None:
                return _unparsed_cna(
                    raw=raw,
                    status=status,
                    less_than=less_than,
                    less_than_or_equal=less_than_or_equal,
                    version_type=version_type,
                    changes=changes,
                    kind=kind,
                    profile=profile,
                    error="exact_mixed_with_structured_upper",
                )
            if upper is None:
                upper = structured_upper
                upper_inc = structured_upper_inclusive
            else:
                comparison_profile = profile_for(
                    (lower, upper, structured_upper),
                    version_type=version_type,
                    product_key=product_key,
                )
                try:
                    comparison = compare_versions(
                        upper, structured_upper, comparison_profile
                    )
                except ValueError:
                    return _unparsed_cna(
                        raw=raw,
                        status=status,
                        less_than=less_than,
                        less_than_or_equal=less_than_or_equal,
                        version_type=version_type,
                        changes=changes,
                        kind=kind,
                        profile=profile,
                        error="conflicting_inline_and_structured_upper",
                    )
                if comparison > 0:
                    upper = structured_upper
                    upper_inc = structured_upper_inclusive
                elif comparison == 0:
                    upper_inc = bool(upper_inc) and bool(
                        structured_upper_inclusive
                    )
        values = (lower, upper, exact)
        profile = profile_for(values, version_type=version_type, product_key=product_key)
        resolution = (
            "EXACT"
            if exact is not None
            else "BOUNDED_RANGE"
            if lower and upper
            else "UNBOUNDED_RANGE"
        )
        base = CompiledExpression(
            raw_expression=(
                canonical_json(
                    {
                        "version": raw,
                        "status": status,
                        "lessThan": less_than,
                        "lessThanOrEqual": less_than_or_equal,
                        "versionType": version_type,
                        "changes": list(changes),
                    }
                )
                if less_than is not None or less_than_or_equal is not None
                else raw
            ),
            version_kind=kind,
            version_class=resolution,
            parse_status="parsed",
            parse_error=None,
            profile=profile,
            segments=(
                Segment(
                    status=status,
                    lower=lower,
                    lower_inclusive=lower_inc,
                    lower_arity=arity_semantics(
                        lower, profile, explicit_type=explicit_type
                    ),
                    upper=upper,
                    upper_inclusive=upper_inc,
                    upper_arity=arity_semantics(
                        upper, profile, explicit_type=explicit_type
                    ),
                    exact=exact,
                    branch_key=branch_key(exact or lower or upper, profile),
                    breadth_class="bounded" if (exact or (lower and upper)) else "unbounded",
                ),
            ),
        )
    elif less_than is not None or less_than_or_equal is not None:
        lower = None if lowered == "0" or is_placeholder(raw) else raw
        upper = structured_upper
        resolution = (
            "UNSPECIFIED"
            if lower is None and upper is None
            else "BOUNDED_RANGE"
            if lower is not None and upper is not None
            else "UNBOUNDED_RANGE"
        )
        effective_profile = profile_for(
            (lower, upper, *(item.get("at") for item in changes)),
            version_type=version_type,
            product_key=product_key,
        )
        profile = effective_profile
        base = CompiledExpression(
            raw_expression=canonical_json(
                {
                    "version": raw,
                    "status": status,
                    "lessThan": less_than,
                    "lessThanOrEqual": less_than_or_equal,
                    "versionType": version_type,
                    "changes": list(changes),
                }
            ),
            version_kind=kind,
            version_class=resolution,
            parse_status="parsed",
            parse_error=None,
            profile=effective_profile,
            segments=(
                Segment(
                    status=status,
                    lower=lower,
                    lower_inclusive=True if lower else None,
                    lower_arity=arity_semantics(
                        lower, effective_profile, explicit_type=explicit_type
                    ),
                    upper=upper,
                    upper_inclusive=(
                        structured_upper_inclusive if upper else None
                    ),
                    upper_arity=arity_semantics(
                        upper, effective_profile, explicit_type=explicit_type
                    ),
                    branch_key=branch_key(lower or upper, effective_profile),
                    breadth_class=(
                        "bounded"
                        if lower is not None and upper is not None
                        else "unbounded"
                    ),
                ),
            ),
        )
    elif kind == "branch_wildcard":
        base = CompiledExpression(
            raw_expression=raw,
            version_kind=kind,
            version_class="BRANCH_RANGE",
            parse_status="parsed",
            parse_error=None,
            profile=profile,
            segments=(
                Segment(
                    status=status,
                    exact=raw,
                    branch_key=_BRANCH_RE.fullmatch(raw).group(1),  # type: ignore[union-attr]
                    lower_arity="not_applicable",
                    upper_arity="not_applicable",
                ),
            ),
        )
    elif kind == "not_applicable":
        base = CompiledExpression(
            raw_expression=raw,
            version_kind=kind,
            version_class="NOT_APPLICABLE",
            parse_status="parsed",
            parse_error=None,
            profile=profile,
            segments=(Segment(status=status),),
        )
    elif kind == "missing":
        base = CompiledExpression(
            raw_expression="",
            version_kind=kind,
            version_class="UNSPECIFIED",
            parse_status="parsed",
            parse_error=None,
            profile=profile,
            segments=(Segment(status=status, breadth_class="unbounded"),),
        )
    else:
        base = CompiledExpression(
            raw_expression=raw,
            version_kind=kind,
            version_class="EXACT",
            parse_status="parsed",
            parse_error=None,
            profile=profile,
            segments=(
                Segment(
                    status=status,
                    exact=raw,
                    branch_key=branch_key(raw, profile),
                ),
            ),
        )
    if not changes:
        return base
    if len(base.segments) != 1:
        return replace(
            base,
            version_class="UNPARSED",
            parse_status="accepted_unparsed",
            parse_error="changes_base_expression_ambiguous",
            segments=(Segment(status=status),),
        )
    original = base.segments[0]
    transitions: list[tuple[str, str]] = []
    for change in changes:
        at, changed_status = change.get("at"), change.get("status")
        if not isinstance(at, str) or not at.strip() or not isinstance(changed_status, str):
            return replace(
                base,
                version_class="UNPARSED",
                parse_status="accepted_unparsed",
                parse_error="malformed_changes_transition",
                segments=(Segment(status=status),),
            )
        normalized_status = changed_status.strip().casefold()
        if normalized_status not in {"affected", "unaffected", "unknown"}:
            normalized_status = "unknown"
        transitions.append((at.strip(), normalized_status))
    initial_lower = original.lower
    initial_lower_inclusive = original.lower_inclusive
    if initial_lower is None and original.exact is not None:
        initial_lower = original.exact
        initial_lower_inclusive = True
    current_status = status
    try:
        for left, right in zip(transitions, transitions[1:]):
            if compare_versions(left[0], right[0], profile) >= 0:
                raise ValueError("unordered_changes")
        if initial_lower is not None and compare_versions(
            transitions[0][0], initial_lower, profile
        ) < 0:
            raise ValueError("changes_below_initial_version")
        if initial_lower is not None and transitions:
            if compare_versions(transitions[0][0], initial_lower, profile) == 0:
                current_status = transitions.pop(0)[1]
        if original.upper is not None:
            retained: list[tuple[str, str]] = []
            for transition in transitions:
                comparison = compare_versions(
                    transition[0], original.upper, profile
                )
                if comparison > 0 or (
                    comparison == 0 and original.upper_inclusive is False
                ):
                    continue
                retained.append(transition)
            transitions = retained
    except (TypeError, ValueError) as error:
        reason = str(error)
        if reason not in {
            "unordered_changes",
            "changes_below_initial_version",
        }:
            reason = f"changes_comparator_unavailable:{reason}"
        return replace(
            base,
            version_class="UNPARSED",
            parse_status="accepted_unparsed",
            parse_error=reason,
            segments=(Segment(status=status),),
        )
    if not transitions:
        return replace(
            base,
            segments=(
                replace(
                    original,
                    status=current_status,
                ),
            ),
        )
    compiled: list[Segment] = []
    current_lower = initial_lower
    current_lower_inclusive = initial_lower_inclusive
    for at, changed_status in transitions:
        compiled.append(
            replace(
                original,
                status=current_status,
                lower=current_lower,
                lower_inclusive=current_lower_inclusive,
                lower_arity=arity_semantics(
                    current_lower, profile, explicit_type=explicit_type
                ),
                upper=at,
                upper_inclusive=False,
                upper_arity=arity_semantics(at, profile, explicit_type=explicit_type),
                exact=None,
                transition_source="changes",
            )
        )
        current_lower, current_lower_inclusive, current_status = at, True, changed_status
    compiled.append(
        replace(
            original,
            status=current_status,
            lower=current_lower,
            lower_inclusive=current_lower_inclusive,
            lower_arity=arity_semantics(
                current_lower, profile, explicit_type=explicit_type
            ),
            transition_source="changes",
            exact=None,
        )
    )
    return replace(base, segments=tuple(compiled))


def evaluate_segment(
    *,
    candidate: str,
    version_class: str,
    profile: str,
    segment: Segment,
    branch_coverage: str,
    all_branch_keys: Sequence[str] = (),
) -> VersionEvaluation:
    if version_class == "EXPLICIT_ALL":
        return VersionEvaluation(Tri.TRUE, "explicit_all")
    if version_class == "CPE_ANY_UNCORROBORATED":
        return VersionEvaluation(Tri.UNKNOWN, "cpe_any_uncorroborated")
    if version_class == "UNSPECIFIED":
        return VersionEvaluation(Tri.UNKNOWN, "version_unspecified")
    if version_class == "UNPARSED":
        return VersionEvaluation(Tri.UNKNOWN, "version_unparsed")
    if version_class == "NOT_APPLICABLE":
        return VersionEvaluation(Tri.FALSE, "version_not_applicable")
    if version_class == "BRANCH_RANGE":
        match = _BRANCH_RE.fullmatch(segment.exact or "")
        if match is None:
            return VersionEvaluation(Tri.UNKNOWN, "branch_parse_failed")
        prefix = match.group(1)
        if candidate == prefix or candidate.startswith(prefix + "."):
            return VersionEvaluation(Tri.TRUE, "branch_prefix_match", "same_branch")
        # An explicit branch wildcard (for example ``2.2.x``) defines a
        # closed prefix constraint, not an observation from which other
        # branches must be inferred.  A concrete version outside that prefix
        # is therefore false even when the surrounding source does not mark
        # its aggregate branch coverage as complete.  Returning UNKNOWN here
        # made inclusive queries treat every unrelated branch as affected.
        return VersionEvaluation(
            Tri.FALSE, "branch_prefix_mismatch", "lateral_incompatible"
        )
    if segment.exact is not None:
        exact_match = compare_versions(candidate, segment.exact, profile) == 0
        if exact_match:
            return VersionEvaluation(Tri.TRUE, "exact_match", "same_branch")
        return VersionEvaluation(Tri.FALSE, "exact_mismatch", "same_branch")

    candidate_branch = branch_key(candidate, profile)
    segment_branch = segment.branch_key
    if candidate_branch and segment_branch and candidate_branch != segment_branch:
        keys = sorted(set(all_branch_keys))
        if keys and candidate_branch < keys[0]:
            relation = "out_of_range_below"
            if branch_coverage != "complete":
                return VersionEvaluation(
                    Tri.UNKNOWN, "branch_below_coverage", relation
                )
        elif keys and candidate_branch > keys[-1] and segment_branch == keys[-1]:
            relation = "out_of_range_above"
        else:
            relation = "lateral_incompatible"
            if branch_coverage != "complete":
                return VersionEvaluation(
                    Tri.UNKNOWN, "branch_lateral_uncovered", relation
                )
            return VersionEvaluation(Tri.FALSE, "branch_outside_complete_coverage", relation)
    else:
        relation = "same_branch" if candidate_branch else None

    states: list[Tri] = []
    reasons: list[str] = []
    for bound, inclusive, semantics, direction in (
        (segment.lower, segment.lower_inclusive, segment.lower_arity, "lower"),
        (segment.upper, segment.upper_inclusive, segment.upper_arity, "upper"),
    ):
        if bound is None:
            continue
        if semantics == "branch_prefix":
            match = _BRANCH_RE.fullmatch(bound)
            if match is None:
                return VersionEvaluation(Tri.UNKNOWN, "branch_parse_failed")
            prefix = match.group(1)
            prefix_match = candidate == prefix or candidate.startswith(prefix + ".")
            if not prefix_match:
                return VersionEvaluation(
                    Tri.FALSE,
                    "branch_prefix_mismatch",
                    "lateral_incompatible",
                )
            if direction == "lower":
                # ``version=1.x, lessThan=1.20.7`` means the 1.x branch below
                # the concrete upper bound.  The prefix itself is the lower
                # predicate; comparing a concrete version numerically with
                # the literal token ``1.x`` is both unnecessary and wrong.
                continue
            # A wildcard upper endpoint such as ``<=7.0.x`` names the whole
            # 7.0 branch.  It is not a point that can be ordered numerically;
            # membership in the named prefix is the predicate.
            continue
        comparison = compare_versions(candidate, bound, profile)
        excludes = (
            comparison < 0 or (comparison == 0 and inclusive is False)
            if direction == "lower"
            else comparison > 0 or (comparison == 0 and inclusive is False)
        )
        if excludes:
            states.append(Tri.FALSE)
            reasons.append(
                "lower_bound_not_met"
                if direction == "lower"
                else "upper_bound_exceeded"
            )
        else:
            states.append(Tri.TRUE)
            reasons.append("bound_satisfied")
    if Tri.FALSE in states:
        index = states.index(Tri.FALSE)
        return VersionEvaluation(Tri.FALSE, reasons[index], relation)
    if Tri.UNKNOWN in states:
        index = states.index(Tri.UNKNOWN)
        return VersionEvaluation(Tri.UNKNOWN, reasons[index], relation)
    return VersionEvaluation(Tri.TRUE, "range_match", relation)


def tri_and(values: Iterable[Tri]) -> Tri:
    saw_unknown = False
    for value in values:
        if value is Tri.FALSE:
            return Tri.FALSE
        if value is Tri.UNKNOWN:
            saw_unknown = True
    return Tri.UNKNOWN if saw_unknown else Tri.TRUE


def tri_or(values: Iterable[Tri]) -> Tri:
    saw_unknown = False
    for value in values:
        if value is Tri.TRUE:
            return Tri.TRUE
        if value is Tri.UNKNOWN:
            saw_unknown = True
    return Tri.UNKNOWN if saw_unknown else Tri.FALSE
