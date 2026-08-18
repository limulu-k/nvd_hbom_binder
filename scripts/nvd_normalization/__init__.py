"""NVD Applicability Framework 3.3 identity-alias implementation."""

from .query_engine import ApplicabilityQuery, QueryEngine, QueryError

__all__ = ["ApplicabilityQuery", "QueryEngine", "QueryError"]
__version__ = "3.3.1"
