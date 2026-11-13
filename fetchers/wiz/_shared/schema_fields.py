#!/usr/bin/env python3
"""
Build GraphQL selections from the fields a tenant's schema really has.

Some Wiz fetchers cover modules (Wiz Defend, Runtime Sensor, Attack Surface
Management, Wiz Code) that the tenant used to build this category could not
exercise with real data. Rather than guess field names and fail on the first
customer run, those fetchers ask the tenant's own schema (``__type``, read-only
introspection) which of the wanted fields exist and select only those. Fields
that are missing are reported in the evidence, so a reviewer sees exactly what
was and was not collected.

If introspection itself is unavailable, the wanted selection is used as
written and the evidence says the schema could not be checked.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from wiz_client import WizClient

# A field is a name, or (name, [sub-fields]) for an object field.
FieldSpec = Union[str, Tuple[str, Sequence["FieldSpec"]]]

_TYPE_QUERY = """
{ __type(name: "%s") {
    fields { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
    inputFields { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
} }
"""


def _base(t: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    while t and not t.get("name") and t.get("ofType"):
        t = t["ofType"]
    return t or {}


class Schema:
    """Caches ``__type`` lookups for one run. Lookups never count as collection failures."""

    def __init__(self, client: WizClient) -> None:
        self.client = client
        self._cache: Dict[str, Optional[Dict[str, str]]] = {}
        self.unavailable = False

    def _lookup(self, type_name: str, key: str) -> Optional[Dict[str, str]]:
        cache_key = f"{key}:{type_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        if not type_name.replace("_", "").isalnum():
            raise ValueError(f"unexpected GraphQL type name {type_name!r}")
        before = len(self.client.api_failures)
        data = self.client.graphql("__type", _TYPE_QUERY % type_name)
        del self.client.api_failures[before:]
        t = (data or {}).get("__type")
        if data is None:
            self.unavailable = True
        fields = None
        if t is not None:
            fields = {f["name"]: _base(f.get("type")).get("name") or "" for f in (t.get(key) or [])}
        self._cache[cache_key] = fields
        return fields

    def fields(self, type_name: str) -> Optional[Dict[str, str]]:
        """{field name: base type name}, or None when the type could not be read."""
        return self._lookup(type_name, "fields")

    def input_fields(self, type_name: str) -> Optional[Dict[str, str]]:
        return self._lookup(type_name, "inputFields")

    def selection(self, type_name: str, spec: Sequence[FieldSpec], path: str = "",
                  fallback: Optional[Sequence[FieldSpec]] = None) -> Tuple[str, List[str]]:
        """
        GraphQL selection text for ``spec`` limited to fields ``type_name`` has,
        plus the dotted names of wanted fields that were left out. When the
        type cannot be read, ``fallback`` (fields known from Wiz's published
        reference) is used as written, or ``spec`` when no fallback is given.
        """
        have = self.fields(type_name)
        if have is None and fallback is not None:
            return _as_written(fallback), []
        parts: List[str] = []
        missing: List[str] = []
        for item in spec:
            name, sub = (item, None) if isinstance(item, str) else (item[0], item[1])
            dotted = f"{path}{name}"
            if have is not None and name not in have:
                missing.append(dotted)
                continue
            if sub is None:
                parts.append(name)
                continue
            child_type = (have or {}).get(name, "")
            if have is not None and child_type:
                inner, inner_missing = self.selection(child_type, sub, dotted + ".")
            else:
                inner, inner_missing = _as_written(sub), []
            missing.extend(inner_missing)
            if inner:
                parts.append(f"{name} {{ {inner} }}")
            else:
                missing.append(dotted)
        return " ".join(parts), missing


def _as_written(spec: Sequence[FieldSpec]) -> str:
    out = []
    for item in spec:
        if isinstance(item, str):
            out.append(item)
        else:
            out.append(f"{item[0]} {{ {_as_written(item[1])} }}")
    return " ".join(out)


def connection_query(operation: str, root: str, filter_type: Optional[str], selection: str,
                     extra_args: str = "") -> str:
    """A paginated read query over ``root`` with the given node selection."""
    var_decl = "$first: Int, $after: String" + (f", $filterBy: {filter_type}" if filter_type else "")
    args = "first: $first, after: $after" + (", filterBy: $filterBy" if filter_type else "") + extra_args
    return (f"query {operation}({var_decl}) {{ {root}({args}) {{ nodes {{ {selection} }} "
            "pageInfo { hasNextPage endCursor } } }")
