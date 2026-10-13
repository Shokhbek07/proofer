"""A small map of the whole repository, for reviewing one file at a time.

Single-file review misses weaknesses that are judged against other files: a
check the other handlers perform, a helper defined elsewhere (E3, E8). This
builds a deterministic map of entry points, the protections applied to them,
and where functions are defined, then renders the part that matters for one
file. Nothing here decides that something is a weakness; the map only lets the
model compare a handler with its peers.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .agent import wrap_untrusted
from .judge import HELPER_LINES, imported_names
from .workspace import Workspace, WorkspaceError

FAMILY = {
    ".py": "python",
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js",
    ".php": "php",
}

# An identifier names a protection when it mentions authentication,
# authorisation, CSRF, signatures, validation or escaping.
GUARD_WORD = re.compile(
    r"(?i)(auth|login|logged|permi|role|admin|staff|owner|csrf|xsrf|token|signature|"
    r"verify|validat|sanitiz|escape|allow|acl|policy|guard|protect|forbid)"
)
# A comparison with the identity of the caller is an inline ownership check.
IDENTITY = re.compile(
    r"(g\.user|current_user|request\.user|session\[['\"]user|get_jwt_identity\(|"
    r"req\.user|req\.session\.user|res\.locals\.user|\$_SESSION\[)"
)
COMPARES_IDENTITY = "compares a value with the current user"

_PY_ROUTE = re.compile(
    r"^\s*@[\w.]+\.(route|get|post|put|patch|delete|api_route)\(\s*(?:['\"]([^'\"]*)['\"])?"
)
_PY_DECORATOR = re.compile(r"^\s*@([\w.]+)")
_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(")
_JS_ROUTE = re.compile(
    r"\b\w+\.(get|post|put|patch|delete|all)\(\s*(['\"`])([^'\"`]+)\2\s*,(.*)$"
)
_JS_MIDDLEWARE = re.compile(r"([A-Za-z_$][\w$.]*)\s*(?=,)")
_PHP_INPUT = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b")
_CALL = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")

_DEFINITIONS = {
    "python": [re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("), re.compile(r"^\s*class\s+(\w+)")],
    "js": [
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([\w$]+)\s*\("),
        re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*"
            r"(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)"
        ),
        re.compile(r"^\s*(?:module\.)?exports\.([\w$]+)\s*="),
    ],
    "php": [re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+(\w+)\s*\(")],
}
_NOT_CALLS = {
    "if", "for", "while", "switch", "return", "catch", "function", "elif", "and", "or",
    "not", "print", "len", "str", "int", "dict", "list", "set", "isset", "empty", "array",
    "echo", "require", "include", "super", "typeof",
}

MAX_PEER_GUARDS = 10
MAX_ENTRIES_SHOWN = 20
MAX_DEFINITIONS = 6


@dataclass
class Entry:
    path: str
    line: int
    name: str
    route: str
    guards: list[str] = field(default_factory=list)


@dataclass
class ProjectMap:
    entries: list[Entry] = field(default_factory=list)
    definitions: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    families: dict[str, str] = field(default_factory=dict)

    def render(self, ws: Workspace, path: str) -> str:
        """The map as seen from one file, ready to append to its review prompt."""
        family = self.families.get(path)
        if family is None:
            return ""
        sections: list[str] = []

        mine = [e for e in self.entries if e.path == path]
        if mine:
            rows = [
                f"- {e.route} {e.name} (line {e.line}): {', '.join(e.guards) or 'no protection found'}"
                for e in mine[:MAX_ENTRIES_SHOWN]
            ]
            sections.append("Entry points in this file and the protections applied to them:\n"
                            + "\n".join(rows))

        peers = [e for e in self.entries if e.path != path and self.families.get(e.path) == family]
        if len(peers) >= 2:
            uses: Counter[str] = Counter()
            files: dict[str, set[str]] = defaultdict(set)
            for e in peers:
                for g in set(e.guards):
                    uses[g] += 1
                    files[g].add(e.path)
            rows = []
            for guard, count in uses.most_common(MAX_PEER_GUARDS):
                where = self._defined_at(guard.rstrip("()").split(".")[-1], family)
                rows.append(f"- {guard}: {count} of {len(peers)} entry points in "
                            f"{len(files[guard])} file(s){where}")
            if rows:
                sections.append(f"Protections used by the {len(peers)} entry points in other "
                                "files of this project:\n" + "\n".join(rows))

        definitions = self._called_definitions(ws, path, family)
        if definitions:
            sections.append("Definitions of functions this file calls that live in other files:\n"
                            + "\n\n".join(definitions))

        if not sections:
            return ""
        return (
            "Project map, built mechanically from the whole repository. It is context, not "
            f"evidence: report findings only in `{path}` and quote only that file. An entry "
            "point that lacks a protection its peers use is worth checking; it is a weakness "
            "only if this entry point needs that protection.\n"
            + wrap_untrusted("\n\n".join(sections))
        )

    def _defined_at(self, name: str, family: str) -> str:
        places = [p for p in self.definitions.get(name, []) if self.families.get(p[0]) == family]
        return f", defined in {places[0][0]}:{places[0][1]}" if len(places) == 1 else ""

    def _called_definitions(self, ws: Workspace, path: str, family: str) -> list[str]:
        try:
            lines = ws.lines(path)
        except WorkspaceError:
            return []
        already = set(imported_names(lines))  # shown by the prompt's helper definitions
        called: list[str] = []
        for text in lines:
            for full in _CALL.findall(text):
                name = full.split(".")[-1]
                if name not in called and name not in already and name not in _NOT_CALLS:
                    called.append(name)
        # Protections first: they are what a peer comparison is about.
        called.sort(key=lambda n: not GUARD_WORD.search(n))
        blocks: list[str] = []
        for name in called:
            places = [p for p in self.definitions.get(name, []) if self.families.get(p[0]) == family]
            if len(places) != 1 or places[0][0] == path:
                continue  # undefined here, defined in this file, or ambiguous
            where, line = places[0]
            try:
                body = ws.read(where, line, line + HELPER_LINES - 1)
            except WorkspaceError:
                continue
            blocks.append(f"--- {where} (definition of {name}) ---\n{body}")
            if len(blocks) >= MAX_DEFINITIONS:
                break
        return blocks


def build_map(ws: Workspace) -> ProjectMap:
    pmap = ProjectMap()
    definitions: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for rel in ws.files():
        dot = rel.rfind(".")
        family = FAMILY.get(rel[dot:].lower()) if dot != -1 else None
        if family is None:
            continue
        try:
            lines = ws.lines(rel)
        except WorkspaceError:
            continue
        pmap.families[rel] = family
        for n, text in enumerate(lines, start=1):
            for rx in _DEFINITIONS[family]:
                m = rx.match(text)
                if m:
                    definitions[m.group(1)].append((rel, n))
        pmap.entries += {"python": _python_entries, "js": _js_entries, "php": _php_entries}[family](rel, lines)
    pmap.definitions = dict(definitions)
    return pmap


def _guard_calls(lines: list[str]) -> list[str]:
    found: list[str] = []
    for text in lines:
        for full in _CALL.findall(text):
            name = full.split(".")[-1]
            if GUARD_WORD.search(name) and f"{full}()" not in found:
                found.append(f"{full}()")
        if IDENTITY.search(text) and re.search(r"(==|!=|===|!==|\bis\b|\bin\b)", text) \
                and COMPARES_IDENTITY not in found:
            found.append(COMPARES_IDENTITY)
    return found


def _python_entries(path: str, lines: list[str]) -> list[Entry]:
    entries: list[Entry] = []
    pending: list[str] = []
    for i, text in enumerate(lines):
        if _PY_DECORATOR.match(text):
            pending.append(text)
            continue
        m = _PY_DEF.match(text)
        if not m:
            if text.strip() and not text.strip().startswith("#"):
                pending = []
            continue
        routes = [d for d in pending if _PY_ROUTE.match(d)]
        if routes:
            route = _PY_ROUTE.match(routes[0])
            method = route.group(1).upper() if route.group(1) != "route" else "ROUTE"
            guards = [
                name for d in pending if not _PY_ROUTE.match(d)
                for name in [_PY_DECORATOR.match(d).group(1)] if GUARD_WORD.search(name)
            ]
            indent = len(m.group(1))
            body: list[str] = []
            for later in lines[i + 1:]:
                stripped = later.strip()
                if stripped and not stripped.startswith("#") and len(later) - len(later.lstrip()) <= indent:
                    break
                body.append(later)
            guards += [g for g in _guard_calls(body) if g not in guards]
            entries.append(Entry(path, i + 1, m.group(2), f"{method} {route.group(2) or ''}".strip(), guards))
        pending = []
    return entries


def _js_entries(path: str, lines: list[str]) -> list[Entry]:
    starts = [(i, m) for i, text in enumerate(lines) if (m := _JS_ROUTE.search(text))]
    entries: list[Entry] = []
    for k, (i, m) in enumerate(starts):
        end = starts[k + 1][0] if k + 1 < len(starts) else min(len(lines), i + 80)
        rest = m.group(4)
        middleware = [
            name for name in _JS_MIDDLEWARE.findall(rest.split("=>")[0].split("function")[0])
            if name not in ("req", "res", "next", "async")
        ]
        guards = middleware + [g for g in _guard_calls(lines[i + 1:end]) if g not in middleware]
        entries.append(Entry(path, i + 1, "handler", f"{m.group(1).upper()} {m.group(3)}", guards))
    return entries


def _php_entries(path: str, lines: list[str]) -> list[Entry]:
    first = next((i for i, text in enumerate(lines) if _PHP_INPUT.search(text)), None)
    if first is None:
        return []
    return [Entry(path, first + 1, "file", "reads request input", _guard_calls(lines))]
