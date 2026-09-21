#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_no_swallow.py — enforce the project rule: NO SILENT FAILURES
==================================================================
An `except` block in this repo must do at least ONE of:

  1. re-raise                                   (`raise`)
  2. report loudly                              (`report_error(...)`, `print(...)`,
                                                 logger.warning / error / exception /
                                                 critical, `_emit(...)`, traceback.print_exc)
  3. be a documented control-flow exception     (see EXPECTED below)

and it must NOT be any of:

  SILENT               body is only pass / continue / break / return <constant>
  FALLBACK-NO-REPORT   assigns or returns a fallback and never mentions the error
  DEBUG-ONLY           its only "report" is logger.debug(...) or _log(..., "debug"),
                       which the default INFO log level never shows
  BARE-EXCEPT          `except:` (also traps KeyboardInterrupt / SystemExit)
  SUPPRESS             contextlib.suppress(...)  — the same thing in a `with`
  JS-SWALLOW           a JavaScript catch block, inside the embedded dashboard pages
                       (they live in Python strings), that never reports the error:
                       empty, or only flips a flag.  It must call reportUiError(...),
                       console.error / console.warn, alert(...), or rethrow.  Also flags
                       an empty promise .catch handler.

Documented control-flow exceptions
----------------------------------
Some exceptions are the normal way a loop ticks (an empty queue.get(timeout=...),
the TX-guard self-test tripping on purpose).  Mark the `except` line:

    except queue.Empty:  # expected-exception: idle poll, queue is empty most of the time

The marker needs a reason (>= 10 chars) AND the exception type must be in
EXPECTED_TYPES below.  Anything else has to be reported.  Keep that list short.

Usage
-----
    python tools/check_no_swallow.py                 # scan real_warfare/ train/ tools/
    python tools/check_no_swallow.py path1.py dir2   # scan specific files / folders
Exit code 0 = clean, 1 = violations (so it can gate CI or a pre-commit hook).

test_sdr_sentinel.py imports find_violations() from this file, so the rule is
also enforced by the normal test run.

Limitation (by nature of static analysis): a handler that merely *mentions* the
exception variable (`except E as e: x = str(e)`) is accepted.  Review those by eye.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

# Calls that count as "reporting".  `debug` is deliberately absent.
REPORTING_CALLS = {
    "report_error", "print", "warning", "warn", "error", "exception", "critical",
    "info", "log", "_log", "_emit", "print_exc", "print_exception",
}
# Calls that take a level argument: reporting only if that level is not "debug".
LEVELED_CALLS = {"_log", "_emit", "log"}

# The ONLY exception types allowed to carry an `# expected-exception:` marker.
EXPECTED_TYPES = {"queue.Empty", "_q.Empty", "Empty", "TransmitBlockedError"}

_MARKER = re.compile(r"#\s*expected-exception:\s*(\S.{8,})")

# Embedded browser JS (the dashboards are Python strings, so the AST cannot see them):
# every `catch (...) { ... }` block must report.  Found by regex + brace matching.
_JS_CATCH_OPEN = re.compile(r"\bcatch\s*(?:\(\s*\w*\s*\))?\s*\{")
_JS_REPORTS = re.compile(
    r"\breportUiError\s*\(|\bconsole\s*\.\s*(?:error|warn)\s*\(|\balert\s*\(|\bthrow\b")
_JS_EMPTY_PROMISE_CATCH = re.compile(r"\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)?\s*=>\s*\{\s*\}\s*\)")


def _js_catch_blocks(text):
    """Yield (offset_of_catch, body_text) for each JS catch block, matching braces."""
    for m in _JS_CATCH_OPEN.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += (text[i] == "{") - (text[i] == "}")
            i += 1
        yield m.start(), text[m.end(): i - 1 if depth == 0 else i]


_HAS_UNPARSE = hasattr(ast, "unparse")          # ast.unparse exists from Python 3.9


def _unparse(node) -> str:
    """ast.unparse with a small fallback so the checker also runs on Python 3.8."""
    if _HAS_UNPARSE:
        return ast.unparse(node)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_unparse(node.value)}.{node.attr}"
    if isinstance(node, ast.Tuple):
        return "(" + ", ".join(_unparse(e) for e in node.elts) + ")"
    if isinstance(node, ast.Call):
        return _unparse(node.func) + "(...)"
    return type(node).__name__


def _call_name(call: ast.Call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _is_debug_level(call: ast.Call) -> bool:
    """True if a leveled call was given the literal level "debug"."""
    args = list(call.args) + [kw.value for kw in call.keywords]
    return any(isinstance(a, ast.Constant) and a.value == "debug" for a in args)


def _reports(body) -> bool:
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in REPORTING_CALLS:
                    if name in LEVELED_CALLS and _is_debug_level(node):
                        continue
                    return True
    return False


def _raises(body) -> bool:
    return any(isinstance(n, ast.Raise) for s in body for n in ast.walk(s))


def _trivial(stmt) -> bool:
    if isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
        return True                                   # docstring / Ellipsis
    if isinstance(stmt, ast.Return):
        v = stmt.value
        if v is None or isinstance(v, ast.Constant):
            return True
        if isinstance(v, (ast.Tuple, ast.List, ast.Set)) and not v.elts:
            return True
        if isinstance(v, ast.Dict) and not v.keys:
            return True
    return False


def _uses_name(body, name) -> bool:
    return bool(name) and any(
        isinstance(n, ast.Name) and n.id == name for s in body for n in ast.walk(s))


def _only_debug_calls(body) -> bool:
    """True if the handler logs, but only at debug level (called after _reports() is False)."""
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                n = _call_name(node)
                if n == "debug" or (n in LEVELED_CALLS and _is_debug_level(node)):
                    return True
    return False


def _type_text(h: ast.ExceptHandler) -> str:
    return "bare" if h.type is None else _unparse(h.type)


def _classify(h: ast.ExceptHandler, src_lines):
    """Return a violation kind, or None if the handler is acceptable."""
    body = h.body
    if _raises(body):
        return None                                   # re-raise is always fine
    # documented control-flow exception?
    line = src_lines[h.lineno - 1] if h.lineno - 1 < len(src_lines) else ""
    m = _MARKER.search(line)
    if m and _type_text(h) in EXPECTED_TYPES:
        return None
    if h.type is None:
        return "BARE-EXCEPT"
    if _reports(body):
        return None
    if _only_debug_calls(body):
        return "DEBUG-ONLY"
    if all(_trivial(s) for s in body):
        return "SILENT"
    if not _uses_name(body, h.name):
        return "FALLBACK-NO-REPORT"
    return None


def find_violations(path):
    """[(lineno, kind, 'except <type>')] for one file.  Raises on unreadable/unparsable
    files (a checker that silently skips a file would defeat its own purpose)."""
    text = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    lines = text.splitlines()
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            kind = _classify(node, lines)
            if kind:
                out.append((node.lineno, kind, f"except {_type_text(node)}"))
        elif isinstance(node, ast.With):
            for item in node.items:
                ce = item.context_expr
                if isinstance(ce, ast.Call) and _call_name(ce) == "suppress":
                    out.append((node.lineno, "SUPPRESS", _unparse(ce)))
    for start, body in _js_catch_blocks(text):
        if not _JS_REPORTS.search(body):
            out.append((text.count("\n", 0, start) + 1, "JS-SWALLOW",
                        "JavaScript catch block never reports the error"))
    for m in _JS_EMPTY_PROMISE_CATCH.finditer(text):
        out.append((text.count("\n", 0, m.start()) + 1, "JS-SWALLOW",
                    "empty JavaScript promise .catch handler"))
    return sorted(out)


def default_targets():
    """Return the .py files this checker is responsible for.

    Standard repo layout
    --------------------
    real_warfare/ train/ tools/  all live next to this script's *parent*
    directory (i.e. two levels up from check_no_swallow.py).  Scan those.

    Flat / development layout
    -------------------------
    When all source files live in the same directory (e.g. during a test run
    where everything is copied flat), the standard subdirs either don't exist
    or contain fewer than 5 files combined.  In that case also include every
    *.py in the root directory itself, excluding test_*.py (which deliberately
    contains bad patterns as fixtures) and this checker's own basename.
    """
    root = Path(__file__).resolve().parent.parent
    files = []
    for sub in ("real_warfare", "train", "tools"):
        files += sorted((root / sub).glob("*.py"))
    if len(files) < 5:
        checker_name = Path(__file__).name
        flat = sorted(
            p for p in root.glob("*.py")
            if not p.name.startswith("test_") and p.name != checker_name
        )
        files = sorted(set(files) | set(flat))
    return files


def _expand(paths):
    files = []
    for p in paths:
        p = Path(p)
        files += sorted(p.rglob("*.py")) if p.is_dir() else [p]
    return files


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    files = _expand(argv) if argv else default_targets()
    if not files:
        print("check_no_swallow: khong tim thay file .py nao de kiem tra", file=sys.stderr)
        return 2
    total = 0
    for f in files:
        for lineno, kind, what in find_violations(f):
            total += 1
            print(f"{f}:{lineno}: [{kind}] {what}")
    if total:
        print(f"\ncheck_no_swallow: {total} cho nuot loi. Sua bang report_error(...) hoac raise; "
              f"xem docstring de biet ngoai le hop le.", file=sys.stderr)
        return 1
    print(f"check_no_swallow: OK — {len(files)} file, 0 cho nuot loi.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
