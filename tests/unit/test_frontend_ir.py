# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Python frontend and the shared IR.

These test IR *construction* (canonicalization, binder inventory, CFG shape,
locations, error handling, determinism) — not detector true/false positives,
which belong to the detector-author work package.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from scanipy import ir
from scanipy.frontends import PythonFrontend
from scanipy.frontends.resolver import build_import_table, canonical_dotted

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "python" / "ir"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(tmp_path: Path, source: str, name: str = "sample.py") -> ir.IRModule:
    """Write ``source`` to a temp file and parse it (asserting success)."""
    path = tmp_path / name
    path.write_text(source)
    module = PythonFrontend().parse(path)
    assert module is not None
    return module


def _scope(module: ir.IRModule, qualname: str) -> ir.IRFunction:
    for fn in module.functions:
        if fn.qualname == qualname:
            return fn
    raise AssertionError(
        f"scope {qualname!r} not found in {[f.qualname for f in module.functions]}"
    )


def _iter_nodes(node: object) -> Iterator[object]:
    """Yield ``node`` and every nested IR dataclass reachable from it."""
    yield node
    fields = getattr(node, "__dataclass_fields__", None)
    if not fields:
        return
    for field_name in fields:
        value = getattr(node, field_name)
        if isinstance(value, tuple):
            for item in value:
                if hasattr(item, "__dataclass_fields__"):
                    yield from _iter_nodes(item)
        elif hasattr(value, "__dataclass_fields__"):
            yield from _iter_nodes(value)


def _all_in_scope(fn: ir.IRFunction) -> list[object]:
    out: list[object] = []
    for block in fn.body_blocks:
        for stmt in block.statements:
            out.extend(_iter_nodes(stmt))
    return out


def _calls(fn: ir.IRFunction) -> list[ir.IRCall]:
    return [n for n in _all_in_scope(fn) if isinstance(n, ir.IRCall)]


# ---------------------------------------------------------------------------
# Resolver / import canonicalization
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_import_resolution_all_styles(tmp_path: Path) -> None:
    source = (
        "import os\n"
        "import os as o\n"
        "from os import system\n"
        "from os import system as s\n"
        "from subprocess import run\n"
        "import os.path as p\n"
        "def f(x):\n"
        "    os.system(x)\n"
        "    o.system(x)\n"
        "    system(x)\n"
        "    s(x)\n"
        "    run(x)\n"
        "    p.join(x)\n"
    )
    module = _parse(tmp_path, source)
    paths = [c.callee_path for c in _calls(_scope(module, "f"))]
    assert paths == [
        "os.system",
        "os.system",
        "os.system",
        "os.system",
        "subprocess.run",
        "os.path.join",
    ]


@pytest.mark.unit
def test_value_rooted_method_chain(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(conn, sql):\n    conn.cursor.execute(sql)\n")
    call = _calls(_scope(module, "f"))[0]
    assert call.callee_path == "conn.cursor.execute"
    assert isinstance(call.receiver, ir.IRAttribute)
    assert isinstance(call.args[0], ir.IRName)
    assert call.args[0].name == "sql"


@pytest.mark.unit
def test_local_var_not_rewritten(tmp_path: Path) -> None:
    # A local that shadows nothing keeps its bare dotted path.
    module = _parse(tmp_path, "def f(data):\n    data.execute(q)\n")
    assert _calls(_scope(module, "f"))[0].callee_path == "data.execute"


@pytest.mark.unit
def test_attribute_source_canonical(tmp_path: Path) -> None:
    # The `flask.request.*` attribute source must resolve via both import forms.
    module = _parse(tmp_path, "import flask\ndef h():\n    x = flask.request.form\n")
    attrs = [
        n.canonical for n in _all_in_scope(_scope(module, "h")) if isinstance(n, ir.IRAttribute)
    ]
    assert "flask.request.form" in attrs

    module2 = _parse(
        tmp_path, "from flask import request\ndef h():\n    x = request.args\n", "two.py"
    )
    attrs2 = [
        n.canonical for n in _all_in_scope(_scope(module2, "h")) if isinstance(n, ir.IRAttribute)
    ]
    assert "flask.request.args" in attrs2


@pytest.mark.unit
def test_relative_and_star_import_recorded(tmp_path: Path) -> None:
    module = _parse(
        tmp_path,
        "from . import helper\nfrom mod import *\n",
    )
    kinds = {e.kind for e in module.imports.entries}
    assert "name" in kinds  # relative `helper` recorded
    assert "star" in kinds  # star marker recorded
    # A name under a star import is not falsely canonicalized.
    table = module.imports
    assert table.resolve("*") is not None


@pytest.mark.unit
def test_resolver_unit_non_name_root() -> None:
    import ast  # local import keeps ``ast`` out of the IR/test top level

    table = build_import_table([])
    expr = ast.parse("foo().bar", mode="eval").body
    assert canonical_dotted(expr, table) is None


@pytest.mark.unit
def test_import_nested_in_if_is_canonicalized(tmp_path: Path) -> None:
    # Regression: imports guarded by control flow were never canonicalized
    # (silent false negative). `if True: import os.path as p` must still resolve
    # `p.join(x)` to `os.path.join`.
    module = _parse(
        tmp_path,
        "def f(x):\n    if True:\n        import os.path as p\n    p.join(x)\n",
    )
    paths = [c.callee_path for c in _calls(_scope(module, "f"))]
    assert "os.path.join" in paths


@pytest.mark.unit
def test_import_nested_in_try_is_canonicalized(tmp_path: Path) -> None:
    # Regression: an import nested in a `try` body binds in the enclosing scope;
    # `from os import system as s` must resolve `s(x)` to `os.system`.
    module = _parse(
        tmp_path,
        "def f(x):\n    try:\n        from os import system as s\n    except Exception:\n"
        "        pass\n    s(x)\n",
    )
    paths = [c.callee_path for c in _calls(_scope(module, "f"))]
    assert "os.system" in paths


# ---------------------------------------------------------------------------
# Calls / keywords / args
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_keyword_literal_preserved(tmp_path: Path) -> None:
    module = _parse(
        tmp_path,
        "import subprocess\ndef f(x, flag):\n"
        "    subprocess.run(x, shell=True)\n"
        "    subprocess.run(x, shell=flag)\n",
    )
    calls = _calls(_scope(module, "f"))
    literal_kw = calls[0].kwargs[0]
    assert literal_kw.name == "shell"
    assert isinstance(literal_kw.value, ir.IRLiteral)
    assert literal_kw.value.is_constant is True
    assert literal_kw.value.value is True
    var_kw = calls[1].kwargs[0]
    assert isinstance(var_kw.value, ir.IRName)


@pytest.mark.unit
def test_positional_vs_keyword_capture(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(a, b, kw):\n    g(a, b, key=1, **kw)\n")
    call = _calls(_scope(module, "f"))[0]
    assert len(call.args) == 2  # a, b
    kw_names = [kw.name for kw in call.kwargs]
    assert kw_names == ["key", None]  # None marks the **kw splat


# ---------------------------------------------------------------------------
# Scopes / params
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_module_scope_captures_toplevel(tmp_path: Path) -> None:
    module = _parse(tmp_path, "import os\nos.system(input())\n")
    assert module.module_scope.qualname == "<module>"
    paths = sorted(c.callee_path or "" for c in _calls(module.module_scope))
    assert "os.system" in paths
    assert "input" in paths


@pytest.mark.unit
def test_params_first_class(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(a, b, /, c, *args, d, **kw):\n    pass\n")
    params = _scope(module, "f").params
    got = [(p.name, p.kind, p.index) for p in params]
    assert got == [
        ("a", "posonly", 0),
        ("b", "posonly", 1),
        ("c", "arg", 2),
        ("args", "vararg", 3),
        ("d", "kwonly", 4),
        ("kw", "kwarg", 5),
    ]
    assert all(p.location.line >= 1 for p in params)


@pytest.mark.unit
def test_param_defaults_flagged(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(a, b=1, *, c, d=2):\n    pass\n")
    by_name = {p.name: p for p in _scope(module, "f").params}
    assert by_name["a"].has_default is False
    assert by_name["b"].has_default is True
    assert by_name["c"].has_default is False
    assert by_name["d"].has_default is True


@pytest.mark.unit
def test_nested_scope_comprehension_lambda(tmp_path: Path) -> None:
    module = _parse(
        tmp_path,
        "def f(items):\n    a = [g(x) for x in items]\n    h = lambda z: k(z)\n",
    )
    quals = [fn.qualname for fn in module.functions]
    assert "<module>" in quals
    assert "f" in quals
    listcomp = _scope(module, "f.<listcomp>")
    lam = _scope(module, "f.<lambda>")
    f_index = module.functions.index(_scope(module, "f"))
    assert listcomp.parent_index == f_index
    assert lam.parent_index == f_index
    assert lam.is_lambda is True
    # The comprehension target is bound inside the nested scope.
    assert any(
        isinstance(n, ir.IRAssign) and isinstance(n.targets[0], ir.IRNameTarget)
        for n in _all_in_scope(listcomp)
    )


@pytest.mark.unit
def test_classdef_body_inlined_into_enclosing_scope(tmp_path: Path) -> None:
    # Regression: ClassDef statements were silently dropped. A class-level call
    # (a potential source/sink) must appear in the enclosing scope's lowered CFG.
    module = _parse(tmp_path, "class C:\n    y = f(input())\n")
    paths = [c.callee_path for c in _calls(module.module_scope)]
    assert "f" in paths
    assert "input" in paths


@pytest.mark.unit
def test_classdef_methods_remain_own_scope(tmp_path: Path) -> None:
    # The class body is inlined (no class scope), but each method stays its own
    # IRFunction; the class-level call is still captured in the enclosing scope.
    module = _parse(
        tmp_path,
        "class C:\n    y = f(input())\n    def m(self, x):\n        os.system(x)\n",
    )
    quals = [fn.qualname for fn in module.functions]
    assert "<module>" in quals
    assert "m" in quals  # the method is its own scope
    assert "C" not in quals  # the class body is not a scope of its own
    # Class-level call captured in the enclosing (module) scope.
    assert "f" in [c.callee_path for c in _calls(module.module_scope)]
    # The method body lowers its own call.
    assert any(c.callee_path == "os.system" for c in _calls(_scope(module, "m")))


# ---------------------------------------------------------------------------
# Binders
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_binders_tuple_star_walrus_with_except(tmp_path: Path) -> None:
    source = (
        "def f(t):\n"
        "    a, b = t\n"
        "    first, *rest = t\n"
        "    (y := g())\n"
        "    with open() as fh:\n"
        "        use(fh)\n"
        "    try:\n"
        "        pass\n"
        "    except E as e:\n"
        "        use(e)\n"
        "    x.a = t\n"
        "    x[0] = t\n"
    )
    module = _parse(tmp_path, source)
    target_types = {
        type(stmt.targets[0]).__name__
        for stmt in _all_in_scope(_scope(module, "f"))
        if isinstance(stmt, ir.IRAssign)
    }
    assert {
        "IRTupleTarget",
        "IRNameTarget",
        "IRAttrTarget",
        "IRSubscriptTarget",
    } <= target_types
    # The star target is nested inside the tuple target.
    tuples = [
        stmt.targets[0]
        for stmt in _all_in_scope(_scope(module, "f"))
        if isinstance(stmt, ir.IRAssign) and isinstance(stmt.targets[0], ir.IRTupleTarget)
    ]
    assert any(any(isinstance(el, ir.IRStarTarget) for el in t.elements) for t in tuples)


@pytest.mark.unit
def test_augassign_marks_is_aug(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(t):\n    x = ''\n    x += t\n")
    assigns = [n for n in _all_in_scope(_scope(module, "f")) if isinstance(n, ir.IRAssign)]
    aug = [a for a in assigns if a.is_aug]
    assert len(aug) == 1
    assert isinstance(aug[0].targets[0], ir.IRNameTarget)


@pytest.mark.unit
def test_annassign_with_value_binds(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(t):\n    x: int = t\n    y: int\n")
    assigns = [n for n in _all_in_scope(_scope(module, "f")) if isinstance(n, ir.IRAssign)]
    # Only the annotated assignment with a value binds; the bare annotation does not.
    assert len(assigns) == 1
    assert isinstance(assigns[0].targets[0], ir.IRNameTarget)


# ---------------------------------------------------------------------------
# Expression vocabulary
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_fstring_and_binop_exprs(tmp_path: Path) -> None:
    module = _parse(
        tmp_path,
        "def f(name):\n    a = f'x{name}'\n    b = 'a' + name\n    c = '%s' % name\n",
    )
    nodes = _all_in_scope(_scope(module, "f"))
    assert any(isinstance(n, ir.IRJoinedStr) for n in nodes)
    binops = [n for n in nodes if isinstance(n, ir.IRBinOp)]
    ops = sorted(b.op for b in binops)
    assert ops == ["%", "+"]


@pytest.mark.unit
def test_const_vs_dynamic_subscript(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(a, d, i):\n    w = a[0]\n    x = d['k']\n    z = a[i]\n")
    subs = [n for n in _all_in_scope(_scope(module, "f")) if isinstance(n, ir.IRSubscript)]
    const = [(s.is_const_index, s.const_index) for s in subs]
    assert (True, 0) in const
    assert (True, "k") in const
    assert (False, None) in const


@pytest.mark.unit
def test_boolop_and_ifexp(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(a, b):\n    x = a or b\n    y = a if b else c\n")
    nodes = _all_in_scope(_scope(module, "f"))
    assert any(isinstance(n, ir.IRBoolOp) and n.op == "or" for n in nodes)
    assert any(isinstance(n, ir.IRIfExp) for n in nodes)


@pytest.mark.unit
def test_containers(tmp_path: Path) -> None:
    module = _parse(
        tmp_path, "def f(t):\n    a = [t]\n    b = (t,)\n    c = {t}\n    d = {'k': t}\n"
    )
    containers = [n for n in _all_in_scope(_scope(module, "f")) if isinstance(n, ir.IRContainer)]
    kinds = sorted(c.kind for c in containers)
    assert kinds == ["dict", "list", "set", "tuple"]
    dict_c = next(c for c in containers if c.kind == "dict")
    assert dict_c.keys and isinstance(dict_c.keys[0], ir.IRLiteral)


# ---------------------------------------------------------------------------
# CFG shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_if_else_creates_join(tmp_path: Path) -> None:
    module = _parse(
        tmp_path,
        "def f(t):\n    x = 1\n    if t:\n        x = 2\n    else:\n        x = 3\n    use(x)\n",
    )
    fn = _scope(module, "f")
    preds = dict.fromkeys(range(len(fn.body_blocks)), 0)
    for block in fn.body_blocks:
        for succ in block.successors:
            preds[succ] += 1
    assert any(count > 1 for count in preds.values())  # a join block exists


@pytest.mark.unit
def test_loop_has_back_edge(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(items):\n    for x in items:\n        use(x)\n    done()\n")
    fn = _scope(module, "f")
    back_edges = [
        (block.index, succ)
        for block in fn.body_blocks
        for succ in block.successors
        if succ <= block.index
    ]
    assert back_edges  # the loop body links back to the header


@pytest.mark.unit
def test_straight_line_is_one_block(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f():\n    a = 1\n    b = 2\n    c = 3\n")
    assert len(_scope(module, "f").body_blocks) == 1


@pytest.mark.unit
def test_loop_var_and_condition_calls_seen(tmp_path: Path) -> None:
    # Calls inside the iter/test must appear so the engine sees them.
    module = _parse(tmp_path, "def f():\n    for x in get_items():\n        pass\n")
    assert any(c.callee_path == "get_items" for c in _calls(_scope(module, "f")))


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_locations_precise(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def f(x):\n    os.system(x)\n")
    call = _calls(_scope(module, "f"))[0]
    assert call.location.line == 2  # 1-based line
    assert call.location.column == 4  # 0-based column
    assert call.location.end_line == 2
    assert call.location.file.endswith("sample.py")


# ---------------------------------------------------------------------------
# Error handling / resilience
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_syntax_error_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "broken.py"
    path.write_text("def f(:\n    pass\n")
    assert PythonFrontend().parse(path) is None


@pytest.mark.unit
def test_syntax_error_fixture_returns_none() -> None:
    assert PythonFrontend().parse(FIXTURES / "syntax_error.py") is None


@pytest.mark.unit
def test_decode_error_returns_none() -> None:
    assert PythonFrontend().parse(FIXTURES / "bad_bytes.bin") is None


@pytest.mark.unit
def test_null_bytes_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "nul.py"
    path.write_bytes(b"x = 1\x00 = 2\n")
    assert PythonFrontend().parse(path) is None


@pytest.mark.unit
def test_missing_file_returns_none(tmp_path: Path) -> None:
    assert PythonFrontend().parse(tmp_path / "does_not_exist.py") is None


@pytest.mark.unit
def test_deeply_nested_returns_none(tmp_path: Path) -> None:
    # Regression: a parseable-but-deeply-nested file can raise RecursionError
    # while lowering, contradicting the never-raises contract. ``parse`` must catch
    # it and return ``None`` (skip the file) rather than crash. A long attribute
    # chain (``a.b.b.b...``) parses fine but recurses one frame per level in
    # ``lower_expr`` — past the default ~1000 limit it would crash without the fix.
    depth = 3000
    path = tmp_path / "deep.py"
    path.write_text("x = a" + ".b" * depth + "\n")
    assert PythonFrontend().parse(path) is None


@pytest.mark.unit
def test_unknown_node_is_opaque(tmp_path: Path) -> None:
    # ``await`` is not modeled structurally -> IRUnknown, never a crash.
    module = _parse(tmp_path, "async def f(x):\n    y = await g(x)\n")
    nodes = _all_in_scope(_scope(module, "f"))
    assert any(isinstance(n, ir.IRUnknown) for n in nodes)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_determinism_stable(tmp_path: Path) -> None:
    path = tmp_path / "same.py"
    path.write_text("import os\ndef f():\n    os.system(input())\n")
    first = PythonFrontend().parse(path)
    second = PythonFrontend().parse(path)
    assert first == second
    assert hash(first) == hash(second)


@pytest.mark.unit
def test_functions_emitted_in_source_order(tmp_path: Path) -> None:
    module = _parse(tmp_path, "def a():\n    pass\ndef b():\n    pass\ndef c():\n    pass\n")
    names = [fn.name for fn in module.functions]
    assert names == ["<module>", "a", "b", "c"]


# ---------------------------------------------------------------------------
# Bundled fixtures (the corpus the engine will run on)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_bundled_import_styles_fixture() -> None:
    module = PythonFrontend().parse(FIXTURES / "import_styles.py")
    assert module is not None
    paths = sorted(c.callee_path or "" for c in _calls(_scope(module, "styles")))
    assert paths == [
        "conn.cursor.execute",
        "os.path.join",
        "os.system",
        "os.system",
        "os.system",
        "os.system",
        "subprocess.run",
    ]
