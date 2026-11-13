# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A refusal formats no value it was handed or answered.

Section 7 of the btclib-org standard, *A refusal carries no secret*, says
an argument in the wrong place may be a key. The census reads the sources
and finds every exception the package builds: each call of a name ending
in `Error` or `Exception`, and the exception of each `raise` that is not
what a function of the package returns. Every argument of each has to be
traced to values a refusal may print, and the census fails closed: what
it cannot trace is a finding. It traces

- a literal, a comparison, a name bound by an import, a `def` or a
  `class`, and an attribute named in capitals;
- what `_code`, `_message_text`, `_quoted`, `len`, `type` and `bool`
  answer, what the methods `bit_length`, `count`, `find` and `index`
  answer, and a `__name__` or a `__qualname__`;
- what `_label` answers, where it traces the labels it is handed;
- the index `enumerate` counts from a start it traces, and the one a
  `range` counts from zero or from a start it traces;
- a call, an attribute or an item of what it traces; each element a loop
  or a comprehension takes from it, or `zip` pairs; and in a loop over
  rows written out, the column the name takes;
- a local or module name, where it traces every value the name is bound
  to, what a `with` binds traced as the call it makes, and every value
  put into it anywhere in the scope, by a method such as `append` or by
  an assignment to an item or an attribute;
- a parameter of a private function, where it traces what every call in
  the package passes there;
- what a function of the package answers, where it traces every value
  the function returns or yields, or the item at the position a tuple is
  unpacked from.

A name called is the `def` of the scope that binds it, or the one of the
module of the package it is imported from; an attribute called is every
method of that name in the package. So the census does not trace a
parameter of a public function or of a lambda, a method's `self`, a
function read as a value rather than called, the exception an `except`
binds, or the environment and the arguments of the process. Each of these
holds what a caller, a server or another program handed over, and
reaches a refusal only through `_code`, `_message_text` or `_quoted`, or
not at all.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib_wallet"

# a call whose answer describes what it is handed and holds no byte of it
_DESCRIBING = frozenset({"_code", "_message_text", "_quoted", "len", "type", "bool"})
_DESCRIBING_METHODS = frozenset({"bit_length", "count", "find", "index"})
_DESCRIBING_ATTRIBUTES = frozenset({"__name__", "__qualname__"})
# what a module holds that the process was handed
_PROCESS_INPUT = frozenset({"environ", "argv", "stdin"})
# the methods that put values into a list, a set, a dict or a deque
_MUTATORS = frozenset(
    {
        "add",
        "append",
        "appendleft",
        "extend",
        "extendleft",
        "insert",
        "setdefault",
        "update",
    }
)
_CONSTANT = re.compile(r"_*[A-Z][A-Z0-9_]*")
_FUNCTION = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSION = (ast.ListComp, ast.SetComp, ast.GeneratorExp)
_BINDING = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)
_LOOP = (ast.For, ast.AsyncFor, ast.comprehension)
_DECLARED = (ast.Import, ast.ImportFrom, *_FUNCTION, ast.ClassDef)


def _private(name: str) -> bool:
    return name.startswith("_") and not name.endswith("__")


def _called_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _arguments(func: ast.AST) -> list[ast.arg]:
    args: ast.arguments = func.args  # type: ignore[attr-defined]
    found = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    found.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
    return found


def _own_nodes(scope: ast.AST) -> list[ast.AST]:
    """Return the nodes of a scope, not entering a nested function or class."""
    found: list[ast.AST] = []
    todo = list(ast.iter_child_nodes(scope))
    while todo:
        node = todo.pop()
        found.append(node)
        if isinstance(node, (*_FUNCTION, ast.ClassDef)):
            # its decorators are read in this scope, its body is not
            todo.extend(getattr(node, "decorator_list", []))
            continue
        todo.extend(ast.iter_child_nodes(node))
    return found


def _names(target: ast.AST) -> list[str]:
    return [node.id for node in ast.walk(target) if isinstance(node, ast.Name)]


def _mutates(node: ast.AST, name: str) -> bool:
    """Return whether a node is a call putting values into a named container."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _MUTATORS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == name
    )


def _mutated(node: ast.AST) -> list[str]:
    """Return the names a node puts values into, by a call or an assignment.

    `x.append(v)` puts `v` into `x`, and so do `x[k] = v` and `x.k = v`.
    """
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _MUTATORS
            and isinstance(func.value, ast.Name)
        ):
            return [func.value.id]
        return []
    if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        return []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    found: list[str] = []
    for target in targets:
        for part in ast.walk(target):
            if isinstance(part, (ast.Subscript, ast.Attribute)):
                root = part.value
                while isinstance(root, (ast.Subscript, ast.Attribute)):
                    root = root.value
                if isinstance(root, ast.Name):
                    found.append(root.id)
    return found


def _binds(node: ast.AST, name: str) -> bool:  # noqa: PLR0911
    """Return whether a node binds a name in the scope it belongs to."""
    if _mutates(node, name):
        return True
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return any(name in _names(target) for target in targets)
    if isinstance(node, (*_LOOP, ast.NamedExpr)):
        return name in _names(node.target)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return any(
            item.optional_vars is not None and name in _names(item.optional_vars)
            for item in node.items
        )
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return any((a.asname or a.name).split(".")[0] == name for a in node.names)
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return name in node.names
    if isinstance(
        node,
        (ast.ExceptHandler, ast.MatchAs, ast.MatchStar, *_FUNCTION, ast.ClassDef),
    ):
        return getattr(node, "name", None) == name
    return False


@dataclass
class _Module:
    name: str
    tree: ast.Module
    parents: dict[ast.AST, ast.AST] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node

    def scopes(self, node: ast.AST) -> list[ast.AST]:
        """Return the enclosing functions, innermost first, then the module."""
        found: list[ast.AST] = []
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, _FUNCTION):
                found.append(current)
            current = self.parents.get(current)
        found.append(self.tree)
        return found

    def where(self, node: ast.AST) -> str:
        return f"{self.name}:{getattr(node, 'lineno', 0)}"


# what a value is traced through: a name in the scope that binds it, a
# parameter of a function, or what a private function returns
_Key = tuple[str, int, str]


@dataclass
class _Census:
    modules: list[_Module]
    # the calls of each function of the package, and where it is read as a
    # value, keyed by the id of its `def`
    calls: dict[int, list[tuple[_Module, ast.Call]]] = field(default_factory=dict)
    reads: dict[int, list[tuple[_Module, ast.AST]]] = field(default_factory=dict)
    functions: dict[int, tuple[_Module, ast.AST]] = field(default_factory=dict)
    methods: dict[str, list[ast.AST]] = field(default_factory=dict)
    scopes: dict[int, tuple[_Module, ast.AST]] = field(default_factory=dict)
    nodes: dict[int, list[ast.AST]] = field(default_factory=dict)
    mutations: dict[int, dict[str, list[ast.AST]]] = field(default_factory=dict)
    edges: dict[_Key, tuple[list[str], set[_Key]]] = field(default_factory=dict)
    reached: dict[_Key, frozenset[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:  # noqa: C901
        for module in self.modules:
            for node in ast.walk(module.tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[id(node)] = (module, node)
                    if isinstance(module.parents.get(node), ast.ClassDef):
                        self.methods.setdefault(node.name, []).append(node)
        for module in self.modules:
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Call):
                    for func in self._resolve(node.func, module) or []:
                        self.calls.setdefault(id(func), []).append((module, node))
                elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(
                    node.ctx, ast.Load
                ):
                    parent = module.parents.get(node)
                    if not (isinstance(parent, ast.Call) and parent.func is node):
                        for func in self._resolve(node, module) or []:
                            self.reads.setdefault(id(func), []).append((module, node))

    def _resolve(self, func: ast.expr, module: _Module) -> list[ast.AST] | None:
        """Return the `def`s of the package a callee may be, None where unknown.

        A name is the `def` of the scope that binds it, or the one of the
        module it is imported from. An attribute is every method of that
        name.
        """
        if isinstance(func, ast.Attribute):
            return self.methods.get(func.attr)
        if not isinstance(func, ast.Name):
            return None
        for scope in module.scopes(func):
            bindings = [n for n in self._scope_nodes(scope) if _binds(n, func.id)]
            if isinstance(scope, _FUNCTION) and any(
                arg.arg == func.id for arg in _arguments(scope)
            ):
                return None
            if not bindings:
                continue
            found: list[ast.AST] = []
            for binding in bindings:
                if isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found.append(binding)
                elif isinstance(binding, ast.ImportFrom):
                    found.extend(self._imported(binding, func.id))
                else:
                    return None
            return found or None
        return None

    def _imported(self, node: ast.ImportFrom, name: str) -> list[ast.AST]:
        """Return the `def`s an import of the package binds to a name."""
        source = next(a.name for a in node.names if (a.asname or a.name) == name)
        path = f"{(node.module or '').replace('.', '/')}.py"
        package = path.removesuffix(".py") + "/__init__.py"
        return [
            func
            for module in self.modules
            if module.name in {path, package}
            for func in module.tree.body
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))
            and func.name == source
        ]

    def sites(self) -> list[tuple[_Module, ast.Call]]:
        """Return each exception the package builds, as the call that builds it.

        A `raise` of what a function of the package returns is not one: the
        exception that function builds is.
        """
        found: dict[int, tuple[_Module, ast.Call]] = {}
        for module in self.modules:
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                    if self._resolve(node.exc.func, module) is None:
                        found[id(node.exc)] = (module, node.exc)
                elif isinstance(node, ast.Call):
                    name = _called_name(node.func) or ""
                    if name.endswith(("Error", "Exception")):
                        found[id(node)] = (module, node)
        return sorted(found.values(), key=lambda site: (site[0].name, site[1].lineno))

    def findings(self) -> list[str]:
        """Return each exception built from a value the census cannot trace."""
        found: list[str] = []
        for module, call in self.sites():
            values = [*call.args, *(keyword.value for keyword in call.keywords)]
            untraced = sorted(self.untraced(values, module))
            if untraced:
                found.append(f"{module.where(call)}: " + "; ".join(untraced))
        return found

    def untraced(self, exprs: list[ast.expr], module: _Module) -> set[str]:
        """Return each value the expressions hold that cannot be traced."""
        leaves: list[str] = []
        keys: set[_Key] = set()
        for expr in exprs:
            self._visit(expr, module, leaves, keys)
        found = set(leaves)
        for key in keys:
            found |= self._reach(key)
        return found

    def _visit(  # noqa: C901, PLR0911, PLR0912
        self, expr: ast.AST | None, module: _Module, leaves: list[str], keys: set[_Key]
    ) -> None:
        """Sort what an expression holds into untraced values and keys."""
        if expr is None or isinstance(expr, (ast.Constant, ast.Compare)):
            # nothing, a literal, or a bool whatever it compares
            return
        if isinstance(expr, ast.Name):
            key = self._name_key(expr, module)
            if key is not None:
                keys.add(key)
            return
        if isinstance(expr, ast.Call):
            func = expr.func
            name = _called_name(func) or ""
            if isinstance(func, ast.Name) and name == "_label":
                # an element of the labels it is handed second, or what
                # `_quoted` answers: the labels are what is traced
                labels = [k.value for k in expr.keywords if k.arg != "value"]
                for child in [*expr.args[1:], *labels]:
                    self._visit(child, module, leaves, keys)
                return
            if isinstance(func, ast.Name) and name in _DESCRIBING:
                return
            if isinstance(func, ast.Attribute) and name in _DESCRIBING_METHODS:
                return
            functions = self._resolve(func, module)
            if functions is not None:
                # what a function of the package answers: each value it
                # returns or yields, whichever `def` the call reaches
                keys.update(("returns", id(function), "") for function in functions)
                return
            for child in [func, *expr.args, *(k.value for k in expr.keywords)]:
                self._visit(child, module, leaves, keys)
            return
        if isinstance(expr, ast.Attribute):
            if expr.attr in _DESCRIBING_ATTRIBUTES or _CONSTANT.fullmatch(expr.attr):
                return
            if expr.attr in _PROCESS_INPUT:
                leaves.append(f"{module.where(expr)} {ast.unparse(expr)}")
                return
            self._visit(expr.value, module, leaves, keys)
            return
        if isinstance(expr, (ast.Subscript, ast.NamedExpr, ast.Starred)):
            # an item of what is traced, whichever item
            self._visit(expr.value, module, leaves, keys)
            return
        if isinstance(expr, ast.DictComp):
            self._visit(expr.key, module, leaves, keys)
            self._visit(expr.value, module, leaves, keys)
            return
        if isinstance(expr, _COMPREHENSION):
            # its targets are bound in the enclosing scope, as a loop's are
            self._visit(expr.elt, module, leaves, keys)
            return
        if isinstance(expr, ast.IfExp):
            # the test only chooses
            self._visit(expr.body, module, leaves, keys)
            self._visit(expr.orelse, module, leaves, keys)
            return
        if isinstance(
            expr,
            (
                ast.JoinedStr,
                ast.FormattedValue,
                ast.BinOp,
                ast.UnaryOp,
                ast.BoolOp,
                ast.Tuple,
                ast.List,
                ast.Set,
                ast.Dict,
                ast.Slice,
            ),
        ):
            for node in ast.iter_child_nodes(expr):
                if isinstance(node, ast.expr):
                    self._visit(node, module, leaves, keys)
            return
        leaves.append(f"{module.where(expr)} {ast.unparse(expr)}")

    def _mutations(self, scope: ast.AST) -> dict[str, list[ast.AST]]:
        """Return, by name, the nodes in a scope that put values into it."""
        if id(scope) not in self.mutations:
            found: dict[str, list[ast.AST]] = {}
            for node in ast.walk(scope):
                for name in _mutated(node):
                    found.setdefault(name, []).append(node)
            self.mutations[id(scope)] = found
        return self.mutations[id(scope)]

    def _scope_nodes(self, scope: ast.AST) -> list[ast.AST]:
        if id(scope) not in self.nodes:
            self.nodes[id(scope)] = _own_nodes(scope)
        return self.nodes[id(scope)]

    def _name_key(self, node: ast.Name, module: _Module) -> _Key | None:
        """Return the key of the innermost scope binding a name, or None."""
        for scope in module.scopes(node):
            params = isinstance(scope, _FUNCTION) and any(
                arg.arg == node.id for arg in _arguments(scope)
            )
            if params or any(_binds(n, node.id) for n in self._scope_nodes(scope)):
                self.scopes[id(scope)] = (module, scope)
                return ("name", id(scope), node.id)
        return None

    def _reach(self, start: _Key) -> frozenset[str]:  # noqa: C901, PLR0912
        """Return each untraced value a key reaches, through every key it reads.

        Tarjan's strongly connected components, iterative: a key on a cycle
        reaches what every key of the cycle reaches.
        """
        if start in self.reached:
            return self.reached[start]
        index: dict[_Key, int] = {}
        low: dict[_Key, int] = {}
        stack: list[_Key] = []
        on_stack: set[_Key] = set()
        work: list[tuple[_Key, list[_Key]]] = []

        def enter(key: _Key) -> None:
            index[key] = low[key] = len(index)
            stack.append(key)
            on_stack.add(key)
            work.append((key, sorted(self._edges(key)[1])))

        enter(start)
        while work:
            key, todo = work[-1]
            if todo:
                child = todo.pop()
                if child in self.reached:
                    continue
                if child not in index:
                    enter(child)
                else:
                    # a key whose component is complete is in `reached`, so
                    # one indexed and not there is on the stack
                    low[key] = min(low[key], index[child])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[key])
            if low[key] == index[key]:
                component: list[_Key] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == key:
                        break
                found: set[str] = set()
                for member in component:
                    leaves, children = self._edges(member)
                    found.update(leaves)
                    for child in children:
                        if child not in component:
                            found |= self.reached[child]
                for member in component:
                    self.reached[member] = frozenset(found)
        return self.reached[start]

    def _edges(self, key: _Key) -> tuple[list[str], set[_Key]]:  # noqa: C901, PLR0912
        """Return the untraced values a key holds and the keys it reads."""
        if key not in self.edges:
            leaves: list[str] = []
            keys: set[_Key] = set()
            kind, scope_id, name = key
            if kind == "returns":
                module, func = self.functions[scope_id]
                for node in self._scope_nodes(func):
                    if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                        self._visit(node.value, module, leaves, keys)
            elif kind == "item":
                module, func = self.functions[scope_id]
                position, size = map(int, name.split("/"))
                for node in self._scope_nodes(func):
                    if isinstance(node, ast.Return):
                        value = node.value
                        if isinstance(value, ast.Tuple) and len(value.elts) == size:
                            value = value.elts[position]
                        elif isinstance(value, ast.Call) and (
                            callees := self._resolve(value.func, module)
                        ):
                            # that item of what the function it calls returns
                            keys.update(("item", id(c), name) for c in callees)
                            continue
                        self._visit(value, module, leaves, keys)
                    elif isinstance(node, (ast.Yield, ast.YieldFrom)):
                        self._visit(node.value, module, leaves, keys)
            elif kind == "parameter":
                module, func = self.scopes[scope_id]
                self._parameter(func, name, module, leaves, keys)
            else:
                module, scope = self.scopes[scope_id]
                if isinstance(scope, _FUNCTION) and any(
                    arg.arg == name for arg in _arguments(scope)
                ):
                    keys.add(("parameter", scope_id, name))
                bindings = [n for n in self._scope_nodes(scope) if _binds(n, name)]
                # and what any function the scope holds puts into it
                bindings.extend(
                    node
                    for node in self._mutations(scope).get(name, [])
                    if node not in bindings
                )
                for node in bindings:
                    self._binding(node, name, module, leaves, keys)
            self.edges[key] = (leaves, keys)
        return self.edges[key]

    def _binding(  # noqa: C901
        self,
        node: ast.AST,
        name: str,
        module: _Module,
        leaves: list[str],
        keys: set[_Key],
    ) -> None:
        if _mutates(node, name):
            call = cast("ast.Call", node)
            for value in [*call.args, *(k.value for k in call.keywords)]:
                self._visit(value, module, leaves, keys)
        elif isinstance(node, _BINDING):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if name in _names(target):
                    self._element(target, node.value, name, module, leaves, keys)
        elif isinstance(node, _LOOP):
            self._element(node.target, node.iter, name, module, leaves, keys, loop=True)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            # what the context manager answers, traced as what makes it
            for item in node.items:
                if item.optional_vars is not None and name in _names(
                    item.optional_vars
                ):
                    self._visit(item.context_expr, module, leaves, keys)
        elif not isinstance(node, _DECLARED):
            leaves.append(
                f"{module.where(node)} {name}, bound by {type(node).__name__}"
            )

    def _element(  # noqa: C901, PLR0911, PLR0912
        self,
        target: ast.AST,
        value: ast.expr | None,
        name: str,
        module: _Module,
        leaves: list[str],
        keys: set[_Key],
        *,
        loop: bool = False,
    ) -> None:
        """Sort what the value a target takes the name from holds.

        Where `loop` is set the target takes each element of `value` in turn.
        """
        if loop and isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            counter, args = value.func.id, value.args
            if counter == "range":
                if len(args) > 1:
                    self._visit(args[0], module, leaves, keys)
                return
            if counter == "enumerate" and args and isinstance(target, ast.Tuple):
                index, element = target.elts
                if name in _names(index):
                    # the index, counted from a start that has to be traced
                    for start in [*args[1:], *(k.value for k in value.keywords)]:
                        self._visit(start, module, leaves, keys)
                    return
                self._element(element, args[0], name, module, leaves, keys, loop=True)
                return
            if counter == "zip" and isinstance(target, ast.Tuple):
                for part, iterable in zip(target.elts, args, strict=False):
                    if name in _names(part):
                        self._element(
                            part, iterable, name, module, leaves, keys, loop=True
                        )
                        return
        if (
            loop
            and isinstance(target, ast.Tuple)
            and isinstance(value, (ast.Tuple, ast.List))
            and all(
                isinstance(row, ast.Tuple) and len(row.elts) == len(target.elts)
                for row in value.elts
            )
        ):
            # a loop over rows written out: the name takes its column
            position = next(
                i for i, part in enumerate(target.elts) if name in _names(part)
            )
            for row in value.elts:
                row_items = cast("ast.Tuple", row).elts
                self._element(
                    target.elts[position],
                    row_items[position],
                    name,
                    module,
                    leaves,
                    keys,
                )
            return
        if (
            not loop
            and isinstance(target, ast.Tuple)
            and isinstance(value, ast.Tuple)
            and len(target.elts) == len(value.elts)
        ):
            # the name is in the target, so in one of its parts
            part, item = next(
                (part, item)
                for part, item in zip(target.elts, value.elts, strict=True)
                if name in _names(part)
            )
            self._element(part, item, name, module, leaves, keys)
            return
        if not loop and isinstance(target, ast.Tuple) and isinstance(value, ast.Call):
            functions = self._resolve(value.func, module)
            position = next(
                (i for i, part in enumerate(target.elts) if name in _names(part)), 0
            )
            if functions is not None and isinstance(target.elts[position], ast.Name):
                # the item of each tuple a function returns, at that position
                keys.update(
                    ("item", id(function), f"{position}/{len(target.elts)}")
                    for function in functions
                )
                return
        self._visit(value, module, leaves, keys)

    def _parameter(  # noqa: C901
        self,
        func: ast.AST,
        name: str,
        module: _Module,
        leaves: list[str],
        keys: set[_Key],
    ) -> None:
        """Sort what every call of the package passes to a parameter."""
        arg = next(arg for arg in _arguments(func) if arg.arg == name)
        func_name = getattr(func, "name", "a lambda")
        origin = f"{module.where(arg)} parameter {name} of {func_name}"
        func_args: ast.arguments = func.args  # type: ignore[attr-defined]
        positional = [*func_args.posonlyargs, *func_args.args]
        bound = bool(positional) and positional[0].arg in {"self", "cls"}
        if not _private(func_name) or arg in {func_args.vararg, func_args.kwarg}:
            leaves.append(origin)
            return
        if bound and arg is positional[0]:
            # the object a method is called on, which no call passes
            leaves.append(origin)
            return
        if id(func) in self.reads:
            # read as a value, it is called where the census cannot see
            reader, read = self.reads[id(func)][0]
            leaves.append(f"{origin}, read at {reader.where(read)}")
            return
        calls = self.calls.get(id(func), [])
        if not calls:
            leaves.append(f"{origin}, never called")
        for caller, call in calls:
            if any(isinstance(a, ast.Starred) for a in call.args) or any(
                k.arg is None for k in call.keywords
            ):
                leaves.append(f"{origin}, unpacked at {caller.where(call)}")
                continue
            passed = [k.value for k in call.keywords if k.arg == name]
            if arg in positional:
                position = positional.index(arg)
                if bound and isinstance(call.func, ast.Attribute):
                    position -= 1
                if 0 <= position < len(call.args):
                    passed.append(call.args[position])
            for value in passed:
                self._visit(value, caller, leaves, keys)


def _census(sources: dict[str, str]) -> _Census:
    return _Census([_Module(name, ast.parse(text)) for name, text in sources.items()])


def _library() -> dict[str, str]:
    return {
        path.relative_to(_LIBRARY.parent).as_posix(): path.read_text()
        for path in sorted(_LIBRARY.rglob("*.py"))
    }


def test_no_refusal_formats_a_value() -> None:
    """Each exception the package builds formats only what the census traces."""
    findings = _census(_library()).findings()
    assert not findings, "\n".join(findings)


# one module per shape the docstring claims, each refusing `key`, a public
# function's parameter, or a value made from it: the census traces the
# first of each pair and flags the second
_SHAPES = {
    "literal": (
        "def f(key):\n    raise ValueError('a literal')",
        "def f(key):\n    raise ValueError(key)",
    ),
    "comparison": (
        "def f(key):\n    raise ValueError(f'{key == 1}')",
        "def f(key):\n    raise ValueError(f'{key + 1}')",
    ),
    "capitals": (
        "import m\ndef f(key):\n    raise ValueError(m.LIMIT)",
        "def f(key):\n    raise ValueError(key.limit)",
    ),
    "describing call": (
        "def f(key):\n    raise ValueError(_quoted(key), len(key), _code(key))",
        "def f(key):\n    raise ValueError(str(key))",
    ),
    "describing method": (
        "def f(key):\n    raise ValueError(key.count(';'), key.bit_length())",
        "def f(key):\n    raise ValueError(key.hex())",
    ),
    "name attribute": (
        "def f(key):\n    raise ValueError(type(key).__name__, key.__qualname__)",
        "def f(key):\n    raise ValueError(key.__doc__)",
    ),
    "enumerate": (
        "def f(keys):\n    for i, key in enumerate(keys):\n        raise ValueError(i)",
        (
            "def f(keys):\n    for i, key in enumerate(keys):\n"
            "        raise ValueError(key)"
        ),
    ),
    "enumerate start": (
        (
            "def f(keys):\n    for i, key in enumerate(keys, 1):\n"
            "        raise ValueError(i)"
        ),
        (
            "def f(keys, start):\n    for i, key in enumerate(keys, start):\n"
            "        raise ValueError(i)"
        ),
    ),
    "range": (
        "def f(n):\n    for i in range(n):\n        raise ValueError(i)",
        "def f(n, start):\n    for i in range(start, n):\n        raise ValueError(i)",
    ),
    "zip": (
        (
            "def f(keys):\n    for name, key in zip(('a',), keys):\n"
            "        raise ValueError(name)"
        ),
        (
            "def f(keys):\n    for name, key in zip(('a',), keys):\n"
            "        raise ValueError(key)"
        ),
    ),
    "rows": (
        (
            "def f(key):\n    for value, name in ((key, 'a'),):\n"
            "        raise ValueError(name)"
        ),
        (
            "def f(key):\n    for value, name in ((key, 'a'),):\n"
            "        raise ValueError(value)"
        ),
    ),
    "comprehension": (
        "def f(keys):\n    raise ValueError([len(key) for key in keys])",
        "def f(keys):\n    raise ValueError([key for key in keys])",
    ),
    "local name": (
        "def f(key):\n    text = 'a'\n    raise ValueError(text)",
        "def f(key):\n    text = 'a'\n    text = key\n    raise ValueError(text)",
    ),
    "with": (
        (
            "def _open():\n    return 'a'\n"
            "def f(key):\n    with _open() as text:\n        raise ValueError(text)"
        ),
        "def f(key):\n    with open(key) as text:\n        raise ValueError(text)",
    ),
    "mutator": (
        (
            "def f(key):\n    names = []\n    names.append('a')\n"
            "    raise ValueError(names)"
        ),
        (
            "def f(key):\n    names = []\n    names.append(key)\n"
            "    raise ValueError(names)"
        ),
    ),
    "item assignment": (
        (
            "def f(key):\n    names = {}\n    names['a'] = 'b'\n"
            "    raise ValueError(names)"
        ),
        (
            "def f(key):\n    names = {}\n    def g():\n        names['a'] = key\n"
            "    raise ValueError(names)"
        ),
    ),
    "private parameter": (
        "def _g(text):\n    raise ValueError(text)\ndef f(key):\n    _g('a')",
        "def _g(text):\n    raise ValueError(text)\ndef f(key):\n    _g(key)",
    ),
    "never called": (
        "def _g(text):\n    raise ValueError(len(text))",
        "def _g(text):\n    raise ValueError(text)",
    ),
    "read as a value": (
        "def _g(text):\n    raise ValueError(len(text))\nTABLE = {'a': _g}",
        "def _g(text):\n    raise ValueError(text)\nTABLE = {'a': _g}",
    ),
    "lambda": (
        "def f(key):\n    g = lambda text: ValueError(len(text))",
        "def f(key):\n    g = lambda text: ValueError(text)",
    ),
    "self": (
        "class C:\n    def _m(self):\n        raise ValueError(type(self))",
        "class C:\n    def _m(self):\n        raise ValueError(self)",
    ),
    "except": (
        (
            "def f(key):\n    try:\n        pass\n    except OSError as e:\n"
            "        raise ValueError(type(e).__name__) from e"
        ),
        (
            "def f(key):\n    try:\n        pass\n    except OSError as e:\n"
            "        raise ValueError(str(e)) from e"
        ),
    ),
    "environment": (
        "import os\ndef f(key):\n    raise ValueError(len(os.environ))",
        "import os\ndef f(key):\n    raise ValueError(os.environ['HOME'])",
    ),
    "arguments": (
        "import sys\ndef f(key):\n    raise ValueError(len(sys.argv))",
        "import sys\ndef f(key):\n    raise ValueError(sys.argv[0])",
    ),
    "returns": (
        "def _g(key):\n    return 'a'\ndef f(key):\n    raise ValueError(_g(key))",
        "def _g(key):\n    return key\ndef f(key):\n    raise ValueError(_g(key))",
    ),
    "item": (
        (
            "def _g(key):\n    return 'a', key\ndef f(key):\n"
            "    name, value = _g(key)\n    raise ValueError(name)"
        ),
        (
            "def _g(key):\n    return 'a', key\ndef f(key):\n"
            "    name, value = _g(key)\n    raise ValueError(value)"
        ),
    ),
    "item forwarded": (
        (
            "def _g(key):\n    return 'a', key\ndef _h(key):\n    return _g(key)\n"
            "def f(key):\n    name, value = _h(key)\n    raise ValueError(name)"
        ),
        (
            "def _g(key):\n    return 'a', key\ndef _h(key):\n    return _g(key)\n"
            "def f(key):\n    name, value = _h(key)\n    raise ValueError(value)"
        ),
    ),
    "method": (
        (
            "class C:\n    def _m(self, text):\n        raise ValueError(text)\n"
            "def f(key, c):\n    c._m('a')"
        ),
        (
            "class C:\n    def _m(self, text):\n        raise ValueError(text)\n"
            "def f(key, c):\n    c._m(key)"
        ),
    ),
    "raise of a call": (
        (
            "def _error(key):\n    return ValueError(len(key))\n"
            "def f(key):\n    raise _error(key)"
        ),
        (
            "def _error(key):\n    return ValueError(key)\n"
            "def f(key):\n    raise _error(key)"
        ),
    ),
    "label": (
        "LABELS = ('a',)\ndef f(key):\n    raise ValueError(_label(key, LABELS))",
        "def f(key):\n    raise ValueError(_label(key, (key,)))",
    ),
    "error name": (
        "def f(key):\n    return KeyError('a')",
        "def f(key):\n    return KeyError(key)",
    ),
    "dict comprehension": (
        "def f(keys):\n    raise ValueError({len(k): len(k) for k in keys})",
        "def f(keys):\n    raise ValueError({k: 1 for k in keys})",
    ),
    "expression the census does not read": (
        "def f(key):\n    raise ValueError('a literal')",
        "def f(key):\n    raise ValueError(lambda: 1)",
    ),
    "chained assignment": (
        "def f(key):\n    a = b = len(key)\n    raise ValueError(a, b)",
        "def f(key):\n    a = b = key\n    raise ValueError(a, b)",
    ),
    "with of several items": (
        "def f(key):\n    with open('a') as h, lock():\n        raise ValueError(h)",
        "def f(key):\n    with open(key) as h, lock():\n        raise ValueError(h)",
    ),
    "zip of fewer iterables than names": (
        (
            "def f(key):\n    for a, b, c in zip((1,), (2,)):\n"
            "        raise ValueError(c)"
        ),
        (
            "def f(key):\n    for a, b, c in zip((1,), (key,)):\n"
            "        raise ValueError(c)"
        ),
    ),
    "tuple from a tuple": (
        "def f(key):\n    a, b = 1, len(key)\n    raise ValueError(b)",
        "def f(key):\n    a, b = 1, key\n    raise ValueError(b)",
    ),
    "tuple from a call outside the package": (
        "def f(key):\n    a, b = divmod(1, 2)\n    raise ValueError(a)",
        "def f(key):\n    a, b = divmod(key, 2)\n    raise ValueError(a)",
    ),
    "tuple from a generator": (
        (
            "def _g():\n    yield 1\n    yield 2\n"
            "def f(key):\n    a, b = _g()\n    raise ValueError(a)"
        ),
        (
            "def _g(key):\n    yield key\n    yield 2\n"
            "def f(key):\n    a, b = _g(key)\n    raise ValueError(a)"
        ),
    ),
    "arguments unpacked": (
        "def _g(x):\n    raise ValueError(x)\ndef f(keys):\n    _g(1)",
        "def _g(x):\n    raise ValueError(x)\ndef f(keys):\n    _g(*keys)",
    ),
}


@pytest.mark.parametrize("traced, flagged", _SHAPES.values(), ids=_SHAPES)
def test_census_controls(traced: str, flagged: str) -> None:
    """The census traces one module of a shape and flags the other."""
    assert not _census({"m.py": traced}).findings()
    assert _census({"m.py": flagged}).findings()
