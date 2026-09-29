"""Governance-intent IR and its reference semantics (the oracle every surface is compared against).

An intent denies a state iff every scope predicate holds and at least one require predicate
does not. A predicate over a MISSING attribute is false (fail closed): an absent attribute
never proves compliance and never places a resource in scope.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .model import ATTRS, MISSING, SURFACES

OPS = ("eq", "ne", "in", "not_in", "le", "ge", "is_true", "is_false")


@dataclass(frozen=True)
class Pred:
    attr: str
    op: str
    value: object = None  # str | int | tuple[str, ...]

    def holds(self, state: dict) -> bool:
        x = state[self.attr]
        if x is MISSING:
            return False
        return {
            "eq": lambda: x == self.value,
            "ne": lambda: x != self.value,
            "in": lambda: x in self.value,
            "not_in": lambda: x not in self.value,
            "le": lambda: x <= self.value,
            "ge": lambda: x >= self.value,
            "is_true": lambda: x is True,
            "is_false": lambda: x is False,
        }[self.op]()


@dataclass(frozen=True)
class Intent:
    id: str
    title: str
    criticality: int  # 1 (low) .. 3 (high); weights the Governance Consistency Score
    surfaces: tuple[str, ...]
    scope: tuple[Pred, ...]
    require: tuple[Pred, ...]

    def denies(self, state: dict) -> bool:
        return all(p.holds(state) for p in self.scope) and not all(p.holds(state) for p in self.require)

    @property
    def attrs(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(p.attr for p in self.scope + self.require))


def _pred(raw: list) -> Pred:
    attr, op, *rest = raw
    value = rest[0] if rest else None
    return Pred(attr, op, tuple(value) if isinstance(value, list) else value)


def _validate(i: Intent) -> None:
    if not i.require:
        raise ValueError(f"{i.id}: needs at least one require predicate")
    for p in i.scope + i.require:
        if p.attr not in ATTRS or p.op not in OPS:
            raise ValueError(f"{i.id}: unknown attribute or op in {p}")
        t = ATTRS[p.attr].type
        if (p.op in ("is_true", "is_false")) != (t == "bool") or (p.op in ("le", "ge")) != (t == "int"):
            raise ValueError(f"{i.id}: op {p.op} does not fit {t} attribute {p.attr}")
    for s in i.surfaces:
        missing = [a for a in i.attrs if a not in SURFACES[s].bindings]
        if missing:
            raise ValueError(f"{i.id}: surface {s} has no binding for {missing}")


def load_intents(path: str | Path) -> list[Intent]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    intents = [Intent(d["id"], d["title"], d["criticality"], tuple(d["surfaces"]),
                      tuple(map(_pred, d.get("scope", []))), tuple(map(_pred, d["require"])))
               for d in doc["intents"]]
    for i in intents:
        _validate(i)
    return intents
