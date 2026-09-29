"""Test-state generators.

``psf_suite`` is the mechanism: an IR-derived, MC/DC-style boundary suite. Around an
in-scope compliant baseline it varies one referenced attribute at a time across its whole
domain (so every require predicate is the *decisive* one somewhere), and around an
in-scope violating baseline it does the same for scope attributes (so every scope
predicate is decisive too). The others are the baselines it is measured against.
"""
from __future__ import annotations

import itertools
import random

from .ir import Intent
from .model import ATTRS, domain, neutral_state


def key(state: dict) -> tuple:
    return tuple(state[a] for a in ATTRS)


def dedupe(states: list[dict]) -> list[dict]:
    seen, out = set(), []
    for s in states:
        if key(s) not in seen:
            seen.add(key(s))
            out.append(s)
    return out


def _pick(intent: Intent, attr: str, state: dict, want_require0: bool = True) -> object:
    preds = [p for p in intent.scope + intent.require if p.attr == attr]
    r0 = intent.require[0]
    for v in domain(attr):
        t = {**state, attr: v}
        if all(p.holds(t) for p in preds if p is not r0) and (r0.attr != attr or r0.holds(t) == want_require0):
            return v
    raise ValueError(f"{intent.id}: no value of {attr} satisfies the intent's predicates")


def baseline(intent: Intent) -> dict:
    """In scope and compliant: every predicate holds; unreferenced attributes stay neutral."""
    s = neutral_state()
    for a in intent.attrs:
        s[a] = _pick(intent, a, s)
    return s


def violating(intent: Intent) -> dict:
    """The baseline with the first require predicate violated (in scope, so denied)."""
    b = baseline(intent)
    return {**b, intent.require[0].attr: _pick(intent, intent.require[0].attr, b, want_require0=False)}


def psf_suite(intent: Intent, scope_sweep: bool = True) -> list[dict]:
    b = baseline(intent)
    states = [b] + [{**b, a: v} for a in intent.attrs for v in domain(a)]
    if intent.scope and scope_sweep:
        v = violating(intent)
        states += [{**v, a: x} for a in dict.fromkeys(p.attr for p in intent.scope) for x in domain(a)]
    return dedupe(states)


def random_suite(intent: Intent, n: int, rng: random.Random) -> list[dict]:
    """Uniform random values for the intent's attributes (it knows *which* attributes matter)."""
    base = neutral_state()
    return [{**base, **{a: rng.choice(domain(a)) for a in intent.attrs}} for _ in range(n)]


def example_tests(intent: Intent) -> list[dict]:
    """What a typical hand-written policy unit test covers: one passing and one failing fixture."""
    return [baseline(intent), violating(intent)]


def exhaustive(intent: Intent) -> list[dict]:
    """Every combination of the intent's attribute domains: the ground truth for the benchmark."""
    base, attrs = neutral_state(), intent.attrs
    return [{**base, **dict(zip(attrs, combo))} for combo in itertools.product(*(domain(a) for a in attrs))]
