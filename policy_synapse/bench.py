"""Mutation study: which testing strategy notices one drifted predicate on one enforcement surface?

Ground truth per intent is the exhaustive product of the intent's attribute domains, evaluated
with OPA. A mutant is *non-equivalent* iff it disagrees with the IR on at least one of those
states; equivalent mutants are reported and excluded from detection rates.
"""
from __future__ import annotations

import random
import statistics
from collections import defaultdict

from .compiler import MUTATIONS, Mutation, applicable, module
from .engine import run
from .ir import Intent
from .model import SURFACES
from .opa import Policy, compile_errors
from .suites import baseline, example_tests, exhaustive, key, psf_suite, random_suite

METHODS = ("example_tests", "random_same_budget", "random_10x_budget", "psf_without_scope_sweep", "psf")


def _dist(s: dict, b: dict, attrs) -> int:
    return sum(s[a] != b[a] for a in attrs)


def _shrink(s: dict, b: dict, attrs, index: dict, wrong: set) -> dict:
    """Greedily move a counterexample back toward the baseline while it still exposes the drift."""
    changed = True
    while changed:
        changed = False
        for a in attrs:
            if s[a] != b[a]:
                t = {**s, a: b[a]}
                if index[key(t)] in wrong:
                    s, changed = t, True
    return s


def bench_intent(intent: Intent, rng: random.Random) -> tuple[list[dict], dict]:
    b, attrs = baseline(intent), intent.attrs
    psf = psf_suite(intent)
    suites = {"example_tests": example_tests(intent), "psf": psf,
              "random_same_budget": random_suite(intent, len(psf), rng),
              "random_10x_budget": random_suite(intent, 10 * len(psf), rng),
              "psf_without_scope_sweep": psf_suite(intent, scope_sweep=False)}
    exh = exhaustive(intent)
    index = {key(s): j for j, s in enumerate(exh)}
    suite_idx = {m: [index[key(s)] for s in st] for m, st in suites.items()}  # every suite state is in exh

    variants: dict[str, tuple[str, Mutation | None]] = {}
    for s in intent.surfaces:
        variants[f"{s}|reference"] = (s, None)
        for part, preds in (("scope", intent.scope), ("require", intent.require)):
            for i, p in enumerate(preds):
                for op in applicable(p):
                    variants[f"{s}|{part}{i}|{op}"] = (s, Mutation(part, i, op))
    pols = {vid: Policy(module(intent, s, "ps.variant", m), SURFACES[s].decision, s)
            for vid, (s, m) in variants.items()}
    # drift OPA's own type checker refuses to load never reaches an enforcement point
    rejected = compile_errors(pols)
    if any(variants[vid][1] is None for vid in rejected):
        raise RuntimeError(f"{intent.id}: a reference policy does not compile: {rejected}")
    dec = run({vid: p for vid, p in pols.items() if vid not in rejected}, exh)
    truth = [intent.denies(s) for s in exh]

    rows, reference_mismatches = [], 0
    for vid, (s, m) in variants.items():
        wrong = set() if vid in rejected else {j for j, (d, t) in enumerate(zip(dec[vid], truth)) if d != t}
        if m is None:
            reference_mismatches += len(wrong)
            continue
        p = (intent.scope if m.part == "scope" else intent.require)[m.index]
        status = "rejected_by_opa" if vid in rejected else "equivalent" if not wrong else "detectable"
        row = {"intent": intent.id, "surface": s, "part": m.part, "index": m.index, "attr": p.attr,
               "pred_op": p.op, "mutation": m.op, "status": status, "opa_error": rejected.get(vid), "methods": {}}
        if status != "detectable":
            rows.append(row)
            continue
        for name in METHODS:
            found = [j for j in suite_idx[name] if j in wrong]
            row["methods"][name] = {
                "detected": bool(found),
                "raw_size": min(_dist(exh[j], b, attrs) for j in found) if found else None,
                "shrunk_size": min(_dist(_shrink(exh[j], b, attrs, index, wrong), b, attrs)
                                   for j in found) if found else None}
        rows.append(row)
    meta = {"intent": intent.id, "surfaces": len(intent.surfaces), "exhaustive_states": len(exh),
            "suite_sizes": {m: len(st) for m, st in suites.items()},
            "reference_mismatches": reference_mismatches}
    return rows, meta


def _rate(rows: list[dict], m: str) -> dict:
    det = sum(r["methods"][m]["detected"] for r in rows)
    return {"detected": det, "total": len(rows), "rate": round(det / len(rows), 4) if rows else None}


def _median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def _by(rows: list[dict], field: str) -> dict:
    groups = defaultdict(list)
    for r in rows:
        groups[r[field]].append(r)
    out = {}
    for k, g in sorted(groups.items()):
        live = [r for r in g if r["status"] == "detectable"]
        out[k] = {"non_equivalent": len(live), "equivalent": sum(r["status"] == "equivalent" for r in g),
                  "rejected_by_opa": sum(r["status"] == "rejected_by_opa" for r in g),
                  **{m: _rate(live, m)["rate"] for m in METHODS}}
    return out


def bench(intents: list[Intent], seed: int) -> dict:
    rng = random.Random(seed)
    rows, metas = [], []
    for i in intents:
        r, m = bench_intent(i, rng)
        rows += r
        metas.append(m)
    live = [r for r in rows if r["status"] == "detectable"]
    summary = {m: {**_rate(live, m),
                   "median_suite_size": _median(x["suite_sizes"][m] for x in metas),
                   "median_raw_counterexample_size": _median(r["methods"][m]["raw_size"] for r in live),
                   "median_shrunk_counterexample_size": _median(r["methods"][m]["shrunk_size"] for r in live)}
               for m in METHODS}
    return {"seed": seed, "intents": len(intents), "surface_policies": sum(x["surfaces"] for x in metas),
            "mutants": len(rows), "equivalent_mutants": sum(r["status"] == "equivalent" for r in rows),
            "rejected_by_opa": [{k: r[k] for k in ("intent", "surface", "attr", "mutation", "opa_error")}
                                for r in rows if r["status"] == "rejected_by_opa"],
            "detectable_mutants": len(live),
            "reference_mismatches": sum(x["reference_mismatches"] for x in metas),
            "summary": summary, "by_mutation": _by(rows, "mutation"), "by_surface": _by(rows, "surface"),
            "psf_misses": [r for r in live if not r["methods"]["psf"]["detected"]],
            "per_intent": metas, "mutants_detail": rows}


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


LABELS = {"example_tests": "Example tests (1 pass + 1 fail fixture per policy)",
          "random_same_budget": "Random differential, same budget as PSF (ablation)",
          "random_10x_budget": "Random differential, 10x PSF budget",
          "psf_without_scope_sweep": "PSF without the scope sweep (ablation)",
          "psf": "**PSF boundary suite (mechanism)**"}


def markdown(rep: dict) -> str:
    s = rep["summary"]
    live = rep["detectable_mutants"]
    L = ["# POLICY SYNAPSE benchmark: detecting single-predicate drift", "",
         "_Synthetic mutation study. Every number below was produced by the command in the provenance section._", "",
         f"- {rep['intents']} governance intents compiled to {rep['surface_policies']} surface policies "
         f"(CI, Gatekeeper admission, Terraform plan, runtime) and evaluated with OPA.",
         f"- {rep['mutants']} drifted variants (one predicate, one surface, one mutation operator); "
         f"{rep['equivalent_mutants']} are semantically equivalent on the attribute domains and "
         f"{len(rep['rejected_by_opa'])} are rejected by OPA's type checker before they could be deployed; both "
         f"groups are excluded, leaving **{live}** detectable drifts.",
         f"- Reference (unmutated) policies disagreeing with the IR on the exhaustive ground truth: "
         f"**{rep['reference_mismatches']} states**, so no method can report a false positive on them.", "",
         "## Detection of drift", "",
         "| Method | Detected | Rate | Median states per intent | Median counterexample size (raw → shrunk) |",
         "|---|---|---|---|---|"]
    for m in METHODS:
        x = s[m]
        L.append(f"| {LABELS[m]} | {x['detected']}/{x['total']} | {_pct(x['rate'])} | {x['median_suite_size']} | "
                 f"{x['median_raw_counterexample_size']} → {x['median_shrunk_counterexample_size']} |")
    L += ["", "Counterexample size = attributes that differ from the intent's in-scope, compliant baseline "
              "(smaller is easier to act on). \"Shrunk\" greedily reverts attributes while the drift stays visible.",
          "", "## By mutation operator", "",
          "| Mutation | What it models | Detectable | Equivalent | OPA-rejected | " + " | ".join(m.replace("_", " ") for m in METHODS)
          + " |", "|---|---|---|---|---|" + "---|" * len(METHODS)]
    for k, v in rep["by_mutation"].items():
        L.append(f"| `{k}` | {MUTATIONS[k]} | {v['non_equivalent']} | {v['equivalent']} | {v['rejected_by_opa']} | "
                 + " | ".join(_pct(v[m]) for m in METHODS) + " |")
    L += ["", "## By enforcement surface", "",
          "| Surface | Detectable | Equivalent | OPA-rejected | " + " | ".join(m.replace("_", " ") for m in METHODS)
          + " |", "|---|---|---|---|" + "---|" * len(METHODS)]
    for k, v in rep["by_surface"].items():
        L.append(f"| {k} | {v['non_equivalent']} | {v['equivalent']} | {v['rejected_by_opa']} | "
                 + " | ".join(_pct(v[m]) for m in METHODS) + " |")
    L += ["", "## Drift the PSF suite missed", ""]
    if rep["psf_misses"]:
        L += ["| Intent | Surface | Predicate | Mutation |", "|---|---|---|---|"]
        L += [f"| {r['intent']} | {r['surface']} | {r['part']}[{r['index']}] {r['attr']} {r['pred_op']} | "
              f"`{r['mutation']}` |" for r in rep["psf_misses"]]
    else:
        L.append("None within the declared attribute domains. This is expected by construction for single-predicate "
                 "drift (see the README's limitations); the hand-written case study "
                 "(`reports/drift-case-study.md`) includes drift the suite cannot see.")
    L += ["", "## Structural comparison with non-testing baselines (by construction, not measured)", "",
          "| Approach | CI ↔ admission | ↔ Terraform plan | ↔ runtime |", "|---|---|---|---|",
          "| Textual checklist | none | none | none |",
          "| OPA at a single enforcement point | n/a (one surface) | n/a | n/a |",
          "| Shared Rego layer (MDPI 2026) | shared code, consistent by construction | needs an input adapter: untested"
          " | needs an input adapter: untested |",
          "| PSF differential check | tested against IR | tested against IR | tested against IR |", "",
          "## Provenance", "", *(f"- {k}: `{v}`" for k, v in rep["provenance"].items()), ""]
    return "\n".join(L)
