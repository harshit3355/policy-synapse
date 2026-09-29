"""CLI: compile intents to surface policies, check policies against intents, run the benchmark."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import bench as bench_mod
from . import engine
from .compiler import compile_all
from .ir import load_intents


def _write(base: Path, report: dict, md: str) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    base.with_suffix(".md").write_text(md, encoding="utf-8", newline="\n")
    print(f"wrote {base.with_suffix('.json')} and {base.with_suffix('.md')}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m policy_synapse", description=__doc__)
    ap.add_argument("--intents", default=str(engine.ROOT / "intents" / "intents.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compile", help="emit Rego/Gatekeeper policies for every intent and surface")
    c.add_argument("--out", default="build")
    k = sub.add_parser("check", help="differentially test the policies in a manifest; exit 1 on divergence")
    k.add_argument("manifest", help="policies.json listing {intent, surface, file, decision}")
    k.add_argument("--report", help="write <report>.json and <report>.md")
    b = sub.add_parser("bench", help="run the mutation benchmark")
    b.add_argument("--seed", type=int, default=7)
    b.add_argument("--out", default="reports")
    a = ap.parse_args(argv)

    intents_path = Path(a.intents)
    intents = load_intents(intents_path)
    if a.cmd == "compile":
        manifest = compile_all(intents, Path(a.out))
        print(f"compiled {sum(len(i.surfaces) for i in intents)} policies from {len(intents)} intents -> {manifest}")
        return 0
    if a.cmd == "check":
        rep = engine.check(intents, Path(a.manifest))
        rep["provenance"] = engine.provenance(intents_path, manifest=Path(a.manifest).as_posix())
        for r in rep["intents"]:
            for s in r["surfaces"]:
                if not s["consistent"]:
                    print(f"DIVERGES  {r['intent']} [{s['surface']}] {s['file']}: {s['divergent_states']}"
                          f"/{r['suite_size']} states, e.g. {s['counterexamples'][0]['changed_from_baseline']}")
        print(f"GCS {rep['gcs']}  ({'consistent' if rep['consistent'] else 'divergence found'})")
        if a.report:
            _write(Path(a.report), rep, engine.check_markdown(rep))
        return 0 if rep["consistent"] else 1
    rep = bench_mod.bench(intents, a.seed)
    rep["provenance"] = engine.provenance(intents_path, seed=a.seed)
    for m, x in rep["summary"].items():
        print(f"{m:20s} {x['detected']:4d}/{x['total']}  {x['rate']}")
    _write(Path(a.out) / "benchmark", rep, bench_mod.markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
