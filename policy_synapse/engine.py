"""Differential check: run each surface's policy on the PSF suite, compare with the IR and with each other."""
from __future__ import annotations

import datetime
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

from . import opa
from .ir import Intent
from .model import SURFACES
from .suites import baseline, psf_suite

ROOT = opa.ROOT


def run(policies: dict[str, opa.Policy], states: list[dict]) -> dict[str, list[bool]]:
    surfaces = {p.surface for p in policies.values()}
    return opa.evaluate(policies, {s: [SURFACES[s].encode(st) for st in states] for s in surfaces})


def fingerprint(intent_id: str, denied: list[bool]) -> str:
    """Policy Semantic Fingerprint: hash of the intent id and the allow/deny vector over its PSF suite."""
    return hashlib.sha256((intent_id + ":" + "".join("D" if d else "A" for d in denied)).encode()).hexdigest()[:16]


def gcs(rows: list[tuple[int, float]]) -> float:
    """Governance Consistency Score: criticality-weighted mean of per-intent agreement."""
    total = sum(c for c, _ in rows)
    return round(sum(c * a for c, a in rows) / total, 4) if total else 1.0


def provenance(intents_path: Path, **extra) -> dict:
    def git(*args):
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    sha = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--", "policy_synapse", "intents", "examples"))
    return {"commit": (sha or "unknown") + ("-dirty" if dirty else ""),
            "command": "python -m policy_synapse " + " ".join(sys.argv[1:]),
            "python": platform.python_version(), "platform": platform.platform(),
            "opa": opa.opa_version(),
            "intents_sha256": hashlib.sha256(intents_path.read_bytes()).hexdigest()[:16],
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            **extra}


def check(intents: list[Intent], manifest: Path) -> dict:
    entries = json.loads(manifest.read_text(encoding="utf-8"))["policies"]
    known = {i.id for i in intents}
    unknown = sorted({e["intent"] for e in entries} - known)
    if unknown:
        raise ValueError(f"manifest references unknown intents: {unknown}")
    results = []
    for intent in intents:
        mine = [e for e in entries if e["intent"] == intent.id]
        if not mine:
            continue
        states, b = psf_suite(intent), baseline(intent)
        ref = [intent.denies(s) for s in states]
        pols = {e["file"]: opa.Policy((manifest.parent / e["file"]).read_text(encoding="utf-8"), e["decision"],
                                      e["surface"]) for e in mine}
        dec = run(pols, states)
        surfaces = []
        for e in mine:
            bits = dec[e["file"]]
            diffs = sorted((j for j, (x, y) in enumerate(zip(bits, ref)) if x != y),
                           key=lambda j: sum(states[j][a] != b[a] for a in intent.attrs))
            surfaces.append({
                "surface": e["surface"], "file": e["file"], "fingerprint": fingerprint(intent.id, bits),
                "consistent": not diffs, "divergent_states": len(diffs),
                "counterexamples": [{
                    "changed_from_baseline": {a: states[j][a] for a in intent.attrs if states[j][a] != b[a]},
                    "state": {a: states[j][a] for a in intent.attrs},
                    "intent_says": "deny" if ref[j] else "allow",
                    "policy_says": "deny" if bits[j] else "allow"} for j in diffs[:3]]})
        agree = sum(all(dec[e["file"]][j] == ref[j] for e in mine) for j in range(len(states))) / len(states)
        results.append({"intent": intent.id, "title": intent.title, "criticality": intent.criticality,
                        "suite_size": len(states), "baseline": {a: b[a] for a in intent.attrs},
                        "reference_fingerprint": fingerprint(intent.id, ref), "agreement": round(agree, 4),
                        "surfaces": surfaces})
    return {"gcs": gcs([(r["criticality"], r["agreement"]) for r in results]),
            "consistent": all(s["consistent"] for r in results for s in r["surfaces"]),
            "intents": results}


def _fmt(state: dict) -> str:
    return ", ".join(f"{k}={'<absent>' if v is None else json.dumps(v)}" for k, v in state.items()) or "(baseline)"


def check_markdown(report: dict) -> str:
    p = report["provenance"]
    lines = [f"# Policy consistency report: `{p['manifest']}`", "",
             f"Governance Consistency Score: **{report['gcs']}**. "
             f"{'All surfaces agree with the intents.' if report['consistent'] else 'Divergence found.'}", "",
             "| Intent | Surface | File | Fingerprint (intent) | Status | Smallest counterexample |",
             "|---|---|---|---|---|---|"]
    for r in report["intents"]:
        for s in r["surfaces"]:
            cx = s["counterexamples"][0] if s["counterexamples"] else None
            status = "consistent" if s["consistent"] else f"**diverges** on {s['divergent_states']}/{r['suite_size']}"
            detail = (f"{_fmt(cx['changed_from_baseline'])}: intent {cx['intent_says']}, policy {cx['policy_says']}"
                      if cx else "")
            lines.append(f"| {r['intent']} | {s['surface']} | `{s['file']}` | `{s['fingerprint']}` "
                         f"(`{r['reference_fingerprint']}`) | {status} | {detail} |")
    lines += ["", "Counterexamples are shown as the attributes that differ from the intent's in-scope, compliant "
                  "baseline. The fingerprint hashes the allow/deny vector over the intent's PSF suite; equal "
                  "fingerprints mean agreement on the suite, not a proof of equivalence.", "",
              "## Provenance", "", *(f"- {k}: `{v}`" for k, v in p.items()), ""]
    return "\n".join(lines)
