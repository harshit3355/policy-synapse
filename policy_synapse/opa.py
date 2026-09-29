"""Thin wrapper over the `opa` CLI: evaluate many policy modules on many inputs in one process."""
from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def opa_bin() -> str:
    for c in (os.environ.get("OPA_BIN"), shutil.which("opa"), ROOT / ".tools" / "opa.exe", ROOT / ".tools" / "opa"):
        if c and Path(c).is_file():
            return str(c)
    raise RuntimeError("opa not found: set OPA_BIN, put opa on PATH, or place the binary in .tools/")


def opa_version() -> str:
    out = subprocess.run([opa_bin(), "version"], capture_output=True, text=True, check=True).stdout
    return out.splitlines()[0].split(":", 1)[1].strip()


# Policies under test are untrusted code: no network, no environment (CI secrets) during evaluation.
BLOCKED_BUILTINS = {"http.send", "net.lookup_ip_addr", "opa.runtime"}


@functools.lru_cache(maxsize=None)
def _capabilities() -> str:
    run = subprocess.run([opa_bin(), "capabilities", "--current"], capture_output=True, text=True, check=True)
    caps = json.loads(run.stdout)
    caps["builtins"] = [b for b in caps["builtins"] if b["name"] not in BLOCKED_BUILTINS]
    return json.dumps(caps)


def _opa(tmp: str, *args: str) -> subprocess.CompletedProcess:
    caps = Path(tmp, "capabilities.json")
    caps.write_text(_capabilities(), encoding="utf-8")
    return subprocess.run([opa_bin(), *args[:1], "--capabilities", str(caps), *args[1:]], capture_output=True, text=True)


@dataclass(frozen=True)
class Policy:
    text: str  # Rego module source, any package name
    decision: str  # "deny" | "violation" (set rules) or "allow" (boolean rule)
    surface: str  # which encoded input list this policy is evaluated against


def _write_modules(mods: Path, policies: dict[str, Policy]) -> None:
    mods.mkdir()
    for k, (pid, p) in enumerate(policies.items()):
        # rename the package so unrelated policies (e.g. several `package main`) never merge
        text, n = re.subn(r"^package\s+\S+", f"package ps_eval.p{k}", p.text, count=1, flags=re.M)
        if not n:
            raise ValueError(f"{pid}: no package declaration")
        (mods / f"p{k}.rego").write_text(text, encoding="utf-8")


def compile_errors(policies: dict[str, Policy]) -> dict[str, str]:
    """Policies that `opa check` (parser + type checker) rejects, with the first error message."""
    ids = list(policies)
    with tempfile.TemporaryDirectory() as tmp:
        mods = Path(tmp, "policies")
        _write_modules(mods, policies)
        run = _opa(tmp, "check", "-f", "json", str(mods))
    if run.returncode == 0:
        return {}
    errors = {}
    for e in json.loads(run.stdout or run.stderr)["errors"]:
        k = int(re.search(r"p(\d+)\.rego$", e["location"]["file"]).group(1))
        errors.setdefault(ids[k], e["message"])
    return errors


def evaluate(policies: dict[str, Policy], inputs: dict[str, list[dict]]) -> dict[str, list[bool]]:
    """Return, per policy id, whether each input of its surface is denied."""
    ids = list(policies)
    harness = ["package harness", "import rego.v1"]
    with tempfile.TemporaryDirectory() as tmp:
        mods = Path(tmp, "policies")
        _write_modules(mods, policies)
        for k, pid in enumerate(ids):
            p = policies[pid]
            ref = f"data.ps_eval.p{k}.{p.decision}"
            expr = ref if p.decision == "allow" else f"count({ref}) > 0"
            harness.append(f"results[{json.dumps(pid)}] := {{i: d | some i, c in input[{json.dumps(p.surface)}]; "
                           f"d := {expr} with input as c}}")
        (mods / "harness.rego").write_text("\n".join(harness) + "\n", encoding="utf-8")
        inp = Path(tmp, "input.json")
        inp.write_text(json.dumps(inputs), encoding="utf-8")
        run = _opa(tmp, "eval", "-d", str(mods), "-i", str(inp), "-f", "json", "data.harness.results")
    if run.returncode:
        raise RuntimeError(f"opa eval failed:\n{run.stderr or run.stdout}")
    results = json.loads(run.stdout)["result"][0]["expressions"][0]["value"]
    out = {}
    for pid in ids:
        p, got = policies[pid], results.get(pid, {})
        n = len(inputs[p.surface])
        if p.decision == "allow":  # an undefined `allow` means deny
            out[pid] = [not got.get(str(i), False) for i in range(n)]
        elif len(got) != n:  # a deny/violation set is always defined, possibly empty
            raise ValueError(f"{pid}: rule `{p.decision}` is not defined by this policy")
        else:
            out[pid] = [got[str(i)] for i in range(n)]
    return out
