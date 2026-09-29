# POLICY SYNAPSE benchmark: detecting single-predicate drift

_Synthetic mutation study. Every number below was produced by the command in the provenance section._

- 20 governance intents compiled to 67 surface policies (CI, Gatekeeper admission, Terraform plan, runtime) and evaluated with OPA.
- 801 drifted variants (one predicate, one surface, one mutation operator); 89 are semantically equivalent on the attribute domains and 4 are rejected by OPA's type checker before they could be deployed; both groups are excluded, leaving **708** detectable drifts.
- Reference (unmutated) policies disagreeing with the IR on the exhaustive ground truth: **0 states**, so no method can report a false positive on them.

## Detection of drift

| Method | Detected | Rate | Median states per intent | Median counterexample size (raw → shrunk) |
|---|---|---|---|---|
| Example tests (1 pass + 1 fail fixture per policy) | 403/708 | 56.9% | 2.0 | 0 → 0 |
| Random differential, same budget as PSF (ablation) | 525/708 | 74.2% | 13.0 | 1 → 1 |
| Random differential, 10x PSF budget | 662/708 | 93.5% | 130.0 | 1.0 → 1.0 |
| PSF without the scope sweep (ablation) | 508/708 | 71.8% | 8.0 | 1.0 → 1.0 |
| **PSF boundary suite (mechanism)** | 708/708 | 100.0% | 13.0 | 1.0 → 1.0 |

Counterexample size = attributes that differ from the intent's in-scope, compliant baseline (smaller is easier to act on). "Shrunk" greedily reverts attributes while the drift stays visible.

## By mutation operator

| Mutation | What it models | Detectable | Equivalent | OPA-rejected | example tests | random same budget | random 10x budget | psf without scope sweep | psf |
|---|---|---|---|---|---|---|---|---|---|
| `allowlist_extra` | allowlist gained one extra value | 27 | 0 | 0 | 40.7% | 59.3% | 85.2% | 55.6% | 100.0% |
| `case_fold` | case-insensitive comparison where the intent is exact | 60 | 30 | 0 | 6.7% | 86.7% | 93.3% | 26.7% | 100.0% |
| `drop` | predicate deleted | 139 | 0 | 0 | 48.2% | 82.0% | 95.0% | 61.2% | 100.0% |
| `fail_open` | written as 'not violated', so an absent attribute passes | 114 | 25 | 0 | 0.0% | 62.3% | 89.5% | 52.6% | 100.0% |
| `negate` | comparison inverted (== vs !=, in vs not in, >= vs <) | 139 | 0 | 0 | 100.0% | 79.9% | 95.7% | 100.0% | 100.0% |
| `off_by_one` | strict instead of inclusive bound | 4 | 0 | 0 | 50.0% | 50.0% | 100.0% | 100.0% | 100.0% |
| `prefix` | startswith() instead of equality (registry spoofing) | 45 | 34 | 0 | 0.0% | 60.0% | 100.0% | 20.0% | 100.0% |
| `string_bool` | bool compared with "true" (or string with true) | 41 | 0 | 4 | 100.0% | 68.3% | 90.2% | 100.0% | 100.0% |
| `wrong_path` | attribute read from a plausible but wrong field | 139 | 0 | 0 | 100.0% | 74.8% | 93.5% | 100.0% | 100.0% |

## By enforcement surface

| Surface | Detectable | Equivalent | OPA-rejected | example tests | random same budget | random 10x budget | psf without scope sweep | psf |
|---|---|---|---|---|---|---|---|---|
| admission | 206 | 27 | 2 | 57.3% | 74.8% | 93.7% | 71.4% | 100.0% |
| ci | 206 | 27 | 2 | 57.3% | 74.8% | 93.7% | 71.4% | 100.0% |
| runtime | 179 | 23 | 0 | 57.5% | 72.6% | 92.2% | 72.6% | 100.0% |
| terraform | 117 | 12 | 0 | 54.7% | 74.4% | 94.9% | 71.8% | 100.0% |

## Drift the PSF suite missed

None within the declared attribute domains. This is expected by construction for single-predicate drift (see the README's limitations); the hand-written case study (`reports/drift-case-study.md`) includes drift the suite cannot see.

## Structural comparison with non-testing baselines (by construction, not measured)

| Approach | CI ↔ admission | ↔ Terraform plan | ↔ runtime |
|---|---|---|---|
| Textual checklist | none | none | none |
| OPA at a single enforcement point | n/a (one surface) | n/a | n/a |
| Shared Rego layer (MDPI 2026) | shared code, consistent by construction | needs an input adapter: untested | needs an input adapter: untested |
| PSF differential check | tested against IR | tested against IR | tested against IR |

## Provenance

- commit: `a9903eb4d2958d8a1157696df31b65e24fe1f5ad`
- command: `python -m policy_synapse bench --out reports`
- python: `3.10.6`
- platform: `Windows-10-10.0.26200-SP0`
- opa: `1.21.0`
- intents_sha256: `573df24b71055a1a`
- generated_at: `2026-09-29T08:54:13+00:00`
- seed: `7`
