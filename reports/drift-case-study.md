# Policy consistency report: `examples/drifted/policies.json`

Governance Consistency Score: **0.917**. Divergence found.

| Intent | Surface | File | Fingerprint (intent) | Status | Smallest counterexample |
|---|---|---|---|---|---|
| prod-signed-images | ci | `ci_signed_images.rego` | `37b8aa77e0626666` (`44e2c908699e217f`) | **diverges** on 1/13 | (baseline): intent allow, policy deny |
| prod-approved-registry | runtime | `runtime_prod_registry.rego` | `9584f54e161ad08d` (`19a499580a75cc27`) | **diverges** on 2/14 | image_registry="acrprod.azurecr.io.evil.io": intent deny, policy allow |
| prod-eu-residency | terraform | `tf_eu_residency.rego` | `4f09d0faa36bae8d` (`75593a51b8107540`) | **diverges** on 1/16 | region=<absent>: intent deny, policy allow |
| prod-eu-residency | runtime | `runtime_eu_residency.rego` | `75593a51b8107540` (`75593a51b8107540`) | consistent |  |
| confidential-not-public | terraform | `tf_confidential_not_public.rego` | `043511e66a123330` (`4579a2cedd2b641f`) | **diverges** on 1/13 | public_ingress=<absent>: intent deny, policy allow |
| prod-not-public | runtime | `runtime_prod_not_public.rego` | `10b82918b065ff05` (`10b82918b065ff05`) | consistent |  |
| prod-min-replicas | admission | `gatekeeper_min_replicas.rego` | `23d70db6c5617bec` (`eae0381a481d9d23`) | **diverges** on 2/16 | replicas=0: intent deny, policy allow |
| prod-min-replicas | ci | `ci_min_replicas.rego` | `eae0381a481d9d23` (`eae0381a481d9d23`) | consistent |  |

Counterexamples are shown as the attributes that differ from the intent's in-scope, compliant baseline. The fingerprint hashes the allow/deny vector over the intent's PSF suite; equal fingerprints mean agreement on the suite, not a proof of equivalence.

## Provenance

- commit: `a9903eb4d2958d8a1157696df31b65e24fe1f5ad`
- command: `python -m policy_synapse check examples/drifted/policies.json --report reports/drift-case-study`
- python: `3.10.6`
- platform: `Windows-10-10.0.26200-SP0`
- opa: `1.21.0`
- intents_sha256: `573df24b71055a1a`
- generated_at: `2026-09-29T08:54:14+00:00`
- manifest: `examples/drifted/policies.json`
