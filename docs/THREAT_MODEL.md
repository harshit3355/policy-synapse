# Threat model

POLICY SYNAPSE runs in CI next to the policies it checks. It never enforces anything itself;
its output is a report and an exit code that a pipeline can gate on.

## Assets

- The allow/deny behaviour of each enforcement surface (CI, admission, Terraform plan, runtime).
- The CI job's environment: repository token, cloud credentials, other secrets.
- The integrity of the consistency report used as audit evidence.

## Trust boundaries

| Input | Trust | Why |
|---|---|---|
| `intents/intents.json` | trusted, code-reviewed | it *is* the specification; a wrong intent makes every surface "consistent" with the wrong thing |
| Attribute bindings in `policy_synapse/model.py` | trusted, code-reviewed | a wrong binding hides drift on that attribute for every surface |
| Policy files under `check` | **untrusted code** | hand-edited by many teams; may be careless or hostile |
| OPA binary | trusted, version-pinned | CI installs a pinned release; locally the SHA-256 is checked against the release checksum |

## Threats and controls

| Threat | Control |
|---|---|
| A policy under test calls `http.send` / `net.lookup_ip_addr` to reach the network (e.g. cloud metadata) during CI | OPA runs with a capabilities file that removes these builtins; such a policy fails to compile (`tests/test_opa.py`) |
| A policy reads CI secrets via `opa.runtime()` | removed from the capabilities file as well |
| Two policies share `package main` and silently merge rules | every module is renamed to a unique package before evaluation |
| A policy fails to define the decision rule, so it "never denies" | `check` raises instead of treating the missing rule as allow |
| Drift outside the declared attribute domains (e.g. a new region) passes as consistent | not controlled: documented limitation; widen domains when the platform adds values |
| A tampered report is presented as evidence | reports record commit SHA, command, seed, OPA version and intents hash; regenerate from the commit to verify |
| Supply-chain compromise of CI actions | all third-party actions are pinned by commit SHA; workflow token is read-only |

## Out of scope for v0.1

Live Gatekeeper/cluster installation, Kyverno, cloud-native policy engines (Azure Policy, AWS Config),
and signing of reports.
