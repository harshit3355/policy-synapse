package deploy.residency

import rego.v1

# Hand-written. Bug: "uksouth" was added to the allowlist. uksouth is outside the declared
# attribute domain, so no generated state can expose it: a known blind spot of the method.
default allow := false

allow if not input.workload.env == "prod"

allow if input.workload.region in {"westeurope", "northeurope", "uksouth"}
