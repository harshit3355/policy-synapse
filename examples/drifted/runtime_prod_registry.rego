package deploy.registry

import rego.v1

# Hand-written. Bugs: prefix match accepts look-alike registries, and a workload without an
# env field is denied even though the intent only covers production.
default allow := false

allow if input.workload.env != "prod"

allow if startswith(input.workload.image.registry, "prodregistry.example.com")
