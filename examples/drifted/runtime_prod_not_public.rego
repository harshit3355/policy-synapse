package deploy.exposure

import rego.v1

# Hand-written and correct.
default allow := false

allow if not input.workload.env == "prod"

allow if input.workload.public_ingress == false
