package terraform.residency

import rego.v1

# Hand-written. Two bugs: "uksouth" was added to the allowlist (invisible to the suite, see
# runtime_eu_residency.rego), and `not <absent field> in <set>` never fires in OPA, so a plan
# without a location passes.
allowed_regions := {"westeurope", "northeurope", "uksouth"}

deny contains msg if {
	some rc in input.resource_changes
	rc.change.after.tags.env == "prod"
	not rc.change.after.location in allowed_regions
	msg := "production must stay in approved regions"
}
