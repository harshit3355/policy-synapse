package terraform.exposure

import rego.v1

# Hand-written. Bug: `!= false` is undefined when the attribute is absent, so a plan that omits
# public_network_access_enabled (provider default: enabled) passes.
deny contains msg if {
	some rc in input.resource_changes
	rc.change.after.tags["data-class"] in {"confidential", "restricted"}
	rc.change.after.public_network_access_enabled != false
	msg := sprintf("%s must not be public", [rc.address])
}
