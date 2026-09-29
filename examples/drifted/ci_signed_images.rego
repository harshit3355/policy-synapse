package main

import rego.v1

# Hand-written. Bug: the signature annotation is a string ("true"), compared here with a boolean.
deny contains msg if {
	input.metadata.labels.env == "prod"
	not input.metadata.annotations["policy.synapse.io/signed"] == true
	msg := "prod images must be signed"
}
