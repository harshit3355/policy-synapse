package main

import rego.v1

# Hand-written and correct.
deny contains msg if {
	input.metadata.labels.env == "prod"
	input.spec.replicas < 2
	msg := "prod needs at least 2 replicas"
}
