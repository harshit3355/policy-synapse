package k8sprodminreplicas

import rego.v1

# Hand-written Gatekeeper template body. Bug: reads the `environment` label, the platform uses `env`.
violation contains {"msg": msg} if {
	obj := input.review.object
	obj.metadata.labels.environment == "prod"
	obj.spec.replicas < 2
	msg := sprintf("prod needs at least 2 replicas, got %d", [obj.spec.replicas])
}
