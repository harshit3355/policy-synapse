from policy_synapse.engine import check
from policy_synapse.ir import load_intents

from conftest import INTENTS, ROOT

EXPECTED_CONSISTENT = {
    "ci_signed_images.rego": False,
    "runtime_prod_registry.rego": False,
    "tf_eu_residency.rego": False,
    "runtime_eu_residency.rego": True,  # its drift ("uksouth") is outside the attribute domain: known blind spot
    "gatekeeper_min_replicas.rego": False,
    "ci_min_replicas.rego": True,
    "tf_confidential_not_public.rego": False,
    "runtime_prod_not_public.rego": True,
}


def test_hand_written_drift_case_study():
    rep = check(load_intents(INTENTS), ROOT / "examples" / "drifted" / "policies.json")
    assert {s["file"]: s["consistent"] for r in rep["intents"] for s in r["surfaces"]} == EXPECTED_CONSISTENT
