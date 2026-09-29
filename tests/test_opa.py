"""Checks that need the real OPA engine: compiler correctness and the mechanism's key claims."""
import pytest

from policy_synapse.compiler import Mutation, module
from policy_synapse.engine import run
from policy_synapse.ir import load_intents
from policy_synapse.model import SURFACES
from policy_synapse.opa import Policy, compile_errors
from policy_synapse.suites import example_tests, exhaustive, psf_suite

from conftest import INTENTS

ALL = load_intents(INTENTS)
BY_ID = {i.id: i for i in ALL}


def _policy(intent, surface, mutation=None):
    return Policy(module(intent, surface, "t.p", mutation), SURFACES[surface].decision, surface)


def _detected(intent, surface, mutation, states):
    return run({"m": _policy(intent, surface, mutation)}, states)["m"] != [intent.denies(s) for s in states]


@pytest.mark.parametrize("intent", ALL, ids=lambda i: i.id)
def test_compiled_policies_match_the_ir_on_every_state(intent):
    states = exhaustive(intent)
    truth = [intent.denies(s) for s in states]
    for surface, denied in run({s: _policy(intent, s) for s in intent.surfaces}, states).items():
        assert denied == truth, surface


def test_fail_open_drift_is_invisible_to_example_tests_but_not_to_psf():
    i, m = BY_ID["prod-baseline"], Mutation("require", 3, "fail_open")  # owner != "" on the Terraform plan
    assert not _detected(i, "terraform", m, example_tests(i))
    assert _detected(i, "terraform", m, psf_suite(i))


def test_scope_sweep_is_what_catches_scope_drift():
    i, m = BY_ID["prod-signed-images"], Mutation("scope", 0, "case_fold")  # lower(env) == "prod" at runtime
    assert not _detected(i, "runtime", m, psf_suite(i, scope_sweep=False))
    assert _detected(i, "runtime", m, psf_suite(i))


def test_opa_type_checker_rejects_bool_compared_with_string():
    i = BY_ID["prod-digest-pinned"]
    assert compile_errors({"m": _policy(i, "ci", Mutation("require", 0, "string_bool"))})
    assert not compile_errors({"r": _policy(i, "ci")})


def test_policies_under_test_cannot_reach_the_network_or_environment():
    for call in ('http.send({"method": "get", "url": "http://169.254.169.254/"})', "opa.runtime()"):
        text = f"package x\n\nimport rego.v1\n\ndeny contains msg if {{\n\tr := {call}\n\tmsg := r\n}}\n"
        assert compile_errors({"m": Policy(text, "deny", "ci")}), call
