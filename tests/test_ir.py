import json

import pytest

from policy_synapse.ir import Intent, Pred, load_intents
from policy_synapse.model import MISSING, neutral_state
from policy_synapse.suites import baseline, psf_suite, violating

from conftest import INTENTS


def test_missing_attribute_never_satisfies_a_predicate():
    s = {**neutral_state(), "owner": MISSING}
    assert not Pred("owner", "ne", "").holds(s)
    assert not Pred("owner", "not_in", ("x",)).holds(s)


def test_intent_denies_only_in_scope_and_non_compliant():
    i = Intent("t", "t", 1, ("ci",), (Pred("env", "eq", "prod"),), (Pred("replicas", "ge", 2),))
    base = neutral_state()
    assert i.denies({**base, "env": "prod", "replicas": 1})
    assert not i.denies({**base, "env": "prod", "replicas": 2})
    assert not i.denies({**base, "env": "Prod", "replicas": 0})  # exact match: "Prod" is out of scope
    assert not i.denies({**base, "env": MISSING, "replicas": 0})


@pytest.mark.parametrize("intent", load_intents(INTENTS), ids=lambda i: i.id)
def test_suite_baselines_have_the_expected_decisions(intent):
    assert not intent.denies(baseline(intent))
    assert intent.denies(violating(intent))
    assert len(psf_suite(intent)) == len({tuple(s.values()) for s in psf_suite(intent)})


def test_unbound_attribute_is_rejected(tmp_path):
    bad = {"intents": [{"id": "x", "title": "x", "criticality": 1, "surfaces": ["terraform"],
                        "require": [["privileged", "is_false"]]}]}
    (tmp_path / "i.json").write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="no binding"):
        load_intents(tmp_path / "i.json")
