"""Canonical workload model, per-surface attribute bindings, and native-input encoders.

A *state* is a dict holding one value per canonical attribute. ``MISSING`` means the
attribute is absent from the native document (label not set, tag not set, ...).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

MISSING = None


@dataclass(frozen=True)
class Attr:
    name: str
    type: str  # "str" | "bool" | "int"
    domain: tuple
    optional: bool  # True -> MISSING is part of the domain
    neutral: object  # value used when an intent does not reference the attribute


ATTRS: dict[str, Attr] = {a.name: a for a in [
    Attr("env", "str", ("prod", "staging", "dev", "Prod", "production"), True, "dev"),
    Attr("region", "str", ("westeurope", "northeurope", "eastus", "eastus2", "WestEurope"), True, "westeurope"),
    Attr("data_class", "str", ("public", "internal", "confidential", "restricted", "Confidential"), True, "internal"),
    Attr("owner", "str", ("team-payments", "team-data", ""), True, "team-data"),
    Attr("image_registry", "str", ("acrprod.azurecr.io", "ghcr.io", "docker.io", "acrprod.azurecr.io.evil.io"), False,
         "acrprod.azurecr.io"),
    Attr("image_digest_pinned", "bool", (True, False), False, True),
    Attr("signed", "bool", (True, False), True, True),
    Attr("encryption_at_rest", "bool", (True, False), True, True),
    Attr("public_ingress", "bool", (True, False), True, False),
    Attr("run_as_non_root", "bool", (True, False), True, True),
    Attr("privileged", "bool", (True, False), False, False),
    Attr("replicas", "int", (0, 1, 2, 3, 4, 5), False, 2),
]}


def domain(attr: str) -> tuple:
    a = ATTRS[attr]
    return a.domain + ((MISSING,) if a.optional else ())


def neutral_state() -> dict:
    return {name: a.neutral for name, a in ATTRS.items()}


@dataclass(frozen=True)
class Binding:
    path: str  # Rego reference relative to the subject object `o`
    kind: str  # "str" | "bool" | "strbool" (bool carried as "true"/"false") | "int"
    wrong_path: str  # plausible wrong reference, used by the wrong_path mutation
    expr: str = "{}"  # wraps the reference for attributes derived from a native field


_IMG = "o.spec.template.spec.containers[0].image"
_POD_IMG = "o.spec.containers[0].image"  # Pod path instead of Deployment path: a classic copy-paste bug

K8S = {
    "env": Binding("o.metadata.labels.env", "str", "o.metadata.labels.environment"),
    "region": Binding('o.metadata.labels["topology.kubernetes.io/region"]', "str", "o.metadata.labels.region"),
    "data_class": Binding('o.metadata.labels["data-class"]', "str", "o.metadata.labels.data_class"),
    "owner": Binding("o.metadata.labels.owner", "str", "o.metadata.annotations.owner"),
    "image_registry": Binding(_IMG, "str", _POD_IMG, 'split({}, "/")[0]'),
    "image_digest_pinned": Binding(_IMG, "bool", _POD_IMG, 'contains({}, "@sha256:")'),
    "signed": Binding('o.metadata.annotations["policy.synapse.io/signed"]', "strbool",
                      'o.metadata.labels["policy.synapse.io/signed"]'),
    "encryption_at_rest": Binding('o.metadata.annotations["policy.synapse.io/encryption-at-rest"]', "strbool",
                                  'o.metadata.annotations["policy.synapse.io/encryption"]'),
    "public_ingress": Binding('o.metadata.annotations["policy.synapse.io/public-ingress"]', "strbool",
                              'o.metadata.annotations["policy.synapse.io/public"]'),
    "run_as_non_root": Binding("o.spec.template.spec.securityContext.runAsNonRoot", "bool",
                               "o.spec.securityContext.runAsNonRoot"),
    "privileged": Binding("o.spec.template.spec.containers[0].securityContext.privileged", "bool",
                          "o.spec.template.spec.securityContext.privileged"),
    "replicas": Binding("o.spec.replicas", "int", "o.spec.template.spec.replicas"),
}

TERRAFORM = {
    "env": Binding("o.tags.env", "str", "o.tags.environment"),
    "region": Binding("o.location", "str", "o.region"),
    "data_class": Binding('o.tags["data-class"]', "str", "o.tags.data_class"),
    "owner": Binding("o.tags.owner", "str", "o.tags.Owner"),
    "encryption_at_rest": Binding("o.infrastructure_encryption_enabled", "bool", "o.encryption_enabled"),
    "public_ingress": Binding("o.public_network_access_enabled", "bool", "o.public_access_enabled"),
}

RUNTIME = {
    "env": Binding("o.env", "str", "o.environment"),
    "region": Binding("o.region", "str", "o.location"),
    "data_class": Binding("o.data_class", "str", "o.classification"),
    "owner": Binding("o.owner", "str", "o.team"),
    "image_registry": Binding("o.image.registry", "str", "o.registry"),
    "image_digest_pinned": Binding("o.image.digest_pinned", "bool", "o.image.pinned"),
    "signed": Binding("o.attestation.signed", "bool", "o.attestations.signed"),
    "encryption_at_rest": Binding("o.encryption_at_rest", "bool", "o.encrypted"),
    "public_ingress": Binding("o.public_ingress", "bool", "o.ingress.public"),
    "privileged": Binding("o.privileged", "bool", "o.security.privileged"),
}


def _put(d: dict, keys: list[str], v) -> None:
    if v is MISSING:
        return
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = v


def _strbool(v):
    return MISSING if v is MISSING else ("true" if v else "false")


def k8s_manifest(s: dict) -> dict:
    image = s["image_registry"] + ("/app@sha256:" + "0" * 64 if s["image_digest_pinned"] else "/app:1.4.2")
    container = {"name": "app", "image": image, "securityContext": {"privileged": s["privileged"]}}
    pod = {"containers": [container]}
    _put(pod, ["securityContext", "runAsNonRoot"], s["run_as_non_root"])
    md = {"name": "app", "labels": {}, "annotations": {}}
    _put(md, ["labels", "env"], s["env"])
    _put(md, ["labels", "topology.kubernetes.io/region"], s["region"])
    _put(md, ["labels", "data-class"], s["data_class"])
    _put(md, ["labels", "owner"], s["owner"])
    _put(md, ["annotations", "policy.synapse.io/signed"], _strbool(s["signed"]))
    _put(md, ["annotations", "policy.synapse.io/encryption-at-rest"], _strbool(s["encryption_at_rest"]))
    _put(md, ["annotations", "policy.synapse.io/public-ingress"], _strbool(s["public_ingress"]))
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": md,
            "spec": {"replicas": s["replicas"], "template": {"spec": pod}}}


def admission_review(s: dict) -> dict:
    # Gatekeeper's Rego input contract: input.review.object + input.parameters
    return {"review": {"operation": "CREATE", "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
                       "object": k8s_manifest(s)}, "parameters": {}}


def terraform_plan(s: dict) -> dict:
    after = {"name": "stapp", "tags": {}}
    _put(after, ["location"], s["region"])
    _put(after, ["tags", "env"], s["env"])
    _put(after, ["tags", "data-class"], s["data_class"])
    _put(after, ["tags", "owner"], s["owner"])
    _put(after, ["infrastructure_encryption_enabled"], s["encryption_at_rest"])
    _put(after, ["public_network_access_enabled"], s["public_ingress"])
    return {"format_version": "1.2", "resource_changes": [{
        "address": "azurerm_storage_account.this", "type": "azurerm_storage_account",
        "change": {"actions": ["create"], "after": after}}]}


def runtime_request(s: dict) -> dict:
    w = {"image": {"registry": s["image_registry"], "digest_pinned": s["image_digest_pinned"]},
         "privileged": s["privileged"]}
    for k in ("env", "region", "data_class", "owner", "encryption_at_rest", "public_ingress"):
        _put(w, [k], s[k])
    _put(w, ["attestation", "signed"], s["signed"])
    return {"action": "deploy", "workload": w}


@dataclass(frozen=True)
class Surface:
    name: str
    bindings: dict[str, Binding]
    subjects: str  # Rego expression producing the array of subject objects
    decision: str  # "deny" | "violation" | "allow" (the rule the surface's engine reads)
    encode: Callable[[dict], dict]


SURFACES: dict[str, Surface] = {s.name: s for s in [
    Surface("ci", K8S, "[input]", "deny", k8s_manifest),  # conftest on the manifest in CI
    Surface("admission", K8S, "[input.review.object]", "violation", admission_review),  # Gatekeeper
    Surface("terraform", TERRAFORM,
            '[rc.change.after | some rc in input.resource_changes; rc.type == "azurerm_storage_account"]',
            "deny", terraform_plan),  # conftest/OPA on `terraform show -json` output
    Surface("runtime", RUNTIME, "[input.workload]", "allow", runtime_request),  # OPA sidecar at deploy time
]}
