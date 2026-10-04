"""What the Helm chart renders, checked for the properties section 16 asks for.

Rendering needs the `helm` binary, so these run where it is installed, which
includes CI. They check the manifests; installing them on a cluster is done by
the `helm` CI job.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed"),
]

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "guardrail-gateway"
BUNDLE = ROOT / "deploy" / "opa" / "policy" / "guardrail"
DIGEST = "sha256:" + "a" * 64
REQUIRED = {
    "image.repository": "registry.example/guardrail-gateway",
    "image.digest": DIGEST,
    "existingSecret": "guardrail-credentials",
}


def _helm(values: dict[str, str], *extra: str) -> subprocess.CompletedProcess[str]:
    settings = [item for key, value in values.items() for item in ("--set", f"{key}={value}")]
    return subprocess.run(
        ["helm", "template", "release", str(CHART), *settings, *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def _render(**overrides: str) -> list[dict[str, Any]]:
    completed = _helm({**REQUIRED, **overrides})
    assert completed.returncode == 0, completed.stderr
    return [document for document in yaml.safe_load_all(completed.stdout) if document]


def _refusal(values: dict[str, str]) -> str:
    completed = _helm(values)
    assert completed.returncode != 0
    return completed.stderr


def _one(documents: list[dict[str, Any]], kind: str, suffix: str = "") -> dict[str, Any]:
    matches = [
        document
        for document in documents
        if document["kind"] == kind and document["metadata"]["name"].endswith(suffix)
    ]
    assert len(matches) == 1, (kind, suffix, len(matches))
    return matches[0]


def _pod(documents: list[dict[str, Any]]) -> dict[str, Any]:
    pod: dict[str, Any] = _one(documents, "Deployment")["spec"]["template"]["spec"]
    return pod


def test_every_container_is_read_only_unprivileged_and_drops_all_capabilities() -> None:
    pod = _pod(_render())

    assert [container["name"] for container in pod["containers"]] == ["gateway", "opa"]
    for container in pod["containers"]:
        context = container["securityContext"]
        assert context["readOnlyRootFilesystem"] is True
        assert context["runAsNonRoot"] is True
        assert context["allowPrivilegeEscalation"] is False
        assert context["capabilities"] == {"drop": ["ALL"]}
        assert context["seccompProfile"] == {"type": "RuntimeDefault"}
        assert "privileged" not in context
        assert "requests" in container["resources"]
        assert "memory" in container["resources"]["limits"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["runAsUser"] != 0


def test_the_pod_mounts_nothing_from_the_host_and_no_api_token() -> None:
    documents = _render()
    pod = _pod(documents)

    assert pod["automountServiceAccountToken"] is False
    assert _one(documents, "ServiceAccount")["automountServiceAccountToken"] is False
    assert pod["serviceAccountName"] == _one(documents, "ServiceAccount")["metadata"]["name"]
    for volume in pod["volumes"]:
        assert set(volume) - {"name"} <= {"emptyDir", "configMap"}
    for forbidden in ("hostNetwork", "hostPID", "hostIPC"):
        assert forbidden not in pod


def test_the_image_is_deployed_by_digest() -> None:
    gateway = _pod(_render())["containers"][0]

    assert gateway["image"] == f"registry.example/guardrail-gateway@{DIGEST}"


def test_a_mutable_tag_must_be_asked_for_explicitly() -> None:
    without_digest = {key: value for key, value in REQUIRED.items() if key != "image.digest"}

    assert "image.digest is required" in _refusal({**without_digest, "image.tag": "latest"})
    assert "64 hex characters" in _refusal({**REQUIRED, "image.digest": "sha256:abc"})
    tagged = _helm({**without_digest, "image.tag": "1.2.3", "image.allowTag": "true"})
    assert tagged.returncode == 0
    assert "registry.example/guardrail-gateway:1.2.3" in tagged.stdout


def test_credentials_come_only_from_a_secret_the_chart_does_not_create() -> None:
    documents = _render()
    gateway = _pod(documents)["containers"][0]

    assert {"secretRef": {"name": "guardrail-credentials"}} in gateway["envFrom"]
    assert not [document for document in documents if document["kind"] == "Secret"]
    missing = {key: value for key, value in REQUIRED.items() if key != "existingSecret"}
    assert "existingSecret is required" in _refusal(missing)


@pytest.mark.parametrize(
    "setting",
    ["GUARDRAIL_JWT_SECRET", "GUARDRAIL_DATABASE_URL", "GUARDRAIL_CANARY_SECRETS"],
)
def test_a_credential_placed_in_plain_configuration_is_refused(setting: str) -> None:
    assert "holds a credential" in _refusal({**REQUIRED, f"config.{setting}": "value"})


def test_only_gateway_settings_are_accepted_as_configuration() -> None:
    assert "only GUARDRAIL_*" in _refusal({**REQUIRED, "config.LD_PRELOAD": "injected.so"})


def test_the_network_policy_denies_everything_by_default_except_dns() -> None:
    policy = _one(_render(), "NetworkPolicy")["spec"]

    assert policy["policyTypes"] == ["Ingress", "Egress"]
    assert policy["podSelector"]["matchLabels"]["app.kubernetes.io/name"] == "guardrail-gateway"
    assert policy["ingress"] == []
    assert len(policy["egress"]) == 1
    assert {(port["protocol"], port["port"]) for port in policy["egress"][0]["ports"]} == {
        ("UDP", 53),
        ("TCP", 53),
    }


def test_listed_peers_are_the_only_additions_to_the_network_policy(tmp_path: Path) -> None:
    values = tmp_path / "values.yaml"
    values.write_text(
        yaml.safe_dump(
            {
                "networkPolicy": {
                    "ingressFrom": [{"namespaceSelector": {"matchLabels": {"team": "edge"}}}],
                    "metricsFrom": [{"namespaceSelector": {"matchLabels": {"team": "obs"}}}],
                    "egressTo": [
                        {
                            "to": [{"namespaceSelector": {"matchLabels": {"team": "events"}}}],
                            "ports": [{"protocol": "TCP", "port": 9092}],
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    completed = _helm(REQUIRED, "--values", str(values))
    assert completed.returncode == 0, completed.stderr
    documents = [document for document in yaml.safe_load_all(completed.stdout) if document]

    policy = _one(documents, "NetworkPolicy")["spec"]

    assert len(policy["ingress"]) == 1
    assert policy["ingress"][0]["ports"] == [{"protocol": "TCP", "port": 8000}]
    assert [
        peer["namespaceSelector"]["matchLabels"]["team"] for peer in policy["ingress"][0]["from"]
    ] == [
        "edge",
        "obs",
    ]
    assert len(policy["egress"]) == 2
    assert policy["egress"][1]["ports"] == [{"protocol": "TCP", "port": 9092}]


def test_opa_listens_on_loopback_and_the_gateway_is_pointed_at_it() -> None:
    pod = _pod(_render())
    gateway, opa = pod["containers"]

    assert "--addr=127.0.0.1:8181" in opa["args"]
    assert {"name": "GUARDRAIL_OPA_URL", "value": "http://127.0.0.1:8181"} in gateway["env"]
    assert [port["containerPort"] for port in opa["ports"]] == [8282]
    assert opa["volumeMounts"] == [
        {"name": "policy", "mountPath": "/policy/guardrail", "readOnly": True}
    ]


def test_the_sidecar_can_be_turned_off() -> None:
    documents = _render(**{"opa.enabled": "false"})
    pod = _pod(documents)

    assert [container["name"] for container in pod["containers"]] == ["gateway"]
    assert "env" not in pod["containers"][0]
    assert not [
        document
        for document in documents
        if document["kind"] == "ConfigMap" and document["metadata"]["name"].endswith("-policy")
    ]


def test_the_chart_ships_exactly_the_tested_policy_bundle() -> None:
    policy = _one(_render(), "ConfigMap", "-policy")["data"]

    assert set(policy) == {"content.rego", "action.rego", "data.json"}
    for name, rendered in policy.items():
        source = (BUNDLE / name).read_text(encoding="utf-8")
        assert (CHART / "files" / "policy" / name).read_text(encoding="utf-8") == source
        assert rendered.strip() == source.strip()


def test_readiness_uses_the_endpoint_that_reports_every_dependency() -> None:
    gateway = _pod(_render())["containers"][0]

    assert gateway["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert gateway["livenessProbe"]["httpGet"]["path"] == "/health/live"


def test_a_rollout_never_drops_below_the_running_replicas() -> None:
    documents = _render()
    deployment = _one(documents, "Deployment")["spec"]

    assert deployment["strategy"]["rollingUpdate"]["maxUnavailable"] == 0
    assert _one(documents, "PodDisruptionBudget")["spec"]["minAvailable"] == 1
    assert "checksum/config" in deployment["template"]["metadata"]["annotations"]


def test_the_chart_version_matches_the_package() -> None:
    import tomllib

    chart = yaml.safe_load((CHART / "Chart.yaml").read_text(encoding="utf-8"))
    package = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert chart["version"] == chart["appVersion"] == package["project"]["version"]
