"""Helm chart checks: Vector pipeline parity with scripts/render.py, web app
config wiring, secret handling and render-time guards. Skipped without helm."""

from __future__ import annotations

import base64
import copy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "logscope"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import render as R  # noqa: E402
from webapp.api.config import load_app_config  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")

BASE = {
    "image": {"tag": "abc123"},
    "s3": {"bucket": "example-bucket", "region": "us-east-1",
           "credentials": {"webapp": {"existingSecret": "web-s3"},
                           "vector": {"existingSecret": "vec-s3"}}},
}


def _merge(a, b):
    out = copy.deepcopy(a)
    for k, v in b.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _helm(values: dict, *, expect_ok: bool = True) -> tuple[list[dict], str]:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as fh:
        yaml.safe_dump(values, fh)
        fh.flush()
        proc = subprocess.run(
            ["helm", "template", "logscope", str(CHART), "-n", "logging", "-f", fh.name],
            capture_output=True, text=True,
        )
    if expect_ok:
        assert proc.returncode == 0, proc.stderr
    docs = [d for d in yaml.safe_load_all(proc.stdout) if d] if proc.returncode == 0 else []
    return docs, proc.stderr


def _find(docs, kind, name):
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def _render_py_cfg(values: dict) -> dict:
    """The config.yaml an operator would feed scripts/render.py for the same settings."""
    cfg = R.load_config(ROOT / "config.example.yaml")
    chart = yaml.safe_load((CHART / "values.yaml").read_text())
    merged = _merge(chart, values)
    ls = merged["logscope"]
    cfg["routing"]["infra_namespaces"] = ls["routing"]["infra_namespaces"]
    cfg["falco"] = ls["falco"]
    cfg["multiline"] = ls["multiline"]
    cfg["severity"] = ls["severity"]
    cfg["sinks"]["s3"].update(enabled=True, bucket=merged["s3"]["bucket"],
                              region=merged["s3"]["region"], key_prefix=merged["s3"]["keyPrefix"])
    cfg["sinks"]["file"]["enabled"] = False
    cfg["sinks"]["prometheus"]["enabled"] = merged["vector"]["metrics"]["enabled"]
    cfg["paths"]["checkpoint"] = merged["vector"]["dataDir"]
    R.validate_cfg(cfg)
    return cfg


VARIANTS = {
    "defaults": {},
    "customised": {
        "logscope": {
            "routing": {"infra_namespaces": ["kube-*", "team-?", "cert-manager", "o'brien"]},
            "falco": {"enabled": False},
            "multiline": {"enabled": False},
            "severity": {"logfmt_level": False,
                         "extra_patterns": [{"pattern": "(?i)deadlock 'x' detected", "bucket": "error"}]},
        },
        "vector": {"metrics": {"enabled": False}, "dataDir": "/var/lib/logscope-vector"},
        "s3": {"keyPrefix": "prod/logs/{{ log_type }}/%Y/%m/%d/%H_%M_%S_"},
    },
}


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_vector_pipeline_matches_render_py(variant):
    values = _merge(BASE, _merge({"vector": {"enabled": True}}, VARIANTS[variant]))
    docs, _ = _helm(values)
    chart_cfg = yaml.safe_load(_find(docs, "ConfigMap", "logscope-vector-config")["data"]["vector.yaml"])
    expected = R.vector_config_dict(_render_py_cfg(values), include_file=False, include_s3=True)
    assert chart_cfg["transforms"]["classify_and_scope"]["source"] == \
        expected["transforms"]["classify_and_scope"]["source"]
    assert chart_cfg == expected


def test_default_install_manages_no_vector_or_falco_and_keeps_existing_names():
    docs, _ = _helm(BASE)
    kinds = sorted(d["kind"] for d in docs)
    assert kinds == ["ConfigMap", "Deployment", "NetworkPolicy", "PersistentVolumeClaim",
                     "Service", "ServiceAccount"]
    names = {d["metadata"]["name"] for d in docs}
    assert "vector" not in names and "falco" not in names  # never collides with existing releases


def test_webapp_config_loads_and_carries_no_secrets():
    values = _merge(BASE, {
        "s3": {"credentials": {"webapp": {"existingSecret": "", "accessKeyId": "test-access-key-id-not-real",
                                          "secretAccessKey": "example/secret/value/0000"}}},
        "ai": {"provider": "anthropic", "model": "claude-opus-5-5", "apiKey": "sk-ant-example-0000",
               "baseUrl": "https://llm-gw.example.internal"},
    })
    docs, _ = _helm(values)
    cm = _find(docs, "ConfigMap", "logscope-webapp-config")
    raw = cm["data"]["config.yaml"]
    for secret in ("test-access-key-id-not-real", "example/secret/value/0000", "sk-ant-example-0000"):
        assert secret not in raw
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.yaml"
        p.write_text(raw)
        cfg = load_app_config(p)
    assert (cfg.s3_bucket, cfg.ai.provider, cfg.ai.model) == ("example-bucket", "anthropic", "claude-opus-5-5")
    assert cfg.ai.api_key_env == "LOGSCOPE_AI_API_KEY"
    assert cfg.ai.base_url == "https://llm-gw.example.internal"
    assert cfg.webapp.retention_days == 30
    assert cfg.falco_namespace == "falco"

    secret = _find(docs, "Secret", "logscope-webapp-credentials")
    data = {k: base64.b64decode(v).decode() for k, v in secret["data"].items()}
    assert data == {"AWS_ACCESS_KEY_ID": "test-access-key-id-not-real",
                    "AWS_SECRET_ACCESS_KEY": "example/secret/value/0000",
                    "AI_API_KEY": "sk-ant-example-0000"}
    env = {e["name"]: e for e in _find(docs, "Deployment", "logscope-webapp")
           ["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["LOGSCOPE_ACTIONS_ENABLED"]["value"] == "false"
    assert env["LOGSCOPE_AI_API_KEY"]["valueFrom"]["secretKeyRef"] == \
        {"name": "logscope-webapp-credentials", "key": "AI_API_KEY"}
    assert env["AWS_ACCESS_KEY_ID"]["valueFrom"]["secretKeyRef"]["name"] == "logscope-webapp-credentials"


@pytest.mark.parametrize("provider", ["anthropic", "gemini", "openai", "openrouter"])
def test_ai_provider_with_existing_secret(provider):
    docs, _ = _helm(_merge(BASE, {"ai": {"provider": provider, "model": "m-1",
                                         "existingSecret": "ai-key", "existingSecretKey": "token"}}))
    env = {e["name"]: e for e in _find(docs, "Deployment", "logscope-webapp")
           ["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["LOGSCOPE_AI_API_KEY"]["valueFrom"]["secretKeyRef"] == {"name": "ai-key", "key": "token"}
    assert not [d for d in docs if d["kind"] == "Secret"]  # nothing inline → no chart Secret
    assert f"provider: {provider}" in _find(docs, "ConfigMap", "logscope-webapp-config")["data"]["config.yaml"]


def test_ai_disabled_has_no_key_env():
    docs, _ = _helm(BASE)
    env = [e["name"] for e in _find(docs, "Deployment", "logscope-webapp")
           ["spec"]["template"]["spec"]["containers"][0]["env"]]
    assert "LOGSCOPE_AI_API_KEY" not in env


def test_vector_uses_its_own_write_credentials():
    docs, _ = _helm(_merge(BASE, {"vector": {"enabled": True}}))
    ds = _find(docs, "DaemonSet", "logscope-vector")
    pod = ds["spec"]["template"]
    c = pod["spec"]["containers"][0]
    refs = {e["name"]: e["valueFrom"]["secretKeyRef"]["name"] for e in c["env"] if "secretKeyRef" in e.get("valueFrom", {})}
    assert refs == {"AWS_ACCESS_KEY_ID": "vec-s3", "AWS_SECRET_ACCESS_KEY": "vec-s3"}
    assert pod["metadata"]["labels"]["vector.dev/exclude"] == "true"
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert {m["name"]: m.get("readOnly") for m in c["volumeMounts"]}["var-log"] is True


@pytest.mark.parametrize("overrides,message", [
    ({"image": {"tag": "latest"}}, "immutable"),
    ({"s3": {"bucket": ""}}, "s3.bucket is required"),
    ({"s3": {"credentials": {"webapp": {"existingSecret": ""}}}}, "s3.credentials.webapp"),
    ({"vector": {"enabled": True}, "s3": {"credentials": {"vector": {"existingSecret": ""}}}}, "s3.credentials.vector"),
    ({"ai": {"provider": "anthropic", "model": "m"}}, "ai.apiKey or ai.existingSecret"),
    ({"ai": {"provider": "bard"}}, "ai.provider must be one of"),
    ({"replicaCount": 2}, "replicaCount must be 0 or 1"),
    ({"ingress": {"enabled": True, "host": "logs.example.internal"}}, "no built-in authentication"),
    ({"ingress": {"enabled": True}}, "ingress.host is required"),
    ({"ingress": {"enabled": True, "host": "https://logs.example.internal/ui"}}, "fully qualified lowercase DNS name"),
    ({"ingress": {"enabled": True, "host": "logs.example.internal", "basicAuth": {"secretName": "a"},
                  "tls": {"enabled": False}}}, "plain HTTP"),
    ({"ingress": {"enabled": True, "host": "logs.example.internal", "controller": "other",
                  "basicAuth": {"secretName": "a"}}}, "Traefik Middleware"),
    ({"logscope": {"falco": {"priority_map": {"debug": "nope"}}}}, "not a logscope.severity.buckets name"),
    ({"falco": {"enabled": True, "namespaceOverride": "security"}}, "must equal logscope.falco.namespace"),
])
def test_render_guards(overrides, message):
    _, err = _helm(_merge(BASE, overrides), expect_ok=False)
    assert message in err
    for secret in ("test-access-key-id-not-real", "example/secret/value/0000", "sk-ant-example-0000"):
        assert secret not in err


def test_ingress_disabled_by_default():
    docs, _ = _helm(BASE)
    assert not [d for d in docs if d["kind"] in ("Ingress", "Middleware")]


def test_ingress_traefik_https_basic_auth_and_redirect():
    docs, _ = _helm(_merge(BASE, {"ingress": {
        "enabled": True, "host": "logscope.example.com", "className": "traefik",
        "tls": {"secretName": "logscope-tls"}, "basicAuth": {"secretName": "basic-auth"},
        "annotations": {"cert-manager.io/cluster-issuer": "example-issuer"}}}))
    ing = _find(docs, "Ingress", "logscope-webapp")
    ann = ing["metadata"]["annotations"]
    assert ann["traefik.ingress.kubernetes.io/router.entrypoints"] == "websecure"
    assert ann["traefik.ingress.kubernetes.io/router.tls"] == "true"
    assert ann["traefik.ingress.kubernetes.io/router.middlewares"] == "logging-logscope-webapp-auth@kubernetescrd"
    assert ann["cert-manager.io/cluster-issuer"] == "example-issuer"
    assert ing["spec"]["ingressClassName"] == "traefik"
    assert ing["spec"]["tls"] == [{"hosts": ["logscope.example.com"], "secretName": "logscope-tls"}]
    rule = ing["spec"]["rules"][0]
    assert rule["host"] == "logscope.example.com"
    backend = rule["http"]["paths"][0]["backend"]["service"]
    svc = _find(docs, "Service", "logscope-webapp")
    assert backend == {"name": svc["metadata"]["name"], "port": {"name": "http"}}
    assert svc["spec"]["ports"][0]["name"] == "http" and svc["spec"]["ports"][0]["port"] == 8000
    assert _find(docs, "Middleware", "logscope-webapp-auth")["spec"]["basicAuth"]["secret"] == "basic-auth"
    redirect = _find(docs, "Ingress", "logscope-webapp-http-redirect")
    assert redirect["metadata"]["annotations"]["traefik.ingress.kubernetes.io/router.entrypoints"] == "web"
    assert _find(docs, "Middleware", "logscope-webapp-https-redirect")["spec"]["redirectScheme"] == \
        {"scheme": "https", "permanent": True}


def test_ingress_default_class_and_controller_certificate():
    docs, _ = _helm(_merge(BASE, {"ingress": {"enabled": True, "host": "logscope.example.com",
                                              "basicAuth": {"secretName": "basic-auth"}, "httpsRedirect": False}}))
    ing = _find(docs, "Ingress", "logscope-webapp")
    assert "ingressClassName" not in ing["spec"]          # cluster default IngressClass
    assert ing["spec"]["tls"] == [{"hosts": ["logscope.example.com"]}]  # controller default cert
    assert not [d for d in docs if d["metadata"]["name"].endswith("redirect")]


def test_ingress_other_controller_with_external_auth():
    docs, _ = _helm(_merge(BASE, {"ingress": {
        "enabled": True, "host": "logscope.example.com", "controller": "other", "className": "nginx",
        "externalAuth": True, "tls": {"secretName": "logscope-tls"},
        "annotations": {"nginx.ingress.kubernetes.io/auth-url": "https://sso.example.com/auth"}}}))
    ing = _find(docs, "Ingress", "logscope-webapp")
    assert not any(k.startswith("traefik.") for k in ing["metadata"]["annotations"])
    assert not [d for d in docs if d["kind"] == "Middleware"]


def test_chart_managed_falco_renders_official_chart_in_its_namespace():
    docs, _ = _helm(_merge(BASE, {"falco": {"enabled": True}}))
    falco_ds = [d for d in docs if d["kind"] == "DaemonSet" and d["metadata"]["name"] == "logscope-falco"]
    assert falco_ds and falco_ds[0]["metadata"]["namespace"] == "falco"
    falco_cm = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "logscope-falco")
    falco_yaml = yaml.safe_load(falco_cm["data"]["falco.yaml"])
    assert falco_yaml["json_output"] is True and falco_yaml["stdout_output"]["enabled"] is True


def test_credential_checksums_roll_workloads_without_exposing_values():
    inline = {"s3": {"credentials": {"vector": {"existingSecret": "", "accessKeyId": "vector-id-not-real",
                                                "secretAccessKey": "vector-secret-not-real"}}},
              "vector": {"enabled": True}}
    docs1, _ = _helm(_merge(BASE, inline))
    docs2, _ = _helm(_merge(BASE, _merge(inline, {"s3": {"credentials": {"vector": {"secretAccessKey": "rotated-not-real"}}}})))
    ann = lambda docs, kind, name: _find(docs, kind, name)["spec"]["template"]["metadata"]["annotations"]
    v1, v2 = ann(docs1, "DaemonSet", "logscope-vector"), ann(docs2, "DaemonSet", "logscope-vector")
    assert v1["checksum/credentials"] != v2["checksum/credentials"]
    # Rotating Vector's key does not restart the web app.
    w1, w2 = ann(docs1, "Deployment", "logscope-webapp"), ann(docs2, "Deployment", "logscope-webapp")
    assert w1["checksum/credentials"] == w2["checksum/credentials"]
    for d in docs1 + docs2:
        if d["kind"] != "Secret":
            text = yaml.safe_dump(d)
            assert "vector-secret-not-real" not in text and "rotated-not-real" not in text


def test_vector_pull_secrets_rbac_names_and_webapp_env():
    docs, _ = _helm(_merge(BASE, {"vector": {"enabled": True, "image": {"pullSecrets": ["vector-registry"]}},
                                  "image": {"pullSecrets": ["webapp-registry"]},
                                  "webapp": {"allowedOrigins": ["https://logs.example.com"]}}))
    ds = _find(docs, "DaemonSet", "logscope-vector")["spec"]["template"]["spec"]
    assert ds["imagePullSecrets"] == [{"name": "vector-registry"}]
    assert _find(docs, "ServiceAccount", "logscope-webapp")["imagePullSecrets"] == [{"name": "webapp-registry"}]
    role = _find(docs, "ClusterRole", "logging-logscope-vector")
    binding = _find(docs, "ClusterRoleBinding", "logging-logscope-vector")
    assert binding["roleRef"]["name"] == role["metadata"]["name"]
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "logscope-vector", "namespace": "logging"}]
    env = {e["name"]: e.get("value") for e in _find(docs, "Deployment", "logscope-webapp")
           ["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE"] == "10"
    assert env["LOGSCOPE_ALLOWED_ORIGINS"] == "https://logs.example.com"
    assert env["LOGSCOPE_ACTIONS_ENABLED"] == "false"

