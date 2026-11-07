#!/usr/bin/env python3
"""Real rc.14 OIDC approval and revocation on a disposable cluster."""

# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
import base64
import importlib.util
import json
import os
import pathlib
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = pathlib.Path(
    os.environ["RESULT_DIR"]
    if os.environ.get("RESULT_DIR")
    else tempfile.mkdtemp(prefix="emergency-lifecycle-")
)
ROOT.mkdir(parents=True, exist_ok=True)
KCFG = os.environ["ADMIN_KUBECONFIG"]
NS = os.environ.get("BREAKGLASS_NAMESPACE", "breakglass-system")
BASE = os.environ["BREAKGLASS_API_URL"].rstrip("/")
CLUSTER = os.environ.get("BREAKGLASS_CLUSTER", "tenant-a")
RUN = uuid.uuid4().hex[:8]
GROUP = "breakglass:platform:emergency-runtime-" + RUN
ESC = "original-oidc-emergency-runtime-" + RUN
records = []
session_names = []


def k(*args, data=None):
    p = subprocess.run(
        ["kubectl", "--kubeconfig", KCFG, *args],
        input=json.dumps(data) if data is not None else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if p.returncode:
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout) if p.stdout.strip().startswith(("{", "[")) else p.stdout


def apply(obj):
    return k("apply", "-f", "-", "-o", "json", data=obj)


def http(url, data, token=None, expected=(200, 201), form=False):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
        if form
        else "application/json"
    }
    if token:
        headers["Authorization"] = "Bearer " + token

    body = (
        urllib.parse.urlencode(data).encode()
        if form
        else (json.dumps(data).encode() if data is not None else None)
    )
    req = urllib.request.Request(url, body, headers, method="POST")
    try:
        with urllib.request.urlopen(
            req,
            context=api_tls
            if url.startswith(server + "/")
            else ssl.create_default_context(
                cafile=os.environ.get("BREAKGLASS_CA_FILE")
            ),
            timeout=30,
        ) as r:
            code, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read()
    value = json.loads(raw) if raw else {}
    if code not in expected:
        raise AssertionError((url, code, value))
    return value


def result(name, value=True):
    print(json.dumps({"check": name, "result": value}), flush=True)
    records.append({"check": name, "result": value})


def wait(fn, expected, seconds=90):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = fn()
        if value == expected:
            return
        time.sleep(1)
    raise AssertionError((expected, value))


if os.environ.get("AUTH_NAMESPACE") or os.environ.get("AUTH_RELEASE"):
    auth_namespace = os.environ["AUTH_NAMESPACE"]
    auth_release = os.environ["AUTH_RELEASE"]
    for component, expected in [
        ("webhook-server", True),
        ("controller-manager", False),
    ]:
        account = f"system:serviceaccount:{auth_namespace}:{auth_release}-{component}"
        review = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                KCFG,
                "--as=" + account,
                "auth",
                "can-i",
                "create",
                "subjectaccessreviews.authorization.k8s.io",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert review.returncode == (0 if expected else 1), review.stderr
        assert review.stdout.strip() == ("yes" if expected else "no"), review.stdout
        result(f"{component} effective SAR permission", expected)

admin = k("config", "view", "--raw", "--minify", "-o", "json")
server = admin["clusters"][0]["cluster"]["server"]
cluster_tls = admin["clusters"][0]["cluster"]
api_tls = (
    ssl.create_default_context(
        cadata=base64.b64decode(cluster_tls["certificate-authority-data"]).decode()
    )
    if "certificate-authority-data" in cluster_tls
    else ssl.create_default_context(cafile=cluster_tls.get("certificate-authority"))
)
requester = pathlib.Path(os.environ["REQUESTER_TOKEN_FILE"]).read_text().strip()
approver = pathlib.Path(os.environ["APPROVER_TOKEN_FILE"]).read_text().strip()
identity = http(
    server + "/apis/authentication.k8s.io/v1/selfsubjectreviews",
    {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"},
    requester,
)["status"]["userInfo"]
assert identity["username"] and not identity["username"].startswith("system:"), identity
assert GROUP not in identity["groups"], identity
result("original OIDC identity; no injected emergency group", identity)


def marker():
    spec = {
        key: identity[key]
        for key in ("username", "uid", "groups", "extra")
        if key in identity
    }
    spec["user"] = spec.pop("username")
    spec["resourceAttributes"] = {
        "group": "breakglass.t-caas.telekom.com",
        "resource": "escalationguards",
        "name": "platform-emergency",
        "verb": "use",
    }
    status = k(
        "create",
        "-f",
        "-",
        "-o",
        "json",
        data={
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": spec,
        },
    )["status"]
    return (
        status.get("allowed", False)
        and not status.get("denied", False)
        and not status.get("evaluationError")
    )


try:
    apply(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "runtime-emergency-cluster-admin-" + RUN},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin",
            },
            "subjects": [
                {
                    "kind": "Group",
                    "apiGroup": "rbac.authorization.k8s.io",
                    "name": GROUP,
                }
            ],
        }
    )
    apply(
        {
            "apiVersion": "breakglass.t-caas.telekom.com/v1alpha1",
            "kind": "BreakglassEscalation",
            "metadata": {"name": ESC, "namespace": NS},
            "spec": {
                "allowed": {
                    "clusters": [CLUSTER],
                    "groups": [os.environ.get("REQUESTER_GROUP", "ops")],
                },
                "escalatedGroup": GROUP,
                "approvers": {
                    "groups": [os.environ.get("APPROVER_GROUP", "senior-ops")]
                },
                "maxValidFor": "5m",
                "approvalTimeout": "5m",
                "retainFor": "1h",
                "blockSelfApproval": True,
            },
        }
    )

    def ready():
        return any(
            x["type"] == "Ready" and x["status"] == "True"
            for x in k("get", "breakglassescalation", ESC, "-n", NS, "-o", "json")
            .get("status", {})
            .get("conditions", [])
        )

    wait(ready, True)
    assert marker() is False
    result("no session: marker denied")

    def create_session(duration):
        obj = http(
            BASE + "/api/breakglassSessions",
            {
                "cluster": CLUSTER,
                "group": GROUP,
                "escalationName": ESC,
                "reason": "Original OIDC emergency integration acceptance",
                "duration": duration,
            },
            requester,
        )
        session_names.append(obj["metadata"]["name"])
        return obj["metadata"]["name"]

    def action(name, verb, tok, expected=(200,)):
        return http(
            BASE + "/api/breakglassSessions/" + name + "/" + verb + "?namespace=" + NS,
            None if verb in ("drop", "withdraw", "cancel") else {},
            tok,
            expected,
        )

    def state(name):
        return (
            k("get", "breakglasssession", name, "-n", NS, "-o", "json")
            .get("status", {})
            .get("state")
        )

    def write_configmap(name, allowed):
        obj = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name + "-" + RUN, "namespace": "default"},
            "data": {"proof": "original-token"},
        }
        http(
            server + "/api/v1/namespaces/default/configmaps",
            obj,
            requester,
            (201,) if allowed else (403,),
        )

    name = create_session(60)
    assert marker() is False
    write_configmap("runtime-before-approval", False)
    result("pending: marker and actual write denied")
    action(name, "approve", requester, (400, 403))
    result("self approval denied")
    action(name, "approve", approver)
    wait(marker, True)
    write_configmap("runtime-approved", True)
    result("approved: marker and actual write allowed")
    session = k("get", "breakglasssession", name, "-n", NS, "-o", "json")
    assert session["spec"]["user"] == identity["username"], session["spec"]
    result("session retains original Kubernetes username", session["spec"]["user"])
    wait(marker, False, 100)
    write_configmap("runtime-expired", False)
    result("natural 60s expiry: marker and write revoked")
    wait(lambda: state(name), "Expired", 45)
    name = create_session(300)
    action(name, "approve", approver)
    wait(marker, True)
    if os.getenv("NAMESPACE_MATRIX") or os.getenv("PERSISTED_MATRIX"):
        # Save only this disposable OIDC user's token; never retain the admin client key here.
        cfg = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": admin["clusters"],
            "users": [{"name": "oidc", "user": {"token": requester}}],
            "contexts": [
                {
                    "name": "oidc",
                    "context": {
                        "cluster": admin["clusters"][0]["name"],
                        "user": "oidc",
                    },
                }
            ],
            "current-context": "oidc",
        }
        usercfg = ROOT / "requester-kubeconfig.json"
        with open(
            usercfg, "w", opener=lambda path, flags: os.open(path, flags, 0o600)
        ) as out:
            json.dump(cfg, out)
        try:
            for variable, label in [
                ("NAMESPACE_MATRIX", "auth namespace operation and protection matrix"),
                ("PERSISTED_MATRIX", "persisted namespace and workload CRUD"),
            ]:
                if not os.getenv(variable):
                    continue
                modspec = importlib.util.spec_from_file_location(
                    variable.lower(), os.environ[variable]
                )
                module = importlib.util.module_from_spec(modspec)
                modspec.loader.exec_module(module)
                result(label, module.run_matrix(usercfg, KCFG))
        finally:
            usercfg.unlink(missing_ok=True)
    action(name, "drop", requester)
    wait(marker, False)
    write_configmap("runtime-dropped", False)
    result("drop: marker and write revoked")
    print("Results directory:", ROOT, flush=True)
    (ROOT / "lifecycle-results.json").write_text(json.dumps(records, indent=2) + "\n")
finally:
    failed = sys.exc_info()[0] is not None
    cleanup_errors = []
    # Revoke the per-run effective grant before deleting its session records.
    resources = [("clusterrolebinding", "runtime-emergency-cluster-admin-" + RUN, None)]
    resources += [("breakglasssession", name, NS) for name in session_names]
    resources += [
        ("breakglassescalation", ESC, NS),
        ("configmap", "runtime-approved-" + RUN, "default"),
    ]
    for kind, name, namespace in resources:
        try:
            args = ["delete", kind, name, "--ignore-not-found", "--wait=false"]
            if namespace:
                args += ["-n", namespace]
            k(*args)
        except (RuntimeError, OSError, ValueError) as error:
            cleanup_errors.append({"kind": kind, "name": name, "error": str(error)})
    (ROOT / "requester-kubeconfig.json").unlink(missing_ok=True)
    records.append(
        {
            "check": "task fixture cleanup",
            "result": not cleanup_errors,
            "errors": cleanup_errors,
        }
    )
    (ROOT / "lifecycle-results.json").write_text(json.dumps(records, indent=2) + "\n")
    if cleanup_errors and not failed:
        raise RuntimeError(
            "Task fixture cleanup failed; inspect lifecycle-results.json"
        )
