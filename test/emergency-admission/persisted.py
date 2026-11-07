# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
"""Persist representative ordinary/protected namespace and ConfigMap CRUD with OIDC."""

import json
import subprocess
import uuid


def run_matrix(requester_kubeconfig, admin_kubeconfig):
    checks = 0
    names = []

    def call(args, obj=None, admin=False, absent=False):
        nonlocal checks
        cfg = admin_kubeconfig if admin else requester_kubeconfig
        proc = subprocess.run(
            ["kubectl", "--kubeconfig", str(cfg), "--request-timeout=20s"] + args,
            input=json.dumps(obj) if obj else None,
            text=True,
            capture_output=True,
            check=False,
        )
        if absent:
            assert proc.returncode and "NotFound" in proc.stderr, proc.stderr
        else:
            assert proc.returncode == 0, proc.stderr
        if not admin:
            checks += 1
            print("PERSISTED", " ".join(args), flush=True)
        return (
            json.loads(proc.stdout)
            if proc.stdout.lstrip().startswith("{")
            else proc.stdout
        )

    try:
        for protected in (False, True):
            name = "emergency-persisted-" + uuid.uuid4().hex[:10]
            labels = {
                "t-caas.telekom.com/owner": "tenant",
                "t-caas.telekom.com/tenant": "emergency-runtime",
            }
            if protected:
                labels["t-caas.telekom.com/protected"] = "emergency-runtime"
            ns = {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": name, "labels": labels},
            }
            names.append(name)
            call(["create", "-f", "-"], ns)
            ns = call(["get", "namespace", name, "-o", "json"])
            assert all(ns["metadata"]["labels"][k] == v for k, v in labels.items())
            ns["metadata"].setdefault("annotations", {})["emergency.test/update"] = (
                "persisted"
            )
            call(["replace", "-f", "-"], ns)
            call(
                [
                    "patch",
                    "namespace",
                    name,
                    "--type=merge",
                    "-p",
                    '{"metadata":{"annotations":{"emergency.test/patch":"persisted"}}}',
                ]
            )
            ns = call(["get", "namespace", name, "-o", "json"])
            assert ns["metadata"]["annotations"]["emergency.test/update"] == "persisted"
            assert ns["metadata"]["annotations"]["emergency.test/patch"] == "persisted"
            cm = {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "probe", "namespace": name},
                "data": {"value": "created"},
            }
            call(["create", "-f", "-"], cm)
            cm = call(["get", "configmap", "probe", "-n", name, "-o", "json"])
            assert cm["data"]["value"] == "created"
            cm["data"]["value"] = "updated"
            call(["replace", "-f", "-"], cm)
            cm = call(["get", "configmap", "probe", "-n", name, "-o", "json"])
            assert cm["data"]["value"] == "updated"
            call(
                [
                    "patch",
                    "configmap",
                    "probe",
                    "-n",
                    name,
                    "--type=merge",
                    "-p",
                    '{"data":{"value":"patched"}}',
                ]
            )
            cm = call(["get", "configmap", "probe", "-n", name, "-o", "json"])
            assert cm["data"]["value"] == "patched"
            listed = call(["get", "configmaps", "-n", name, "-o", "json"])
            assert any(x["metadata"]["name"] == "probe" for x in listed["items"])
            call(["delete", "configmap", "probe", "-n", name])
            call(["get", "configmap", "probe", "-n", name], absent=True)
            call(["delete", "namespace", name, "--wait=true", "--timeout=60s"])
            call(["get", "namespace", name], absent=True)
            names.remove(name)
        print(
            f"PASS {checks} persisted original-identity namespace/workload API checks",
            flush=True,
        )
    finally:
        for name in names:
            call(
                [
                    "delete",
                    "namespace",
                    name,
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=60s",
                ],
                admin=True,
            )
    return checks
