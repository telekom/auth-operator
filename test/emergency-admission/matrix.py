#!/usr/bin/env python3
"""Real API matrix. Call run_matrix(requester_kubeconfig, admin_kubeconfig) during an approved session."""
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
import json
import subprocess


def run_matrix(requester_kubeconfig, admin_kubeconfig):
    checks = 0

    def call(args, obj=None, allowed=True, admin=False, reason=None):
        nonlocal checks
        result = subprocess.run(['kubectl', '--kubeconfig', str(admin_kubeconfig if admin else requester_kubeconfig),
                                 '--request-timeout=15s'] + args,
                                input=json.dumps(obj) if obj else None, text=True, capture_output=True)
        output = result.stdout + result.stderr
        assert (result.returncode == 0) == allowed, (args, output)
        if reason:
            assert reason.lower() in output.lower(), (args, output)
        if not admin:
            checks += 1
            print(('ALLOW' if allowed else 'DENY'), ' '.join(args), flush=True)
        return result.stdout

    def ns(suffix, owner='tenant', protected=False, deletion=False):
        labels = {'t-caas.telekom.com/owner': owner}
        if owner == 'tenant':
            labels['t-caas.telekom.com/tenant'] = 'emergency-runtime'
        if owner == 'addon':
            labels['t-caas.telekom.com/addon'] = 'demo'
        if protected:
            labels['t-caas.telekom.com/protected'] = 'emergency-runtime'
        if deletion:
            labels['t-caas.telekom.com/deletion-protection'] = 'enabled'
        return {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'emergency-runtime-' + suffix, 'labels': labels}}

    fixtures = [ns('ordinary'), ns('protected', protected=True), ns('guarded', protected=True, deletion=True),
                ns('platform', owner='platform'), ns('addon', owner='addon')]
    try:
        for obj in fixtures:
            call(['apply', '-f', '-'], obj, admin=True)
        for suffix in ['ordinary', 'protected']:
            name = 'emergency-runtime-' + suffix
            call(['create', '--dry-run=server', '-f', '-'], ns('new-' + suffix, protected=suffix == 'protected'))
            obj = json.loads(call(['get', 'namespace', name, '-o', 'json']))
            obj['metadata'].setdefault('annotations', {})['emergency.test/update'] = 'true'
            call(['replace', '--dry-run=server', '-f', '-'], obj)
            call(['patch', 'namespace', name, '--type=merge', '-p', '{"metadata":{"annotations":{"emergency.test/patch":"true"}}}', '--dry-run=server'])
            call(['delete', 'namespace', name, '--dry-run=server'])
            call(['patch', 'namespace', name, '--type=merge', '-p', '{"metadata":{"labels":{"t-caas.telekom.com/tenant":"other"}}}', '--dry-run=server'], allowed=False, reason='denied')
            cm = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'probe', 'namespace': name}, 'data': {'test': 'before'}}
            call(['apply', '-f', '-'], cm, admin=True)
            cm['metadata']['name'] = 'new'
            call(['create', '--dry-run=server', '-f', '-'], cm)
            obj = json.loads(call(['get', 'configmap', 'probe', '-n', name, '-o', 'json']))
            call(['get', 'configmaps', '-n', name])
            obj['data']['test'] = 'update'
            call(['replace', '--dry-run=server', '-f', '-'], obj)
            call(['patch', 'configmap', 'probe', '-n', name, '--type=merge', '-p', '{"data":{"test":"patch"}}', '--dry-run=server'])
            call(['delete', 'configmap', 'probe', '-n', name, '--dry-run=server'])
        call(['get', 'namespaces'])
        for suffix in ['platform', 'addon']:
            name = 'emergency-runtime-' + suffix
            call(['delete', 'namespace', name, '--dry-run=server'], allowed=False, reason='denied')
            call(['patch', 'namespace', name, '--type=merge', '-p', '{"metadata":{"annotations":{"emergency.test/patch":"true"}}}', '--dry-run=server'], allowed=False, reason='denied')
        for name in ['default', 'kube-system', 'kube-public', 'kube-node-lease']:
            call(['delete', 'namespace', name, '--dry-run=server'], allowed=False, reason='deleted')
        name = 'emergency-runtime-guarded'
        call(['delete', 'namespace', name, '--dry-run=server'], allowed=False, reason='deletion-protected')
        call(['label', 'namespace', name, 't-caas.telekom.com/deletion-protection-', '--dry-run=server'], allowed=False, reason='allow-deletion')
        call(['annotate', 'namespace', name, 't-caas.telekom.com/allow-deletion=true'])
        call(['delete', 'namespace', name, '--dry-run=server'])
        print(f'PASS {checks} original-identity namespace/workload API checks', flush=True)
    finally:
        for obj in fixtures:
            name = obj['metadata']['name']
            call(['annotate', 'namespace', name, 't-caas.telekom.com/allow-deletion=true', '--overwrite'], admin=True)
            call(['delete', 'namespace', name, '--ignore-not-found', '--wait=false'], admin=True)
    return checks
