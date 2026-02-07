#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# create-test-namespaces.sh — Create labelled namespaces that match the sample
# CRs' selectors, exercising RoleBindings across various label-selector patterns.
#
# Usage:
#   create-test-namespaces.sh
#
# These namespaces exercise:
#   - matchLabels (exact match)
#   - matchExpressions with In, Exists operators
#   - Multiple labels for complex selectors

set -euo pipefail

echo "Creating test namespaces for output-delta ..."

# --- Tenant Alpha ---
kubectl create namespace tenant-alpha --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace tenant-alpha --overwrite \
  t-caas.telekom.com/tenant=alpha \
  t-caas.telekom.com/environment=development \
  t-caas.telekom.com/owner=tenant \
  t-caas.telekom.com/purpose=application

kubectl create namespace tenant-alpha-staging --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace tenant-alpha-staging --overwrite \
  t-caas.telekom.com/tenant=alpha \
  t-caas.telekom.com/environment=staging \
  t-caas.telekom.com/owner=tenant

kubectl create namespace tenant-alpha-prod --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace tenant-alpha-prod --overwrite \
  t-caas.telekom.com/tenant=alpha \
  t-caas.telekom.com/environment=production \
  t-caas.telekom.com/owner=tenant

# --- Tenant Beta ---
kubectl create namespace tenant-beta --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace tenant-beta --overwrite \
  t-caas.telekom.com/tenant=beta \
  t-caas.telekom.com/environment=staging \
  t-caas.telekom.com/owner=tenant

# --- Platform namespaces ---
kubectl create namespace t-caas-system --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace t-caas-system --overwrite \
  t-caas.telekom.com/owner=platform \
  kubernetes.io/metadata.name=t-caas-system

kubectl create namespace t-caas-monitoring --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace t-caas-monitoring --overwrite \
  t-caas.telekom.com/owner=platform \
  t-caas.telekom.com/monitoring=enabled \
  t-caas.telekom.com/component=observability

kubectl create namespace t-caas-logging --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace t-caas-logging --overwrite \
  t-caas.telekom.com/owner=platform \
  kubernetes.io/metadata.name=t-caas-logging

# --- GitOps namespaces (matchExpressions, Exists operator) ---
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace argocd --overwrite \
  argocd.argoproj.io/managed-by=argocd \
  t-caas.telekom.com/gitops-source=true

kubectl create namespace flux-system --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace flux-system --overwrite \
  kustomize.toolkit.fluxcd.io/managed-by=flux \
  t-caas.telekom.com/gitops-source=true

# --- Shared namespaces (matchExpressions, In operator) ---
kubectl create namespace shared-services --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace shared-services --overwrite \
  t-caas.telekom.com/owner=shared \
  t-caas.telekom.com/tenant=shared

# --- Compliance namespace ---
kubectl create namespace compliance-pci --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace compliance-pci --overwrite \
  t-caas.telekom.com/owner=tenant \
  t-caas.telekom.com/tenant=compliance \
  t-caas.telekom.com/compliance-scope=pci-dss

# --- CI/CD namespace ---
kubectl create namespace tenant-alpha-cicd --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace tenant-alpha-cicd --overwrite \
  t-caas.telekom.com/tenant=alpha \
  t-caas.telekom.com/purpose=cicd \
  t-caas.telekom.com/owner=tenant

echo "Test namespaces created:"
kubectl get namespaces --show-labels | grep -E '(tenant-|t-caas-|argocd|flux-|shared-|compliance-)' || true
