//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Command creator-reinvocation-webhook is a test-only mutating admission webhook.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

const (
	createdByKey       = authorizationv1alpha1.AnnotationKeyCreatedBy
	createdByGroupsKey = authorizationv1alpha1.AnnotationKeyCreatedByGroups
	triggerLabelKey    = "e2e.t-caas.telekom.com/reinvoke-trigger"
	markerKey          = "e2e.t-caas.telekom.com/reinvoke-uid"
	maxReviewBytes     = 1 << 20
)

type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionRequest struct {
	UID       string           `json:"uid"`
	Operation string           `json:"operation"`
	Kind      groupVersionKind `json:"kind"`
	Object    json.RawMessage  `json:"object"`
}

type groupVersionKind struct {
	Kind string `json:"kind"`
}

type admissionResponse struct {
	UID       string  `json:"uid"`
	Allowed   bool    `json:"allowed"`
	Patch     []byte  `json:"patch,omitempty"`
	PatchType *string `json:"patchType,omitempty"`
	Result    *status `json:"status,omitempty"`
}

type status struct {
	Message string `json:"message"`
}

type namespace struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations"`
		Labels      map[string]string `json:"labels"`
	} `json:"metadata"`
}

type jsonPatchOperation struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Value     any    `json:"value,omitempty"`
}

type server struct {
	fixture string
}

func main() {
	fixture := os.Getenv("FIXTURE_NAME")
	if fixture == "" {
		log.Fatal("FIXTURE_NAME is required")
	}
	certFile := envOrDefault("TLS_CERT_FILE", "/tls/tls.crt")
	keyFile := envOrDefault("TLS_KEY_FILE", "/tls/tls.key")

	handler := &server{fixture: fixture}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	mux.Handle("/mutate", handler)

	log.Printf("creator reinvocation webhook listening on :8443 for fixture %s", fixture)
	webhookServer := &http.Server{
		Addr:              ":8443",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := webhookServer.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func (server *server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "POST required", http.StatusMethodNotAllowed)
		return
	}
	defer func() { _ = request.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(request.Body, maxReviewBytes+1))
	if err != nil {
		http.Error(writer, "read admission review", http.StatusBadRequest)
		return
	}
	if len(body) > maxReviewBytes {
		http.Error(writer, "admission review is too large", http.StatusRequestEntityTooLarge)
		return
	}
	var review admissionReview
	if err := json.Unmarshal(body, &review); err != nil || review.Request == nil {
		http.Error(writer, "invalid admission review", http.StatusBadRequest)
		return
	}

	response := server.review(review.Request)
	result := admissionReview{
		APIVersion: review.APIVersion,
		Kind:       "AdmissionReview",
		Response:   response,
	}
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(result); err != nil {
		log.Printf("uid=%s response-write-error", review.Request.UID)
	}
}

func (server *server) review(request *admissionRequest) *admissionResponse {
	response := &admissionResponse{UID: request.UID, Allowed: false}
	deny := func(message string) *admissionResponse {
		response.Result = &status{Message: message}
		return response
	}

	if request.Operation != "UPDATE" || request.Kind.Kind != "Namespace" {
		return deny("unexpected admission request")
	}
	var object namespace
	if err := json.Unmarshal(request.Object, &object); err != nil {
		return deny("invalid Namespace object")
	}
	if object.Metadata.Name != server.fixture || object.Metadata.Labels[triggerLabelKey] != "true" {
		return deny("request does not match the exact test fixture")
	}
	createdBy, hasCreatedBy := object.Metadata.Annotations[createdByKey]
	createdByGroups, hasCreatedByGroups := object.Metadata.Annotations[createdByGroupsKey]
	if !hasCreatedBy || !hasCreatedByGroups {
		return deny("creator annotations are required before the test webhook runs")
	}

	patch, err := json.Marshal([]jsonPatchOperation{
		{Operation: "test", Path: annotationPath(createdByKey), Value: createdBy},
		{Operation: "test", Path: annotationPath(createdByGroupsKey), Value: createdByGroups},
		{Operation: "remove", Path: annotationPath(createdByKey)},
		{Operation: "remove", Path: annotationPath(createdByGroupsKey)},
		{Operation: "add", Path: annotationPath(markerKey), Value: request.UID},
	})
	if err != nil {
		return deny("build mutation patch")
	}
	patchType := "JSONPatch"
	response.Allowed = true
	response.Patch = patch
	response.PatchType = &patchType
	log.Printf("uid=%s removed=created-by,created-by-groups", request.UID)
	return response
}

func annotationPath(key string) string {
	return "/metadata/annotations/" + escapeJSONPointer(key)
}

func escapeJSONPointer(value string) string {
	var result strings.Builder
	result.Grow(len(value))
	for _, character := range value {
		switch character {
		case '~':
			result.WriteString("~0")
		case '/':
			result.WriteString("~1")
		default:
			result.WriteRune(character)
		}
	}
	return result.String()
}
