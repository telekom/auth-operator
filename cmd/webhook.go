/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	authorizationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
	authorizationwebhook "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/webhook/authorization"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	webhookPort                                 int
	webhookCertsDir                             string
	enableHTTP2                                 bool
	disableCertRotation                         bool
	certRotationServiceLabelSelector            string
	certRotationSecretLabelSelector             string
	certRotationValidatingWebhooksLabelSelector string
	certRotationMutatingWebhooksLabelSelector   string
	enableTDGMigration                          bool
)

const (
	caName         = "cert"
	caOrganization = "t-caas"
)

// webhookCmd represents the webhook command
var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		setupLog.Info("starting webhook server")
		ctx, cancel := context.WithCancelCause(ctrl.SetupSignalHandler())
		defer cancel(nil)

		disableHTTP2 := func(c *tls.Config) {
			setupLog.Info("disabling http/2")
			c.NextProtos = []string{"http/1.1"}
		}

		tlsOpts := []func(*tls.Config){}
		if !enableHTTP2 {
			tlsOpts = append(tlsOpts, disableHTTP2)
		}

		webhookServer := webhook.NewServer(webhook.Options{
			Port:    webhookPort,
			CertDir: webhookCertsDir,
			TLSOpts: tlsOpts,
		})

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:                 scheme,
			WebhookServer:          webhookServer,
			HealthProbeBindAddress: probeAddr,
		})
		if err != nil {
			return fmt.Errorf("unable to start manager. err: %s", err)
		}

		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			return fmt.Errorf("unable to set up health check. err: %s", err)
		}

		startListeners := make(chan struct{})
		ready := false

		//+kubebuilder:scaffold:builder
		if err := mgr.AddReadyzCheck("readyz", func(req *http.Request) error {
			if ready {
				return nil
			}
			return errors.New("not ready")
		}); err != nil {
			return fmt.Errorf("unable to start readiness check. err: %s", err)
		}

		go func() {
			<-startListeners
			if err := configureWebhooks(mgr); err != nil {
				cancel(fmt.Errorf("error confguring webhooks: %w", err))
			}
			ready = true
		}()

		// The cert rotator will notify when we can start the webhook
		// and the metric endpoint
		if !disableCertRotation {
			if err := enableCertRotation(mgr, startListeners); err != nil {
				return fmt.Errorf("unable to set up cert rotation. err: %s", err)
			}
		} else {
			close(startListeners)
		}

		if err := mgr.Start(ctx); err != nil {
			return fmt.Errorf("problem running manager. err: %s", err)
		}
		return nil
	},
}

func configureWebhooks(mgr manager.Manager) error {
	authorizer := &authorizationwebhook.Authorizer{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("Authorizer"),
	}
	mgr.GetWebhookServer().Register("/authorize", authorizer)

	if err := (&authorizationv1alpha1.RoleDefinition{}).SetupWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("unable create webhook for RoleDefinition: %w", err)
	}

	if err := (&authorizationv1alpha1.BindDefinition{}).SetupWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create webhook for BindDefinition: %w", err)
	}
	// Setup Namespace mutator
	namespaceMutator := &authorizationwebhook.NamespaceMutator{
		Client:       mgr.GetClient(),
		TDGMigration: enableTDGMigration,
	}
	if err := namespaceMutator.InjectDecoder(admission.NewDecoder(mgr.GetScheme())); err != nil {
		return fmt.Errorf("unable to inject decoder for NamespaceMutator: %w", err)
	}
	mgr.GetWebhookServer().Register("/mutate-v1-namespace", &webhook.Admission{Handler: namespaceMutator})

	// Setup Namespace validator
	namespaceValidator := &authorizationwebhook.NamespaceValidator{
		Client:       mgr.GetClient(),
		TDGMigration: enableTDGMigration,
	}
	if err := namespaceValidator.InjectDecoder(admission.NewDecoder(mgr.GetScheme())); err != nil {
		return fmt.Errorf("unable to inject decoder for NamespaceValidator: %w", err)
	}
	mgr.GetWebhookServer().Register("/validate-v1-namespace", &webhook.Admission{Handler: namespaceValidator})

	return nil
}

func getValidatingWebhookNames(mgr manager.Manager) ([]string, error) {
	apiReader := mgr.GetAPIReader()

	validatingWebhooksList := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	selector, err := labels.Parse(certRotationValidatingWebhooksLabelSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to parse label selector %q: %w", certRotationValidatingWebhooksLabelSelector, err)
	}

	if err := apiReader.List(context.Background(), validatingWebhooksList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, fmt.Errorf("failed to list validating webhooks in namespace %q with labels %v: %w", namespace, selector, err)
	}
	result := make([]string, 0, len(validatingWebhooksList.Items))
	for _, webhook := range validatingWebhooksList.Items {
		result = append(result, webhook.Name)
	}
	return result, nil
}

func getMutatingWebhookNames(mgr manager.Manager) ([]string, error) {
	apiReader := mgr.GetAPIReader()

	mutatingWebhooksList := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	selector, err := labels.Parse(certRotationMutatingWebhooksLabelSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to parse label selector %q: %w", certRotationMutatingWebhooksLabelSelector, err)
	}

	if err := apiReader.List(context.Background(), mutatingWebhooksList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, fmt.Errorf("failed to list mutating webhooks in namespace %q with labels %v: %w", namespace, selector, err)
	}
	result := make([]string, 0, len(mutatingWebhooksList.Items))
	for _, webhook := range mutatingWebhooksList.Items {
		result = append(result, webhook.Name)
	}
	return result, nil
}

func getCertificateSecretKey(mgr manager.Manager) (types.NamespacedName, error) {
	// list secrets in operator namespace with label selector and ensure only one is returned
	//c := mgr.GetClient()
	apiReader := mgr.GetAPIReader()

	secretList := &corev1.SecretList{}
	selector, err := labels.Parse(certRotationSecretLabelSelector)
	if err != nil {
		return types.NamespacedName{}, fmt.Errorf("failed to parse label selector %q: %w", certRotationSecretLabelSelector, err)
	}

	if err := apiReader.List(context.Background(), secretList, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return types.NamespacedName{}, fmt.Errorf("failed to list secrets in namespace %q with labels %v: %w", namespace, selector, err)
	}

	if len(secretList.Items) != 1 {
		return types.NamespacedName{}, fmt.Errorf("expected exactly 1 Secret in namespace %q with labels %v, but found %d", namespace, selector, len(secretList.Items))
	}

	secret := secretList.Items[0]
	return types.NamespacedName{
		Namespace: secret.Namespace,
		Name:      secret.Name,
	}, nil
}

func getWebhookService(mgr manager.Manager) (*corev1.Service, error) {
	// list services in operator namespace with label selector and ensure only one is returned
	//c := mgr.GetClient()
	apiReader := mgr.GetAPIReader()

	selector, err := labels.Parse(certRotationServiceLabelSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to parse label selector %q: %w", certRotationSecretLabelSelector, err)
	}

	serviceList := &corev1.ServiceList{}
	if err := apiReader.List(context.Background(), serviceList, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, fmt.Errorf("failed to list services in namespace %q with labels %v: %w", namespace, selector, err)
	}

	if len(serviceList.Items) != 1 {
		return nil, fmt.Errorf("expected exactly 1 Service in namespace %q with labels %v, but found %d", namespace, selector, len(serviceList.Items))
	}

	return &serviceList.Items[0], nil
}

func enableCertRotation(mgr manager.Manager, notifyFinished chan struct{}) error {
	if namespace == "" {
		return errors.New("namespace is undefined. can't enable cert rotator")
	}
	if webhookCertsDir == "" {
		return errors.New("certs-dir is undefined. can't enable cert rotator")
	}
	if caName == "" {
		return errors.New("caName is undefined. can't enable cert rotator")
	}

	webhooks := []rotator.WebhookInfo{}
	validatingWebhooks, err := getValidatingWebhookNames(mgr)
	if err != nil {
		return fmt.Errorf("unable to get validating webhooks. err: %s", err)
	}
	for _, validatingWebhook := range validatingWebhooks {
		webhooks = append(webhooks, rotator.WebhookInfo{
			Name: validatingWebhook,
			Type: rotator.Validating,
		})
	}

	mutatingWebhooks, err := getMutatingWebhookNames(mgr)
	if err != nil {
		return fmt.Errorf("unable to get mutating webhooks. err: %s", err)
	}
	for _, mutatingWebhook := range mutatingWebhooks {
		webhooks = append(webhooks, rotator.WebhookInfo{
			Name: mutatingWebhook,
			Type: rotator.Mutating,
		})
	}

	secretKey, err := getCertificateSecretKey(mgr)
	if err != nil {
		return fmt.Errorf("unable to get secret. err: %s", err)
	}

	service, err := getWebhookService(mgr)
	if err != nil {
		return fmt.Errorf("unable to get service. err: %s", err)
	}

	certDNSName := fmt.Sprintf("%s.%s.svc", service.Name, service.Namespace)

	err = rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey:             secretKey,
		RequireLeaderElection: true,
		CertDir:               webhookCertsDir,
		CAName:                caName,
		CAOrganization:        caOrganization,
		DNSName:               certDNSName,
		IsReady:               notifyFinished,
		Webhooks:              webhooks,
	})
	if err != nil {
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(webhookCmd)

	webhookCmd.Flags().IntVar(&webhookPort, "port", 9443, "The port the webhook server binds to. "+"If not set, it will be set to '9443' as a default.")
	webhookCmd.Flags().BoolVar(&enableHTTP2, "enable-http2", false, "If set, HTTP/2 will be enabled for the webhook server.")
	webhookCmd.Flags().StringVar(&webhookCertsDir, "certs-dir", "", "The directory for https certificates")
	webhookCmd.Flags().BoolVar(&disableCertRotation, "disable-cert-rotation", false, "disable automatic generation and rotation of webhook TLS certificates/keys")
	webhookCmd.Flags().StringVar(&certRotationServiceLabelSelector, "cert-rotation-service-label-selector", "", "The label selector for the webhook service")
	webhookCmd.Flags().StringVar(&certRotationSecretLabelSelector, "cert-rotation-secret-label-selector", "", "The label selector for the webhook secret")
	webhookCmd.Flags().StringVar(&certRotationValidatingWebhooksLabelSelector, "cert-rotation-validating-webhooks-label-selector", "", "The label selector for the validating webhooks")
	webhookCmd.Flags().StringVar(&certRotationMutatingWebhooksLabelSelector, "cert-rotation-mutating-webhooks-label-selector", "", "The label selector for the mutating webhooks")
	webhookCmd.Flags().BoolVar(&enableTDGMigration, "tdg-migration", false, "If set, the legacy lablels and behavior for TDG migration will be enabled. ")
}
