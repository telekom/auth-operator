/*
Copyright © 2025 Deutsche Telekom AG
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
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/webhook/certrotator"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	webhookPort                    int
	webhookCertsDir                string
	enableHTTP2                    bool
	disableCertRotation            bool
	certRotationDNSName            string
	certRotationSecretName         string
	certRotationValidatingWebhooks []string
	certRotationMutatingWebhooks   []string
	enableTDGMigration             bool
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
				cancel(fmt.Errorf("error configuring webhooks: %w", err))
			}
			ready = true
		}()

		webhooks := []rotator.WebhookInfo{}
		for _, wh := range certRotationMutatingWebhooks {
			webhooks = append(webhooks, rotator.WebhookInfo{
				Type: rotator.Mutating,
				Name: wh,
			})
		}
		for _, wh := range certRotationValidatingWebhooks {
			webhooks = append(webhooks, rotator.WebhookInfo{
				Type: rotator.Validating,
				Name: wh,
			})
		}

		// The cert rotator will notify when we can start the webhook
		// and the metric endpoint
		if !disableCertRotation {
			if err := certrotator.Enable(
				mgr,
				namespace,
				webhookCertsDir,
				certRotationDNSName,
				certRotationSecretName,
				webhooks,
				startListeners,
			); err != nil {
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

func init() {
	rootCmd.AddCommand(webhookCmd)

	webhookCmd.Flags().IntVar(&webhookPort, "port", 9443,
		"The port the webhook server binds to. If not set, it will be set to '9443' as a default.")
	webhookCmd.Flags().BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the webhook server.")
	webhookCmd.Flags().StringVar(&webhookCertsDir, "certs-dir", "", "The directory for https certificates")
	webhookCmd.Flags().BoolVar(&disableCertRotation, "disable-cert-rotation", false,
		"disable automatic generation and rotation of webhook TLS certificates/keys")
	webhookCmd.Flags().StringVar(&certRotationDNSName, "cert-rotation-dns-name", "",
		"The DNS name for the webhook service")
	webhookCmd.Flags().StringVar(&certRotationSecretName, "cert-rotation-secret-name", "",
		"The name for the webhook certs secret")
	webhookCmd.Flags().StringSliceVar(&certRotationMutatingWebhooks, "cert-rotation-mutating-webhook",
		[]string{}, "The mutating webhooks")
	webhookCmd.Flags().StringSliceVar(&certRotationValidatingWebhooks, "cert-rotation-validating-webhook",
		[]string{}, "The validating webhooks")

	webhookCmd.Flags().BoolVar(&enableTDGMigration, "tdg-migration", false,
		"If set, the legacy labels and behavior for TDG migration will be enabled.")
}
