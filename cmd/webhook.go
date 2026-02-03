/*
Copyright © 2026 Deutsche Telekom AG
*/
package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	authorizationwebhook "github.com/telekom/auth-operator/internal/webhook/authorization"
	"github.com/telekom/auth-operator/internal/webhook/certrotator"
	"github.com/telekom/auth-operator/pkg/indexer"

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
	Short: "Run the auth-operator webhook server",
	Long: `Run the auth-operator webhook server which handles admission requests
for RoleDefinition and BindDefinition custom resources, as well as namespace
mutation and validation webhooks.

The webhook server validates and mutates resources during admission,
ensuring authorization policies are enforced at creation time.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		setupLog.Info("starting webhook server",
			"port", webhookPort,
			"certsDir", webhookCertsDir,
			"enableHTTP2", enableHTTP2,
			"disableCertRotation", disableCertRotation,
			"namespace", namespace,
		)
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

		cfg, err := ctrl.GetConfig()
		if err != nil {
			return fmt.Errorf("unable to get kubeconfig: %w", err)
		}

		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 scheme,
			WebhookServer:          webhookServer,
			HealthProbeBindAddress: probeAddr,
		})
		if err != nil {
			return fmt.Errorf("unable to start manager: %w", err)
		}

		// Setup field indexes for efficient lookups in webhook validation
		if err := indexer.SetupIndexes(ctx, mgr); err != nil {
			return fmt.Errorf("unable to setup field indexes: %w", err)
		}
		setupLog.Info("field indexes configured for cached client")

		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			return fmt.Errorf("unable to set up health check: %w", err)
		}

		startListeners := make(chan struct{})
		ready := false

		//+kubebuilder:scaffold:builder
		if err := mgr.AddReadyzCheck("readyz", func(req *http.Request) error {
			if ready {
				return nil
			}
			return errors.New("webhook server not ready: waiting for certificate setup")
		}); err != nil {
			return fmt.Errorf("unable to set up ready check: %w", err)
		}

		go func() {
			setupLog.Info("waiting for certificate rotation to complete before configuring webhooks")
			<-startListeners
			setupLog.Info("certificate rotation complete, configuring webhooks")
			if err := configureWebhooks(mgr); err != nil {
				setupLog.Error(err, "failed to configure webhooks")
				cancel(fmt.Errorf("error configuring webhooks: %w", err))
				return
			}
			setupLog.Info("webhooks configured successfully, server is ready")
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
			setupLog.Info("enabling certificate rotation",
				"dnsName", certRotationDNSName,
				"secretName", certRotationSecretName,
				"mutatingWebhooks", certRotationMutatingWebhooks,
				"validatingWebhooks", certRotationValidatingWebhooks,
			)
			if err := certrotator.Enable(
				mgr,
				namespace,
				webhookCertsDir,
				certRotationDNSName,
				certRotationSecretName,
				webhooks,
				startListeners,
			); err != nil {
				return fmt.Errorf("unable to set up cert rotation: %w", err)
			}
		} else {
			setupLog.Info("certificate rotation disabled, using existing certificates")
			close(startListeners)
		}

		setupLog.Info("starting manager")
		if err := mgr.Start(ctx); err != nil {
			return fmt.Errorf("problem running manager: %w", err)
		}
		return nil
	},
}

func configureWebhooks(mgr manager.Manager) error {
	log := ctrl.Log.WithName("webhook-setup")

	log.Info("registering authorization webhook at /authorize")
	authorizer := &authorizationwebhook.Authorizer{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("Authorizer"),
	}
	mgr.GetWebhookServer().Register("/authorize", authorizer)

	log.Info("setting up RoleDefinition webhook")
	if err := (&authorizationv1alpha1.RoleDefinition{}).SetupWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create webhook for RoleDefinition: %w", err)
	}

	log.Info("setting up BindDefinition webhook")
	if err := (&authorizationv1alpha1.BindDefinition{}).SetupWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create webhook for BindDefinition: %w", err)
	}
	// Setup Namespace mutator
	log.Info("setting up Namespace mutator webhook", "tdgMigration", enableTDGMigration)
	namespaceMutator := &authorizationwebhook.NamespaceMutator{
		Client:       mgr.GetClient(),
		TDGMigration: enableTDGMigration,
	}
	if err := namespaceMutator.InjectDecoder(admission.NewDecoder(mgr.GetScheme())); err != nil {
		return fmt.Errorf("unable to inject decoder for NamespaceMutator: %w", err)
	}
	mgr.GetWebhookServer().Register("/mutate-v1-namespace", &webhook.Admission{Handler: namespaceMutator})

	// Setup Namespace validator
	log.Info("setting up Namespace validator webhook", "tdgMigration", enableTDGMigration)
	namespaceValidator := &authorizationwebhook.NamespaceValidator{
		Client:       mgr.GetClient(),
		TDGMigration: enableTDGMigration,
	}
	if err := namespaceValidator.InjectDecoder(admission.NewDecoder(mgr.GetScheme())); err != nil {
		return fmt.Errorf("unable to inject decoder for NamespaceValidator: %w", err)
	}
	mgr.GetWebhookServer().Register("/validate-v1-namespace", &webhook.Admission{Handler: namespaceValidator})

	log.Info("all webhooks configured successfully")
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
