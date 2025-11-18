/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/discovery"

	idpclient "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/client"

	authenticationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/controller/authentication"
	authorizationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/controller/authorization"

	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var (
	enableLeaderElection           bool
	enableAuthProviderReconciler   bool
	enableBindDefinitionReconciler bool
	enableRoleDefinitionReconciler bool
	authProviderRequeueInterval    time.Duration
)

// controllerCmd represents the controller command
var controllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		setupLog.Info("starting controller")
		setupLog.Info("controller configuration",
			"enableLeaderElection", enableLeaderElection,
			"enableAuthProviderReconciler", enableAuthProviderReconciler,
			"enableBindDefinitionReconciler", enableBindDefinitionReconciler,
			"enableRoleDefinitionReconciler", enableRoleDefinitionReconciler,
			"authProviderRequeueInterval", authProviderRequeueInterval,
			"namespace", namespace,
		)

		ctx := ctrl.SetupSignalHandler()

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme: scheme,

			LeaderElection:         enableLeaderElection,
			LeaderElectionID:       "auth.t-caas.telekom.com",
			HealthProbeBindAddress: probeAddr,
		})
		if err != nil {
			return fmt.Errorf("unable to start manager. err: %s", err)
		}

		// Generate a new Discovery client for API group/resource discovery
		discoveryClient, err := discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
		if err != nil {
			return fmt.Errorf("unable to initialize Discovery client: %w", err)
		}

		// Generate a new Dynamic client for listing namespaced resources
		dynamicClient, err := dynamic.NewForConfig(mgr.GetConfig())
		if err != nil {
			return fmt.Errorf("unable to initialize Dynamic client: %w", err)
		}

		if enableRoleDefinitionReconciler {
			if err = (&authorizationcontroller.RoleDefinitionReconciler{
				Client:          mgr.GetClient(),
				Scheme:          mgr.GetScheme(),
				DiscoveryClient: discoveryClient,
				Recorder:        mgr.GetEventRecorderFor("RoleDefinitionReconciler"),
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to create controller RoleDefinition: %w", err)
			}
		} else {
			setupLog.Info("RoleDefinition reconciler is disabled")
		}

		if enableBindDefinitionReconciler {
			if err = (&authorizationcontroller.BindDefinitionReconciler{
				Client:          mgr.GetClient(),
				Scheme:          mgr.GetScheme(),
				DiscoveryClient: discoveryClient,
				DynamicClient:   dynamicClient,
				Recorder:        mgr.GetEventRecorderFor("BindDefinitionReconciler"),
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to create controller BindDefinition: %w", err)
			}
		} else {
			setupLog.Info("BindDefinition reconciler is disabled")
		}

		// Setup an IDP client for AuthProviderReconciler
		// Needs refactoring -> transition to interface and define method group which
		// must be satisfied by all IDP clients to make this as generic as possible
		if enableAuthProviderReconciler {
			idpUrl := os.Getenv("IDP_URL")
			if idpUrl == "" {
				return fmt.Errorf("IDP_URL environment variable must be set")
			}

			apiToken := os.Getenv("API_TOKEN")
			if apiToken == "" {
				return fmt.Errorf("API_TOKEN environment variable must be set")
			}

			idpClient, err := idpclient.NewIDPClient(idpclient.Config{
				IDPURL:   idpUrl,
				APIToken: apiToken,
			}, idpclient.Options{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			})
			if err != nil {
				return fmt.Errorf("unable to initialize IDP client: %w", err)
			}

			if err = (&authenticationcontroller.AuthProviderReconciler{
				Client:          mgr.GetClient(),
				Scheme:          mgr.GetScheme(),
				IDPClient:       idpClient,
				Recorder:        mgr.GetEventRecorderFor("AuthProviderReconciler"),
				RequeueInterval: authProviderRequeueInterval,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to create controller AuthProvider: %w", err)
			}
		} else {
			setupLog.Info("AuthProvider reconciler is disabled")
		}

		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			return fmt.Errorf("unable to set up health check. err: %s", err)
		}
		if err := mgr.Start(ctx); err != nil {
			return fmt.Errorf("problem running manager. err: %s", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(controllerCmd)

	controllerCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager. "+"Enabling this will ensure there is only one active controller manager.")
	controllerCmd.Flags().BoolVar(&enableAuthProviderReconciler, "enable-authprovider-reconciler", true, "Enable or disable AuthProvider reconciler. Enabled by default.")
	controllerCmd.Flags().BoolVar(&enableBindDefinitionReconciler, "enable-binddefinition-reconciler", true, "Enable or disable BindDefinition reconciler. Enabled by default.")
	controllerCmd.Flags().BoolVar(&enableRoleDefinitionReconciler, "enable-roledefinition-reconciler", true, "Enable or disable RoleDefinition reconciler. Enabled by default.")
	controllerCmd.Flags().DurationVar(&authProviderRequeueInterval, "auth-provider-requeue-interval", time.Minute*5, "Interval in which the AuthProvider reconciler requeues AuthProviders for reconciliation. Default is 5 minutes.")
}
