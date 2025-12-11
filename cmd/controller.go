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

	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/discovery"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/idpclient"

	authenticationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/controller/authentication"
	authorizationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/controller/authorization"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var (
	enableLeaderElection        bool
	authProviderConcurrency     int
	bindDefinitionConcurrency   int
	roleDefinitionConcurrency   int
	authProviderRequeueInterval time.Duration
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
			"authProviderConcurrency", authProviderConcurrency,
			"bindDefinitionConcurrency", bindDefinitionConcurrency,
			"roleDefinitionConcurrency", roleDefinitionConcurrency,
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

		resourceTracker := discovery.NewResourceTracker(scheme, mgr.GetConfig())
		if err := mgr.Add(resourceTracker); err != nil {
			return err
		}

		if roleDefinitionConcurrency > 0 {
			roleDefinitionController, err := authorizationcontroller.NewRoleDefinitionReconciler(
				mgr.GetConfig(),
				mgr.GetScheme(),
				mgr.GetEventRecorderFor("RoleDefinitionReconciler"),
				resourceTracker)
			if err != nil {
				return fmt.Errorf("unable to create RoleDefinition reconciler: %w", err)
			}

			if err := roleDefinitionController.SetupWithManager(ctx, mgr, roleDefinitionConcurrency); err != nil {
				return fmt.Errorf("unable to setup controller RoleDefinition with manager: %w", err)
			}
		} else {
			setupLog.Info("RoleDefinition reconciler is disabled")
		}

		if bindDefinitionConcurrency > 0 {
			bindDefinitionController, err := authorizationcontroller.NewBindDefinitionReconciler(
				mgr.GetConfig(),
				mgr.GetScheme(),
				mgr.GetEventRecorderFor("BindDefinitionReconciler"),
				resourceTracker)
			if err != nil {
				return fmt.Errorf("unable to create BindDefinition reconciler: %w", err)
			}
			if err := bindDefinitionController.SetupWithManager(mgr, bindDefinitionConcurrency); err != nil {
				return fmt.Errorf("unable to setup controller BindDefinition with manager: %w", err)
			}
		} else {
			setupLog.Info("BindDefinition reconciler is disabled")
		}

		// Setup an IDP client for AuthProviderReconciler
		// Needs refactoring -> transition to interface and define method group which
		// must be satisfied by all IDP clients to make this as generic as possible
		if authProviderConcurrency > 0 {
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
			}).SetupWithManager(mgr, authProviderConcurrency); err != nil {
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
	controllerCmd.Flags().IntVar(&authProviderConcurrency, "authprovider-concurrency", 5, "Number of concurrent workers for AuthProvider reconciler. Default is 5. Use 0 to disable the reconciler.")
	controllerCmd.Flags().IntVar(&bindDefinitionConcurrency, "binddefinition-concurrency", 5, "Number of concurrent workers for BindDefinition reconciler. Default is 5. Use 0 to disable the reconciler.")
	controllerCmd.Flags().IntVar(&roleDefinitionConcurrency, "roledefinition-concurrency", 5, "Number of concurrent workers for RoleDefinition reconciler. Default is 5. Use 0 to disable the reconciler.")
	controllerCmd.Flags().DurationVar(&authProviderRequeueInterval, "auth-provider-requeue-interval", time.Minute*5, "Interval in which the AuthProvider reconciler requeues AuthProviders for reconciliation. Default is 5 minutes.")
}
