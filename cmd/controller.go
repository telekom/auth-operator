/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/discovery"

	authorizationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/controller/authorization"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var (
	enableLeaderElection      bool
	bindDefinitionConcurrency int
	roleDefinitionConcurrency int
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
			"bindDefinitionConcurrency", bindDefinitionConcurrency,
			"roleDefinitionConcurrency", roleDefinitionConcurrency,
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
	controllerCmd.Flags().IntVar(&bindDefinitionConcurrency, "binddefinition-concurrency", 5, "Number of concurrent workers for BindDefinition reconciler. Default is 5. Use 0 to disable the reconciler.")
	controllerCmd.Flags().IntVar(&roleDefinitionConcurrency, "roledefinition-concurrency", 5, "Number of concurrent workers for RoleDefinition reconciler. Default is 5. Use 0 to disable the reconciler.")
}
