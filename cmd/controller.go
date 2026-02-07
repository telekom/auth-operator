/*
Copyright © 2026 Deutsche Telekom AG.
*/
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	authorizationcontroller "github.com/telekom/auth-operator/internal/controller/authorization"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/indexer"

	// Import metrics package to register custom Prometheus metrics.
	_ "github.com/telekom/auth-operator/pkg/metrics"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	enableLeaderElection      bool
	bindDefinitionConcurrency int
	roleDefinitionConcurrency int
	cacheSyncTimeout          time.Duration
	gracefulShutdownTimeout   time.Duration
	waitForCRDs               bool
)

// controllerCmd represents the controller command.
var controllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "Run the auth-operator controller manager",
	Long: `Run the auth-operator controller manager which reconciles RoleDefinition
and BindDefinition custom resources to manage Kubernetes RBAC resources.

The controller watches for changes to authorization resources and ensures
the corresponding ClusterRoles, Roles, ClusterRoleBindings, and RoleBindings
are created and kept in sync.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if bindDefinitionConcurrency < 0 || roleDefinitionConcurrency < 0 {
			return fmt.Errorf("concurrency values must be >= 0")
		}

		setupLog.Info("starting controller")
		setupLog.Info("controller configuration",
			"enableLeaderElection", enableLeaderElection,
			"bindDefinitionConcurrency", bindDefinitionConcurrency,
			"roleDefinitionConcurrency", roleDefinitionConcurrency,
			"cacheSyncTimeout", cacheSyncTimeout,
			"gracefulShutdownTimeout", gracefulShutdownTimeout,
			"namespace", namespace,
		)

		ctx := ctrl.SetupSignalHandler()

		cfg, err := ctrl.GetConfig()
		if err != nil {
			return fmt.Errorf("unable to get kubeconfig: %w", err)
		}

		// Configure cache with extended sync timeout for environments with slow API servers
		// or when CRDs take time to become available
		cacheOptions := cache.Options{
			SyncPeriod: nil, // Use default
		}

		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme,

			Metrics: metricsserver.Options{
				BindAddress: metricsAddr,
			},
			LeaderElection:          enableLeaderElection,
			LeaderElectionID:        "auth.t-caas.telekom.com",
			LeaderElectionNamespace: namespace,
			HealthProbeBindAddress:  probeAddr,
			Cache:                   cacheOptions,
			GracefulShutdownTimeout: &gracefulShutdownTimeout,
		})
		if err != nil {
			return fmt.Errorf("unable to start manager: %w", err)
		}

		resourceTracker := discovery.NewResourceTracker(scheme, mgr.GetConfig())
		if err := mgr.Add(resourceTracker); err != nil {
			return fmt.Errorf("unable to add resource tracker to manager: %w", err)
		}

		// Wait for CRDs to be available before setting up controllers
		// This prevents cache sync timeout errors when CRDs are not yet installed
		if waitForCRDs {
			if err := waitForRequiredCRDs(ctx, cfg, cacheSyncTimeout); err != nil {
				return fmt.Errorf("failed waiting for required CRDs: %w", err)
			}
		}

		// Setup field indexes for efficient lookups
		if err := indexer.SetupIndexes(ctx, mgr); err != nil {
			return fmt.Errorf("unable to setup field indexes: %w", err)
		}
		setupLog.Info("field indexes configured for cached client")

		if roleDefinitionConcurrency > 0 {
			setupLog.Info("creating RoleDefinition reconciler", "concurrency", roleDefinitionConcurrency)
			roleDefinitionController, err := authorizationcontroller.NewRoleDefinitionReconciler(
				mgr.GetClient(),
				mgr.GetScheme(),
				mgr.GetEventRecorder("RoleDefinitionReconciler"),
				resourceTracker)
			if err != nil {
				return fmt.Errorf("unable to create RoleDefinition reconciler: %w", err)
			}

			if err := roleDefinitionController.SetupWithManager(ctx, mgr, roleDefinitionConcurrency); err != nil {
				return fmt.Errorf("unable to setup controller RoleDefinition with manager: %w", err)
			}
			setupLog.Info("RoleDefinition reconciler configured successfully")
		} else {
			setupLog.Info("RoleDefinition reconciler is disabled")
		}

		if bindDefinitionConcurrency > 0 {
			setupLog.Info("creating BindDefinition reconciler", "concurrency", bindDefinitionConcurrency)
			bindDefinitionController, err := authorizationcontroller.NewBindDefinitionReconciler(
				mgr.GetClient(),
				mgr.GetConfig(),
				mgr.GetScheme(),
				mgr.GetEventRecorder("BindDefinitionReconciler"),
				resourceTracker)
			if err != nil {
				return fmt.Errorf("unable to create BindDefinition reconciler: %w", err)
			}
			if err := bindDefinitionController.SetupWithManager(mgr, bindDefinitionConcurrency); err != nil {
				return fmt.Errorf("unable to setup controller BindDefinition with manager: %w", err)
			}
			setupLog.Info("BindDefinition reconciler configured successfully")
		} else {
			setupLog.Info("BindDefinition reconciler is disabled")
		}

		setupLog.Info("starting manager - waiting for cache sync", "timeout", cacheSyncTimeout)
		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			return fmt.Errorf("unable to set up health check: %w", err)
		}
		if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
			return fmt.Errorf("unable to set up ready check: %w", err)
		}
		if err := mgr.Start(ctx); err != nil {
			return fmt.Errorf("problem running manager: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(controllerCmd)

	controllerCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	controllerCmd.Flags().IntVar(&bindDefinitionConcurrency, "binddefinition-concurrency", 5,
		"Number of concurrent workers for BindDefinition reconciler. Default is 5. Use 0 to disable the reconciler.")
	controllerCmd.Flags().IntVar(&roleDefinitionConcurrency, "roledefinition-concurrency", 5,
		"Number of concurrent workers for RoleDefinition reconciler. Default is 5. Use 0 to disable the reconciler.")
	controllerCmd.Flags().DurationVar(&cacheSyncTimeout, "cache-sync-timeout", 2*time.Minute,
		"Timeout for waiting for CRDs to become available. "+
			"Increase this if CRDs take time to become available. Default is 2 minutes.")
	controllerCmd.Flags().DurationVar(&gracefulShutdownTimeout, "graceful-shutdown-timeout", 30*time.Second,
		"Timeout for graceful shutdown of the manager. Default is 30 seconds.")
	controllerCmd.Flags().BoolVar(&waitForCRDs, "wait-for-crds", true,
		"Wait for required CRDs to be established before starting controllers. "+
			"This prevents cache sync timeout errors when CRDs are not yet installed. Default is true.")
}

// waitForRequiredCRDs waits for all required CRDs to be established before starting controllers.
// This prevents the "timed out waiting for cache to be synced" errors that occur when
// CRDs are not yet installed or not yet established.
func waitForRequiredCRDs(ctx context.Context, cfg *rest.Config, timeout time.Duration) error {
	setupLog.Info("waiting for required CRDs to be established", "timeout", timeout)

	// Create a client for CRD checking (uses direct API calls, not cached)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("unable to create client for CRD waiting: %w", err)
	}

	// Define the CRDs we need to wait for
	requiredGVKs := []schema.GroupVersionKind{
		authorizationv1alpha1.GroupVersion.WithKind("RoleDefinition"),
		authorizationv1alpha1.GroupVersion.WithKind("BindDefinition"),
	}

	waiter := discovery.NewCRDWaiter(c, setupLog)
	if err := waiter.WaitForCRDs(ctx, requiredGVKs, timeout); err != nil {
		return err
	}

	setupLog.Info("all required CRDs are established")
	return nil
}
