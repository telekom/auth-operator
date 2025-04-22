/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/tls"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/client-go/discovery"

	idpclient "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/client"

	authenticationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/controller/authentication"
	authorizationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/controller/authorization"

	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var enableLeaderElection bool

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

		if err = (&authorizationcontroller.RoleDefinitionReconciler{
			Client:          mgr.GetClient(),
			Scheme:          mgr.GetScheme(),
			DiscoveryClient: discoveryClient,
			Recorder:        mgr.GetEventRecorderFor("RoleDefinitionReconciler"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to create controller RoleDefinition: %w", err)
		}

		if err = (&authorizationcontroller.BindDefinitionReconciler{
			Client:          mgr.GetClient(),
			Scheme:          mgr.GetScheme(),
			DiscoveryClient: discoveryClient,
			DynamicClient:   dynamicClient,
			Recorder:        mgr.GetEventRecorderFor("BindDefinitionReconciler"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to create controller BindDefinition: %w", err)
		}

		// Setup an IDP client for AuthProviderReconciler
		// Needs refactoring -> transition to interface and define method group which
		// must be satisfied by all IDP clients to make this as generic as possible
		idpClient, err := idpclient.NewIDPClient(idpclient.Config{
			// TODO: make it configurable
			IDPBasePath:     "portal.security.in.pan-net.eu:443",
			RefreshBasePath: "portal.security.in.pan-net.eu:443", // this is currently the same but can change
			// TODO: remove token from here
			APIToken: "3Y_F0D5SIwfsEwegxYjY8gCwHM_znXjzkgk-8N0EDcgDAcQYB5nTzngPlpX9hHbQ4VuGGjjl9k_PqC7gF_G_dfO608wZn5ekkJuLUk3dxekicJex8-j2ywCBHyvaitvXR1lGUruucMtNMJydXJf4gR0hIfreVR_8WKh5jRMYIeQr3Yd8NCm351aspPFq9qIwL3uljjO0lIEMjcZEdiWFikBia5q3eZBC2vTK3NT9Obaj4enJ8RlfN9Woo1FOx1WjoOw10MczUyVp_r4iytEoq-0QnovLNwbJmmdOigjzhyY1IrpPtplr3Qmc0T181t8sPRN58K_mA05lRkfs9lwtJTY4Iznbtm-oLaIwoIfolRsXLf-Z1W5HPBlCjD4iGYcxVCovLwdITnvyU3EZEFt83ng6lqY-CCULryX2BE0NOozkT7314kn0dA0DKNAJwb8hJCqGJh_i3Wc9MTnNoJxgexCzZPljpNxXtWJLGKiWYGVsUhiXMu4F_V3EC4ecV8PfNS0IXdq6HZBYR4Iv7j4lJw",
		}, idpclient.Options{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		})
		if err != nil {
			return fmt.Errorf("unable to initialize IDP client: %w", err)
		}

		if err = (&authenticationcontroller.AuthProviderReconciler{
			Client:    mgr.GetClient(),
			Scheme:    mgr.GetScheme(),
			IDPClient: *idpClient,
			Recorder:  mgr.GetEventRecorderFor("AuthProviderReconciler"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to create controller AuthProvider: %w", err)
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
}
