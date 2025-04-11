/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authentication/v1alpha1"
	authorizationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	"gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/system"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	setupLog  logr.Logger
	scheme    *runtime.Scheme
	verbosity int
	probeAddr string
	namespace string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "auth-operator",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		ctrl.SetLogger(klog.NewKlogr())
		log := klog.NewKlogr()
		log.Info("app info", "name", system.Name, "version", system.Version, "commit", system.Commit)
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	setupLog = ctrl.Log.WithName("setup")
	klog.InitFlags(nil)
	cobra.OnInitialize(initScheme)

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().StringVar(&namespace, "namespace", os.Getenv("POD_NAMESPACE"), "operator namespace")
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbosity", "v", 2, "Log level (0-9)")
	rootCmd.PersistentFlags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
}

func initScheme() {
	scheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))
	utilruntime.Must(authenticationv1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
}
