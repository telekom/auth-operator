/*
Copyright © 2026 Deutsche Telekom AG
*/
package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/system"
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

// redactSensitiveFlags returns a map of flags with sensitive values redacted
func redactSensitiveFlags() map[string]string {
	flagValues := make(map[string]string)
	sensitiveFlags := map[string]bool{
		"api-token":     true,
		"API_TOKEN":     true,
		"password":      true,
		"secret":        true,
		"token":         true,
		"key":           true,
		"auth":          true,
		"client-secret": true,
		"client_secret": true,
		"private-key":   true,
		"private_key":   true,
	}

	flag.VisitAll(func(f *flag.Flag) {
		name := f.Name
		value := f.Value.String()

		// Check if this is a sensitive flag
		isSensitive := false
		for sensitiveKey := range sensitiveFlags {
			if strings.Contains(strings.ToLower(name), strings.ToLower(sensitiveKey)) {
				isSensitive = true
				break
			}
		}

		if isSensitive && value != "" {
			flagValues[name] = "[REDACTED]"
		} else {
			flagValues[name] = value
		}
	})

	return flagValues
}

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
		// Set the verbosity level for klog
		_ = flag.Set("v", fmt.Sprintf("%d", verbosity))

		ctrl.SetLogger(klog.NewKlogr())
		log := klog.NewKlogr()

		log.Info("app info", "name", system.Name, "version", system.Version, "commit", system.Commit)
		log.Info("startup flags", "verbosity", verbosity, "namespace", namespace, "health-probe-bind-address", probeAddr)

		// Log all flags with redaction of sensitive values
		redactedFlags := redactSensitiveFlags()
		for flagName, flagValue := range redactedFlags {
			log.V(3).Info("flag", "name", flagName, "value", flagValue)
		}
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

	rootCmd.PersistentFlags().StringVar(&namespace, "namespace", os.Getenv("POD_NAMESPACE"), "operator namespace")
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbosity", "v", 2, "Log level (0-9)")
	rootCmd.PersistentFlags().StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
}

func initScheme() {
	scheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
}
