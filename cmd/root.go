/*
Copyright © 2026 Deutsche Telekom AG.
*/
package cmd

import (
	"flag"
	"fmt"
	"os"
	"regexp"

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

// sensitivePattern matches flag names that may contain sensitive data.
// Matches common patterns like: token, secret, password, key, auth, credential, api-key, etc.
var sensitivePattern = regexp.MustCompile(`(?i)(token|secret|password|passphrase|key|auth|credential|private|cert|bearer|api[_-]?key|client[_-]?id)`)

var (
	setupLog    logr.Logger
	scheme      *runtime.Scheme
	verbosity   int
	probeAddr   string
	metricsAddr string
	namespace   string
)

// redactSensitiveFlags returns a map of flags with sensitive values redacted.
// Uses regex pattern matching to identify flags that may contain sensitive data.
func redactSensitiveFlags() map[string]string {
	flagValues := make(map[string]string)

	flag.VisitAll(func(f *flag.Flag) {
		name := f.Name
		value := f.Value.String()

		// Use regex to check if this is a sensitive flag
		if sensitivePattern.MatchString(name) && value != "" {
			flagValues[name] = "[REDACTED]"
		} else {
			flagValues[name] = value
		}
	})

	return flagValues
}

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "auth-operator",
	Short: "Kubernetes operator for managing RBAC with RoleDefinitions, BindDefinitions, and WebhookAuthorizers",
	Long: `Auth Operator is a Kubernetes operator that provides declarative RBAC management
through Custom Resource Definitions (CRDs).

It supports three main resource types:
  - RoleDefinition: Dynamically generates ClusterRoles or Roles based on API discovery
  - BindDefinition: Creates RoleBindings/ClusterRoleBindings with namespace selectors
  - WebhookAuthorizer: Configures authorization webhooks for fine-grained access control

The operator watches for changes in the cluster's API resources and automatically
updates the generated roles to reflect the current state of available APIs.

For more information, visit: https://github.com/telekom/auth-operator`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Set the verbosity level for klog
		_ = flag.Set("v", fmt.Sprintf("%d", verbosity))

		ctrl.SetLogger(klog.NewKlogr())
		log := klog.NewKlogr()

		log.Info("app info", "name", system.Name, "version", system.Version, "commit", system.Commit)
		log.Info("startup flags", "verbosity", verbosity, "namespace", namespace,
			"health-probe-bind-address", probeAddr, "metrics-bind-address", metricsAddr)

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
	rootCmd.PersistentFlags().StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the metrics endpoint binds to. Use \"0\" to disable metrics serving.")
}

func initScheme() {
	scheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
}
