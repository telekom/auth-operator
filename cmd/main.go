package main

import (
	"crypto/tls"
	"flag"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	idpclient "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/client"

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authentication/v1alpha1"
	authorizationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	authenticationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/internal/controller/authentication"
	authorizationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/internal/controller/authorization"
	authorizationwebhook "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/internal/webhook/authorization"
	// +kubebuilder:scaffold:imports
)

const (
	GeneratorFunction = "generator"
	BinderFunction    = "binder"
	IDPFunction       = "idp"
	EmptyFunction     = "empty"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(authorizationv1alpha1.AddToScheme(scheme))
	utilruntime.Must(authenticationv1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	// Declare some vars
	var metricsAddr string
	var probeAddr string
	var function string
	var webhookPort int
	var enableLeaderElection bool
	var secureMetrics bool
	var enableHTTP2 bool

	// Initialize flags
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metric endpoint binds to. "+"If not set, it will be 0 in order to disable the metrics server.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", "0", "The address the probe endpoint binds to. "+"If not set, it will be 0 in order to disable the healthz/readyz probe.")
	flag.StringVar(&function, "function", "empty", "The function this manager will be hooked up with. "+"The functions can be 'generator|binder|idp'.")
	flag.IntVar(&webhookPort, "webhook-bind-port", 9443, "The port the webhook server binds to. "+"If not set, it will be set to '9443' as a default.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager. "+"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false, "If set the metrics endpoint is served securely.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false, "If set, HTTP/2 will be enabled for the metrics and webhook servers.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

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
		CertDir: "/webhook-server/cert",
		TLSOpts: tlsOpts,
	})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       tlsOpts,
		},
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       function + ".authn-authz.t-caas.telekom.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup the RoleDefinition controller and RoleDefinition webhook/s
	if function == GeneratorFunction {
		// Generate a new Discovery client for API group/resource discovery
		discoveryClient, err := discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
		if err != nil {
			setupLog.Error(err, "unable to initialize Discovery client")
			os.Exit(1)
		}
		if err = (&authorizationcontroller.RoleDefinitionReconciler{
			Client:          mgr.GetClient(),
			Scheme:          mgr.GetScheme(),
			DiscoveryClient: discoveryClient,
			Recorder:        mgr.GetEventRecorderFor("RoleDefinitionReconciler"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "RoleDefinition")
			os.Exit(1)
		}
		if os.Getenv("ENABLE_WEBHOOKS") != "false" {
			if err = (&authorizationv1alpha1.RoleDefinition{}).SetupWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "RoleDefinition")
				os.Exit(1)
			}
		}
	}

	// Setup the BindDefinition controller and BindDefinition webhook/s
	if function == BinderFunction {
		if err = (&authorizationcontroller.BindDefinitionReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("BindDefinitionReconciler"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "BindDefinition")
			os.Exit(1)
		}
		if os.Getenv("ENABLE_WEBHOOKS") != "false" {
			if err = (&authorizationv1alpha1.BindDefinition{}).SetupWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "BindDefinition")
				os.Exit(1)
			}
			// Setup Namespace mutator
			namespaceMutator := &authorizationwebhook.NamespaceMutator{
				Client: mgr.GetClient(),
			}
			if err := namespaceMutator.InjectDecoder(admission.NewDecoder(mgr.GetScheme())); err != nil {
				setupLog.Error(err, "unable to inject decoder", "webhook", "NamespaceMutator")
				os.Exit(1)
			}
			mgr.GetWebhookServer().Register("/mutate-v1-namespace", &webhook.Admission{Handler: namespaceMutator})

			// Setup Namespace validator
			namespaceValidator := &authorizationwebhook.NamespaceValidator{
				Client: mgr.GetClient(),
			}
			if err := namespaceValidator.InjectDecoder(admission.NewDecoder(mgr.GetScheme())); err != nil {
				setupLog.Error(err, "unable to inject decoder", "webhook", "NamespaceValidator")
				os.Exit(1)
			}
			mgr.GetWebhookServer().Register("/validate-v1-namespace", &webhook.Admission{Handler: namespaceValidator})
		}
	}

	// Setup the AuthProvider controller and AuthProvider webhook/s
	if function == IDPFunction {
		// Setup an IDP client for AuthProviderReconciler
		// Needs refactoring -> transition to interface and define method group which
		// must be satisfied by all IDP clients to make this as generic as possible
		idpClient, err := idpclient.NewIDPClient(idpclient.Config{
			IDPBasePath:     "portal.security.in.pan-net.eu:443",
			RefreshBasePath: "portal.security.in.pan-net.eu:443", // this is currently the same but can change
			APIToken:        "3Y_F0D5SIwfsEwegxYjY8gCwHM_znXjzkgk-8N0EDcgDAcQYB5nTzngPlpX9hHbQ4VuGGjjl9k_PqC7gF_G_dfO608wZn5ekkJuLUk3dxekicJex8-j2ywCBHyvaitvXR1lGUruucMtNMJydXJf4gR0hIfreVR_8WKh5jRMYIeQr3Yd8NCm351aspPFq9qIwL3uljjO0lIEMjcZEdiWFikBia5q3eZBC2vTK3NT9Obaj4enJ8RlfN9Woo1FOx1WjoOw10MczUyVp_r4iytEoq-0QnovLNwbJmmdOigjzhyY1IrpPtplr3Qmc0T181t8sPRN58K_mA05lRkfs9lwtJTY4Iznbtm-oLaIwoIfolRsXLf-Z1W5HPBlCjD4iGYcxVCovLwdITnvyU3EZEFt83ng6lqY-CCULryX2BE0NOozkT7314kn0dA0DKNAJwb8hJCqGJh_i3Wc9MTnNoJxgexCzZPljpNxXtWJLGKiWYGVsUhiXMu4F_V3EC4ecV8PfNS0IXdq6HZBYR4Iv7j4lJw",
		}, idpclient.Options{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		})
		if err != nil {
			setupLog.Error(err, "unable to initialize IDP client")
			os.Exit(1)
		}

		if err = (&authenticationcontroller.AuthProviderReconciler{
			Client:    mgr.GetClient(),
			Scheme:    mgr.GetScheme(),
			IDPClient: *idpClient,
			Recorder:  mgr.GetEventRecorderFor("AuthProviderReconciler"),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "AuthProvider")
			os.Exit(1)
		}
	}

	if function == EmptyFunction {
		setupLog.Info("function is not defined", "FUNCTION", function)
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	// Setup Health and Readiness probes
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
