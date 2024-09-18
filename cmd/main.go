package main

import (
	"crypto/tls"
	"flag"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	idpclient "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/pkg/client"
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

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authentication/v1alpha1"
	authorizationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	authenticationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/internal/controller/authentication"
	authorizationcontroller "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/internal/controller/authorization"
	// +kubebuilder:scaffold:imports
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
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metric endpoint binds to. "+
		"Use the port :8080. If not set, it will be 0 in order to disable the metrics server")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"If set the metrics endpoint is served securely")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
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
		LeaderElectionID:       "20f41764.t-caas.telekom.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to initialize Discovery client")
		os.Exit(1)
	}

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
	if err = (&authorizationcontroller.BindDefinitionReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "BindDefinition")
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
	// +kubebuilder:scaffold:builder

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
