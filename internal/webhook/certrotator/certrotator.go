package certrotator

import (
	"errors"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch

const (
	caName         = "cert"
	caOrganization = "t-caas"
)

func Enable(
	mgr manager.Manager,
	namespace string,
	dir string,
	dnsName string,
	secretName string,
	webhooks []rotator.WebhookInfo,
	notifyFinished chan struct{},
) error {
	if namespace == "" {
		return errors.New("namespace is undefined. can't enable cert rotator")
	}
	if dir == "" {
		return errors.New("certs-dir is undefined. can't enable cert rotator")
	}
	if caName == "" {
		return errors.New("caName is undefined. can't enable cert rotator")
	}

	err := rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey:              types.NamespacedName{Namespace: namespace, Name: secretName},
		RequireLeaderElection:  true,
		RestartOnSecretRefresh: true,
		CertDir:                dir,
		CAName:                 caName,
		CAOrganization:         caOrganization,
		DNSName:                dnsName,
		IsReady:                notifyFinished,
		Webhooks:               webhooks,
	})
	if err != nil {
		return err
	}
	return nil
}
