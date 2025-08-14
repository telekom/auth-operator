package authentication

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authentication/v1alpha1"
	idpclient2 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/client"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/test/mock"
)

var _ = Describe("AuthProvider Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"
		const groupOwner = "foo"
		const groupName = "bar"
		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		authprovider := &authenticationv1alpha1.AuthProvider{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind AuthProvider")
			err := k8sClient.Get(ctx, typeNamespacedName, authprovider)
			if err != nil && errors.IsNotFound(err) {
				resource := &authenticationv1alpha1.AuthProvider{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: authenticationv1alpha1.AuthProviderSpec{
						Tenant: authenticationv1alpha1.ClusterConsumer{
							Owners: []string{groupOwner},
							Groups: []authenticationv1alpha1.OIDCGroup{
								{
									GroupNames: []string{groupName},
								},
							},
						},
					},
					// TODO(user): Specify other spec details if needed.
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &authenticationv1alpha1.AuthProvider{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance AuthProvider")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			mockIDPClient := idpclient.NewMockClient(gomock.NewController(GinkgoT()))
			mockIDPClient.EXPECT().SetLogger(gomock.Any()).Times(1)
			mockIDPClient.EXPECT().RefreshAccessToken(gomock.Any()).Times(1)
			mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient2.Group{
				{
					Name: groupName,
				},
			}, nil).Times(1)
			controllerReconciler := &AuthProviderReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				IDPClient: mockIDPClient,
				Recorder:  recorder,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})
