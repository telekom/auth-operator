package authorization

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/discovery"
)

var _ = Describe("RoleDefinition Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		// RoleDefinition is cluster-scoped, so Namespace should be empty
		typeNamespacedName := types.NamespacedName{
			Name: resourceName,
		}
		roledefinition := &authorizationv1alpha1.RoleDefinition{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind RoleDefinition")
			err := k8sClient.Get(ctx, typeNamespacedName, roledefinition)
			if err != nil && errors.IsNotFound(err) {
				resource := &authorizationv1alpha1.RoleDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name: resourceName,
					},
					// TODO(user): Specify other spec details if needed.
					Spec: authorizationv1alpha1.RoleDefinitionSpec{
						TargetName: "lorem",
						TargetRole: "ClusterRole",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &authorizationv1alpha1.RoleDefinition{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance RoleDefinition")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			ctx := log.IntoContext(context.Background(), logger)
			controllerReconciler, err := NewRoleDefinitionReconciler(k8sClient, scheme.Scheme, recorder, discovery.NewResourceTracker(scheme.Scheme, cfg))
			Expect(err).NotTo(HaveOccurred())
			go func() {
				for event := range recorder.Events {
					logger.Info("Received event", "event", event)
				}
			}()
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify finalizer was added and conditions are set via SSA
			By("Verifying finalizer and initial conditions are set")
			var updatedRD authorizationv1alpha1.RoleDefinition
			Expect(k8sClient.Get(ctx, typeNamespacedName, &updatedRD)).To(Succeed())

			// Verify Finalizer condition is set (happens before resource tracker check)
			var finalizerCondition *metav1.Condition
			for i := range updatedRD.Status.Conditions {
				if updatedRD.Status.Conditions[i].Type == string(authorizationv1alpha1.FinalizerCondition) {
					finalizerCondition = &updatedRD.Status.Conditions[i]
					break
				}
			}
			Expect(finalizerCondition).NotTo(BeNil(), "Finalizer condition should be set via SSA")
			Expect(finalizerCondition.Status).To(Equal(metav1.ConditionTrue), "Finalizer condition should be True")
		})
	})
})
