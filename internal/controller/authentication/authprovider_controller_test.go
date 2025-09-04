package authentication

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"reflect"
	"testing"

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authentication/v1alpha1"
	idpclient "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/client"
	idpclienttest "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/test/mock"
)

func TestDiffUsersSlice(t *testing.T) {
	tests := []struct {
		name string
		a    []idpclient.User
		b    []idpclient.User
		want []idpclient.User
	}{
		{
			name: "returns users in 'a' not in 'b' by Username",
			a: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
				{Username: "carol"},
			},
			b: []idpclient.User{
				{Username: "bob"},
				{Username: "dave"},
			},
			want: []idpclient.User{
				{Username: "alice"},
				{Username: "carol"},
			},
		},
		{
			name: "all users in 'a' are in 'b'",
			a: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
			},
			b: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
				{Username: "carol"},
			},
			want: []idpclient.User{},
		},
		{
			name: "no users in 'a' are in 'b'",
			a: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
			},
			b: []idpclient.User{
				{Username: "carol"},
				{Username: "dave"},
			},
			want: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
			},
		},
		{
			name: "empty 'a' slice",
			a:    []idpclient.User{},
			b: []idpclient.User{
				{Username: "carol"},
			},
			want: []idpclient.User{},
		},
		{
			name: "empty 'b' slice",
			a: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
			},
			b: []idpclient.User{},
			want: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
			},
		},
		{
			name: "both slices empty",
			a:    []idpclient.User{},
			b:    []idpclient.User{},
			want: []idpclient.User{},
		},
		{
			name: "duplicate usernames in 'a'",
			a: []idpclient.User{
				{Username: "alice"},
				{Username: "alice"},
				{Username: "bob"},
			},
			b: []idpclient.User{
				{Username: "bob"},
			},
			want: []idpclient.User{
				{Username: "alice"},
				{Username: "alice"},
			},
		},
		{
			name: "duplicate usernames in 'b'",
			a: []idpclient.User{
				{Username: "alice"},
				{Username: "bob"},
			},
			b: []idpclient.User{
				{Username: "bob"},
				{Username: "bob"},
			},
			want: []idpclient.User{
				{Username: "alice"},
			},
		},
		{
			name: "case sensitivity",
			a: []idpclient.User{
				{Username: "Alice"},
				{Username: "alice"},
			},
			b: []idpclient.User{
				{Username: "alice"},
			},
			want: []idpclient.User{
				{Username: "Alice"},
			},
		},
		{
			name: "empty usernames",
			a: []idpclient.User{
				{Username: ""},
				{Username: "bob"},
			},
			b: []idpclient.User{
				{Username: ""},
			},
			want: []idpclient.User{
				{Username: "bob"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffUsersSlice(tt.a, tt.b)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("diffUsersSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateIDPGroup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	group := idpclient.Group{
		Name:   "testgroup",
		Type:   "type1",
		Parent: "parent1",
	}

	t.Run("create group if not found", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		createGroupResp := []idpclient.Response{
			{Name: group.Name, Status: "200", Message: "Success"},
		}
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient.Group{}, nil)
		mockIDPClient.EXPECT().CreateGroup(group).Return(createGroupResp, nil)

		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.createIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("do not create group if already exists", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient.Group{{Name: "S - testgroup"}}, nil)
		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.createIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("return error if GetGroup fails", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return(nil, errors.New("fatal"))
		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.createIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})

	t.Run("return error if CreateGroup fails", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		createGroupResp := []idpclient.Response{
			{Name: "", Status: "500", Message: "Internal Server Error"},
		}
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient.Group{}, nil)
		mockIDPClient.EXPECT().CreateGroup(group).Return(createGroupResp, errors.New("fatal"))
		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.createIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})
}

func TestDeleteIDPGroup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	group := idpclient.Group{
		Name:   "testgroup",
		Type:   "type1",
		Parent: "parent1",
	}

	t.Run("delete existing group", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		deleteGroupResp := []idpclient.Response{
			{Name: "S - " + group.Name, Status: "200", Message: "Success"},
		}
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient.Group{{Name: "S - testgroup"}}, nil)
		mockIDPClient.EXPECT().DeleteGroup(gomock.Any()).Return(deleteGroupResp, nil)

		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.deleteIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("do nothing if group not found", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient.Group{}, nil)

		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.deleteIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("return error if GetGroup fails", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return(nil, errors.New("fatal"))

		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.deleteIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})

	t.Run("return error if DeleteGroup fails", func(t *testing.T) {
		ctx := context.TODO()
		mockIDPClient := idpclienttest.NewMockClient(ctrl)
		deleteGroupResp := []idpclient.Response{
			{Name: "", Status: "500", Message: "Internal Server Error"},
		}
		mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient.Group{{Name: "S - testgroup"}}, nil)
		mockIDPClient.EXPECT().DeleteGroup(gomock.Any()).Return(deleteGroupResp, errors.New("fatal"))

		reconciler := &AuthProviderReconciler{IDPClient: mockIDPClient}
		err := reconciler.deleteIDPGroup(ctx, group.Name, group.Type, group.Parent)
		if err == nil {
			t.Errorf("expected error, got nil")
		}
	})
}

var _ = Describe("AuthProvider Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"
		const groupOwner = "foo"
		const groupMember = "foo"
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
			if err != nil && apimachineryerrors.IsNotFound(err) {
				resource := &authenticationv1alpha1.AuthProvider{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: authenticationv1alpha1.AuthProviderSpec{
						Tenant: authenticationv1alpha1.ClusterConsumer{
							Owners: []string{groupOwner},
							Members: []authenticationv1alpha1.OIDCMember{
								{
									Name:       groupMember,
									GroupNames: []string{},
								},
							},
							Groups: []authenticationv1alpha1.OIDCGroup{
								{
									GroupNames:  []string{groupName},
									ParentGroup: TenantGroupParent,
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
			mockIDPClient := idpclienttest.NewMockClient(gomock.NewController(GinkgoT()))
			mockIDPClient.EXPECT().SetLogger(gomock.Any()).Times(1)
			mockIDPClient.EXPECT().RefreshAccessToken().Times(1)
			mockIDPClient.EXPECT().GetGroup(gomock.Any()).Return([]idpclient.Group{
				{
					Name:   groupName,
					Parent: TenantGroupParent,
				},
			}, nil).Times(1)
			mockIDPClient.EXPECT().GetGroupOwners(gomock.Any()).Return([]idpclient.User{}, nil).Times(1)
			mockIDPClient.EXPECT().CreateGroupOwners(idpclient.Group{Name: groupName, Parent: TenantGroupParent}, []idpclient.User{{Username: groupOwner}}).Return([]idpclient.Response{
				{
					Name:    "create",
					Status:  "200",
					Message: "success",
				},
			}, nil).Times(1)
			mockIDPClient.EXPECT().GetGroupMembers(gomock.Any()).Return([]idpclient.User{}, nil).Times(1)
			mockIDPClient.EXPECT().CreateGroupMembers(idpclient.Group{Name: groupName, Parent: TenantGroupParent}, []idpclient.User{{Username: groupMember}}).Return([]idpclient.Response{
				{
					Name:    "create",
					Status:  "200",
					Message: "success",
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
