package authentication

import (
	"context"
	"fmt"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authentication/v1alpha1"
	idpclient "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/client"
)

const (
	TenantGroupParent     = "M - T_CaaS_Tenant"
	ThirdPartyGroupParent = "M - T_CaaS_Third_Party"
)

// diffUsersSlice returns the elements in 'a' that are not in 'b' based on idpclient.User Username
func diffUsersSlice(a, b []idpclient.User) []idpclient.User {
	diff := []idpclient.User{}
	for _, item := range a {
		found := slices.ContainsFunc(b, func(u idpclient.User) bool {
			return item.Username == u.Username
		})

		if !found {
			diff = append(diff, item)
		}
	}
	return diff
}

// AuthProviderReconciler reconciles a AuthProvider object
type AuthProviderReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	IDPClient       idpclient.Client
	Recorder        record.EventRecorder
	RequeueInterval time.Duration
}

func (r *AuthProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	r.IDPClient.SetLogger(log)

	// Fetching the AuthProvider custom resource from Kubernetes API
	authProvider := &authenticationv1alpha1.AuthProvider{}
	err := r.Get(ctx, req.NamespacedName, authProvider)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("AuthProvider resource not found or already deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Unable to fetch AuthProvider resource from Kubernetes API")
		return ctrl.Result{}, err
	}

	// Access token has to be refreshed every 5 minutes
	if err := r.IDPClient.RefreshAccessToken(); err != nil {
		return ctrl.Result{}, err
	}

	if authProvider.GetDeletionTimestamp() != nil {
		return r.reconcileDeletion(ctx, authProvider)
	}
	if controllerutil.AddFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer) {
		if err := r.Update(ctx, authProvider); err != nil {
			return ctrl.Result{}, err
		}
	}
	return r.reconcile(ctx, authProvider)
}

// reconcile handles the main reconciliation of the AuthProvider
func (r *AuthProviderReconciler) reconcile(ctx context.Context, authProvider *authenticationv1alpha1.AuthProvider) (ctrl.Result, error) {
	err := r.validate(ctx, authProvider)
	if err != nil {
		return ctrl.Result{}, err
	}

	aggregatedErrors := []error{}
	// Create IDP groups
	for _, tenantIDPGroup := range authProvider.Spec.Tenant.Groups {
		for _, groupName := range tenantIDPGroup.GroupNames {
			err = r.reconcileGroup(ctx, groupName, tenantIDPGroup.GroupType, tenantIDPGroup.ParentGroup, authProvider.Spec.Tenant.Owners, authProvider.Spec.Tenant.Members)
			if err != nil {
				aggregatedErrors = append(aggregatedErrors, err)
			}
		}
	}
	for _, thirdPartyIDP := range authProvider.Spec.ThirdParty {
		for _, thirdPartyIDPGroup := range thirdPartyIDP.Groups {
			for _, groupName := range thirdPartyIDPGroup.GroupNames {
				err = r.reconcileGroup(ctx, groupName, thirdPartyIDPGroup.GroupType, thirdPartyIDPGroup.ParentGroup, thirdPartyIDP.Owners, thirdPartyIDP.Members)
				if err != nil {
					aggregatedErrors = append(aggregatedErrors, err)
				}
			}
		}
	}

	return ctrl.Result{RequeueAfter: r.RequeueInterval}, kerrors.NewAggregate(aggregatedErrors)
}

func (r *AuthProviderReconciler) reconcileGroup(ctx context.Context, groupName, groupType, parentGroup string, owners []string, members []authenticationv1alpha1.OIDCMember) error {
	err := r.createIDPGroup(ctx, groupName, groupType, parentGroup)
	if err != nil {
		return err
	}
	err = r.ensureGroupOwnerAssignment(ctx, groupName, groupType, parentGroup, owners)
	if err != nil {
		return err
	}
	err = r.ensureGroupMemberAssignment(ctx, groupName, groupType, parentGroup, members)
	if err != nil {
		return err
	}

	return nil
}

// reconcileDeletion handles the deletion of the AuthProvider resource
func (r *AuthProviderReconciler) reconcileDeletion(ctx context.Context, authProvider *authenticationv1alpha1.AuthProvider) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	if controllerutil.RemoveFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer) {
		log.Info("Removing Finalizer for the AuthProvider")
		if err := r.Update(ctx, authProvider); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// validate validates all resources required to reconcile authProvider
func (r *AuthProviderReconciler) validate(ctx context.Context, authProvider *authenticationv1alpha1.AuthProvider) error {
	for _, tenantIDPGroup := range authProvider.Spec.Tenant.Groups {
		for _, groupName := range tenantIDPGroup.GroupNames {
			if tenantIDPGroup.ParentGroup != TenantGroupParent {
				return fmt.Errorf("only groups with parent \"%s\" are allowed for the tenant (see tenant \"%s\" and idp group \"%s\")", TenantGroupParent, authProvider.Spec.Tenant.Name, groupName)
			}
		}
	}
	for _, thirdPartyIDP := range authProvider.Spec.ThirdParty {
		for _, thirdPartyIDPGroup := range thirdPartyIDP.Groups {
			for _, groupName := range thirdPartyIDPGroup.GroupNames {
				if thirdPartyIDPGroup.ParentGroup != ThirdPartyGroupParent {
					return fmt.Errorf("only groups with parent \"%s\" are allowed for the thirdparty (see thirdparty \"%s\" and idp group \"%s\")", ThirdPartyGroupParent, thirdPartyIDP.Name, groupName)
				}
			}
		}
	}
	return nil
}

func (r *AuthProviderReconciler) createIDPGroup(ctx context.Context, groupName, groupType, groupParent string) error {
	// TODO: Implement an idpclient.IsNotFound(err) method
	log := ctrl.LoggerFrom(ctx)
	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	getGroupResp, err := r.IDPClient.GetGroup(group)
	if err != nil {
		return err
	}
	if len(getGroupResp) == 0 {
		log.Info("IDP Group not found in TDI IDP", "group", group.Name)
		createGroupResp, err := r.IDPClient.CreateGroup(group)
		if err != nil {
			log.Error(err, "failed to create IDP Group", "group", group.Name)
			return err
		}
		log.Info("Group creation finished", "status", createGroupResp)
	}

	return nil
}

func (r *AuthProviderReconciler) deleteIDPGroup(ctx context.Context, groupName, groupType, groupParent string) error {
	// TODO: Implement an idpclient.IsNotFound(err) method
	log := ctrl.LoggerFrom(ctx)
	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	resp, err := r.IDPClient.GetGroup(group)
	if err != nil {
		return err
	}
	if len(resp) == 0 {
		log.Info("IDP group not found or already deleted in TDI IDP", "group", group.Name)
		return nil
	}

	idpResponse, err := r.IDPClient.DeleteGroup(group)
	if err != nil {
		log.Error(err, "failed to delete IDP Group", "group", group.Name)
		return err
	}
	log.Info("Group deletion finished", "status", idpResponse)

	return nil
}

func (r *AuthProviderReconciler) ensureGroupOwnerAssignment(ctx context.Context, groupName, groupType, groupParent string, desiredOwnersNames []string) error {
	// TODO: Implement an idpclient.IsNotFound(err) method
	log := ctrl.LoggerFrom(ctx)
	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	groupOwnersInIDP, err := r.IDPClient.GetGroupOwners(group)
	if err != nil {
		return err
	}

	var desiredOwners []idpclient.User
	for _, owner := range desiredOwnersNames {
		desiredOwners = append(desiredOwners, idpclient.User{Username: owner})
	}

	missingOwners := diffUsersSlice(desiredOwners, groupOwnersInIDP)
	if len(missingOwners) > 0 {
		log.Info("Adding missing owners into TDI IDP group", "group", group, "owners", missingOwners)
		resp, err := r.IDPClient.CreateGroupOwners(group, missingOwners)
		if err != nil {
			log.Error(err, "failed to add IDP group owners", "currentOwners", groupOwnersInIDP, "newAdditionalOwners", missingOwners)
			return err
		}
		log.Info("Owner creation finished", "group", group.Name, "status", resp)
	}

	return nil
}

func (r *AuthProviderReconciler) ensureGroupMemberAssignment(ctx context.Context, groupName, groupType, groupParent string, desiredOIDCMembers []authenticationv1alpha1.OIDCMember) error {
	// TODO: Implement an idpclient.IsNotFound(err) method
	log := ctrl.LoggerFrom(ctx)
	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	groupMembersInIDP, err := r.IDPClient.GetGroupMembers(group)
	if err != nil {
		return err
	}

	desiredMembers := []idpclient.User{}
	for _, member := range desiredOIDCMembers {
		desiredMembers = append(desiredMembers, idpclient.User{Username: member.Name})
	}

	missingMembers := diffUsersSlice(desiredMembers, groupMembersInIDP)
	if len(missingMembers) > 0 {
		log.Info("Adding missing members into TDI IDP group", "group", group, "members", missingMembers)
		resp, err := r.IDPClient.CreateGroupMembers(group, missingMembers)
		if err != nil {
			log.Error(err, "failed to add IDP group members", "currentMembers", groupMembersInIDP, "newAdditionalMembers", missingMembers)
			return err
		}
		log.Info("Member creation finished", "group", group.Name, "status", resp)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authenticationv1alpha1.AuthProvider{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
