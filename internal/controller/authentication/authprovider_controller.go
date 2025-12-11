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
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authentication/v1alpha1"
	"gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/idpclient"
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
	log.V(1).Info("DEBUG: Starting AuthProvider reconciliation", "authProviderName", req.Name, "namespace", req.Namespace)

	r.IDPClient.SetLogger(log)

	// Fetching the AuthProvider custom resource from Kubernetes API
	authProvider := &authenticationv1alpha1.AuthProvider{}
	err := r.Get(ctx, req.NamespacedName, authProvider)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(2).Info("DEBUG: AuthProvider resource not found or already deleted", "authProviderName", req.Name, "namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
		log.Error(err, "ERROR: Unable to fetch AuthProvider resource from Kubernetes API", "authProviderName", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, err
	}

	log.V(2).Info("DEBUG: AuthProvider retrieved", "authProviderName", authProvider.Name, "namespace", authProvider.Namespace)

	// Access token has to be refreshed every 5 minutes
	if err := r.IDPClient.RefreshAccessToken(); err != nil {
		log.Error(err, "ERROR: Failed to refresh IDP access token", "authProviderName", authProvider.Name)
		return ctrl.Result{}, err
	}

	if authProvider.GetDeletionTimestamp() != nil {
		log.V(1).Info("DEBUG: AuthProvider marked for deletion", "authProviderName", authProvider.Name)
		return r.reconcileDeletion(ctx, authProvider)
	}

	if controllerutil.AddFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer) {
		log.V(2).Info("DEBUG: Adding finalizer to AuthProvider", "authProviderName", authProvider.Name)
		if err := r.Update(ctx, authProvider); err != nil {
			log.Error(err, "ERROR: Failed to add finalizer", "authProviderName", authProvider.Name)
			return ctrl.Result{}, err
		}
	}
	return r.reconcile(ctx, authProvider)
}

// reconcile handles the main reconciliation of the AuthProvider
func (r *AuthProviderReconciler) reconcile(ctx context.Context, authProvider *authenticationv1alpha1.AuthProvider) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(2).Info("DEBUG: Starting AuthProvider main reconciliation", "authProviderName", authProvider.Name, "namespace", authProvider.Namespace)

	err := r.validate(ctx, authProvider)
	if err != nil {
		log.Error(err, "ERROR: AuthProvider validation failed", "authProviderName", authProvider.Name)
		return ctrl.Result{}, err
	}
	log.V(3).Info("DEBUG: AuthProvider validation passed", "authProviderName", authProvider.Name)

	aggregatedErrors := []error{}
	// Create IDP groups
	log.V(2).Info("DEBUG: Processing Tenant groups", "authProviderName", authProvider.Name, "tenantGroupCount", len(authProvider.Spec.Tenant.Groups))

	for idx, tenantIDPGroup := range authProvider.Spec.Tenant.Groups {
		log.V(3).Info("DEBUG: Processing Tenant group", "authProviderName", authProvider.Name, "index", idx, "groupType", tenantIDPGroup.GroupType, "groupNames", len(tenantIDPGroup.GroupNames))

		for gidx, groupName := range tenantIDPGroup.GroupNames {
			log.V(3).Info("DEBUG: Reconciling group", "authProviderName", authProvider.Name, "groupName", groupName, "groupIndex", gidx)
			err = r.reconcileGroup(ctx, groupName, tenantIDPGroup.GroupType, tenantIDPGroup.ParentGroup, authProvider.Spec.Tenant.Owners, authProvider.Spec.Tenant.Members)
			if err != nil {
				log.Error(err, "ERROR: Failed to reconcile group", "authProviderName", authProvider.Name, "groupName", groupName)
				aggregatedErrors = append(aggregatedErrors, err)
			}
		}
	}

	log.V(2).Info("DEBUG: Processing ThirdParty groups", "authProviderName", authProvider.Name, "thirdPartyCount", len(authProvider.Spec.ThirdParty))

	for tidx, thirdPartyIDP := range authProvider.Spec.ThirdParty {
		log.V(3).Info("DEBUG: Processing ThirdParty IDP", "authProviderName", authProvider.Name, "thirdPartyIndex", tidx, "groupCount", len(thirdPartyIDP.Groups))

		for _, thirdPartyIDPGroup := range thirdPartyIDP.Groups {
			for gidx, groupName := range thirdPartyIDPGroup.GroupNames {
				log.V(3).Info("DEBUG: Reconciling third-party group", "authProviderName", authProvider.Name, "groupName", groupName, "groupIndex", gidx)
				err = r.reconcileGroup(ctx, groupName, thirdPartyIDPGroup.GroupType, thirdPartyIDPGroup.ParentGroup, thirdPartyIDP.Owners, thirdPartyIDP.Members)
				if err != nil {
					log.Error(err, "ERROR: Failed to reconcile third-party group", "authProviderName", authProvider.Name, "groupName", groupName)
					aggregatedErrors = append(aggregatedErrors, err)
				}
			}
		}
	}

	if len(aggregatedErrors) > 0 {
		log.V(1).Info("DEBUG: Reconciliation finished with errors", "authProviderName", authProvider.Name, "errorCount", len(aggregatedErrors))
	} else {
		log.V(1).Info("DEBUG: Reconciliation finished successfully", "authProviderName", authProvider.Name)
	}
	return ctrl.Result{RequeueAfter: r.RequeueInterval}, kerrors.NewAggregate(aggregatedErrors)
}

func (r *AuthProviderReconciler) reconcileGroup(ctx context.Context, groupName, groupType, parentGroup string, owners []string, members []authenticationv1alpha1.OIDCMember) error {
	log := ctrl.LoggerFrom(ctx)
	log.V(2).Info("DEBUG: Starting group reconciliation", "groupName", groupName, "groupType", groupType, "parentGroup", parentGroup)

	err := r.createIDPGroup(ctx, groupName, groupType, parentGroup)
	if err != nil {
		log.Error(err, "ERROR: Failed to create IDP group", "groupName", groupName, "groupType", groupType)
		return err
	}
	log.V(3).Info("DEBUG: IDP group creation/verification successful", "groupName", groupName)

	err = r.ensureGroupOwnerAssignment(ctx, groupName, groupType, parentGroup, owners)
	if err != nil {
		log.Error(err, "ERROR: Failed to assign group owners", "groupName", groupName, "ownerCount", len(owners))
		return err
	}
	log.V(3).Info("DEBUG: Group owner assignment successful", "groupName", groupName, "ownerCount", len(owners))

	err = r.ensureGroupMemberAssignment(ctx, groupName, groupType, parentGroup, members)
	if err != nil {
		log.Error(err, "ERROR: Failed to assign group members", "groupName", groupName, "memberCount", len(members))
		return err
	}
	log.V(3).Info("DEBUG: Group member assignment successful", "groupName", groupName, "memberCount", len(members))

	log.V(2).Info("DEBUG: Group reconciliation completed successfully", "groupName", groupName)
	return nil
}

// reconcileDeletion handles the deletion of the AuthProvider resource
func (r *AuthProviderReconciler) reconcileDeletion(ctx context.Context, authProvider *authenticationv1alpha1.AuthProvider) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	log.V(1).Info("DEBUG: Starting AuthProvider deletion reconciliation", "authProviderName", authProvider.Name, "namespace", authProvider.Namespace)

	if controllerutil.RemoveFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer) {
		log.V(2).Info("DEBUG: Finalizer found, attempting removal", "authProviderName", authProvider.Name, "finalizer", authenticationv1alpha1.AuthProviderFinalizer)

		if err := r.Update(ctx, authProvider); err != nil {
			log.Error(err, "ERROR: Failed to update AuthProvider after finalizer removal", "authProviderName", authProvider.Name)
			return ctrl.Result{}, err
		}
		log.V(1).Info("DEBUG: Finalizer successfully removed and resource updated", "authProviderName", authProvider.Name)
	} else {
		log.V(2).Info("DEBUG: Finalizer not found or already removed", "authProviderName", authProvider.Name)
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
	log.V(3).Info("DEBUG: Checking if IDP group exists", "groupName", groupName, "groupType", groupType)

	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	getGroupResp, err := r.IDPClient.GetGroup(group)
	if err != nil {
		log.Error(err, "ERROR: Failed to query IDP for existing group", "groupName", groupName)
		return err
	}

	if len(getGroupResp) == 0 {
		log.V(2).Info("DEBUG: IDP Group not found, attempting creation", "groupName", groupName, "groupType", groupType, "parent", groupParent)
		createGroupResp, err := r.IDPClient.CreateGroup(group)
		if err != nil {
			log.Error(err, "ERROR: Failed to create IDP Group", "groupName", groupName)
			return err
		}
		log.V(2).Info("DEBUG: IDP Group created successfully", "groupName", groupName, "status", createGroupResp)
	} else {
		log.V(3).Info("DEBUG: IDP Group already exists", "groupName", groupName)
	}

	return nil
}

func (r *AuthProviderReconciler) deleteIDPGroup(ctx context.Context, groupName, groupType, groupParent string) error {
	// TODO: Implement an idpclient.IsNotFound(err) method
	log := ctrl.LoggerFrom(ctx)
	log.V(3).Info("DEBUG: Checking if IDP group exists for deletion", "groupName", groupName)

	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	resp, err := r.IDPClient.GetGroup(group)
	if err != nil {
		log.Error(err, "ERROR: Failed to query IDP for group during deletion", "groupName", groupName)
		return err
	}
	if len(resp) == 0 {
		log.V(2).Info("DEBUG: IDP group not found or already deleted", "groupName", groupName)
		return nil
	}

	log.V(2).Info("DEBUG: Deleting IDP group", "groupName", groupName)
	idpResponse, err := r.IDPClient.DeleteGroup(group)
	if err != nil {
		log.Error(err, "ERROR: Failed to delete IDP Group", "groupName", groupName)
		return err
	}
	log.V(2).Info("DEBUG: IDP Group deleted successfully", "groupName", groupName, "status", idpResponse)

	return nil
}

func (r *AuthProviderReconciler) ensureGroupOwnerAssignment(ctx context.Context, groupName, groupType, groupParent string, desiredOwnersNames []string) error {
	// TODO: Implement an idpclient.IsNotFound(err) method
	log := ctrl.LoggerFrom(ctx)
	log.V(3).Info("DEBUG: Checking group owners in IDP", "groupName", groupName, "desiredOwnerCount", len(desiredOwnersNames))

	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	groupOwnersInIDP, err := r.IDPClient.GetGroupOwners(group)
	if err != nil {
		log.Error(err, "ERROR: Failed to query group owners from IDP", "groupName", groupName)
		return err
	}
	log.V(3).Info("DEBUG: Current IDP group owners retrieved", "groupName", groupName, "currentOwnerCount", len(groupOwnersInIDP))

	var desiredOwners []idpclient.User
	for _, owner := range desiredOwnersNames {
		desiredOwners = append(desiredOwners, idpclient.User{Username: owner})
	}

	missingOwners := diffUsersSlice(desiredOwners, groupOwnersInIDP)
	if len(missingOwners) > 0 {
		log.V(2).Info("DEBUG: Found missing owners, attempting to add", "groupName", groupName, "missingOwnerCount", len(missingOwners))
		resp, err := r.IDPClient.CreateGroupOwners(group, missingOwners)
		if err != nil {
			log.Error(err, "ERROR: Failed to add IDP group owners", "groupName", groupName, "missingOwnerCount", len(missingOwners), "currentOwnerCount", len(groupOwnersInIDP))
			return err
		}
		log.V(2).Info("DEBUG: Group owners added successfully", "groupName", groupName, "addedOwnerCount", len(missingOwners), "status", resp)
	} else {
		log.V(3).Info("DEBUG: All desired owners already present", "groupName", groupName)
	}

	return nil
}

func (r *AuthProviderReconciler) ensureGroupMemberAssignment(ctx context.Context, groupName, groupType, groupParent string, desiredOIDCMembers []authenticationv1alpha1.OIDCMember) error {
	// TODO: Implement an idpclient.IsNotFound(err) method
	log := ctrl.LoggerFrom(ctx)
	log.V(3).Info("DEBUG: Checking group members in IDP", "groupName", groupName, "desiredMemberCount", len(desiredOIDCMembers))

	group := idpclient.Group{
		Name:   groupName,
		Type:   groupType,
		Parent: groupParent,
	}
	groupMembersInIDP, err := r.IDPClient.GetGroupMembers(group)
	if err != nil {
		log.Error(err, "ERROR: Failed to query group members from IDP", "groupName", groupName)
		return err
	}
	log.V(3).Info("DEBUG: Current IDP group members retrieved", "groupName", groupName, "currentMemberCount", len(groupMembersInIDP))

	desiredMembers := []idpclient.User{}
	for _, member := range desiredOIDCMembers {
		desiredMembers = append(desiredMembers, idpclient.User{Username: member.Name})
	}

	missingMembers := diffUsersSlice(desiredMembers, groupMembersInIDP)
	if len(missingMembers) > 0 {
		log.V(2).Info("DEBUG: Found missing members, attempting to add", "groupName", groupName, "missingMemberCount", len(missingMembers))
		resp, err := r.IDPClient.CreateGroupMembers(group, missingMembers)
		if err != nil {
			log.Error(err, "ERROR: Failed to add IDP group members", "groupName", groupName, "missingMemberCount", len(missingMembers), "currentMemberCount", len(groupMembersInIDP))
			return err
		}
		log.V(2).Info("DEBUG: Group members added successfully", "groupName", groupName, "addedMemberCount", len(missingMembers), "status", resp)
	} else {
		log.V(3).Info("DEBUG: All desired members already present", "groupName", groupName)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthProviderReconciler) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authenticationv1alpha1.AuthProvider{}).
		WithOptions(controller.TypedOptions[reconcile.Request]{
			MaxConcurrentReconciles: concurrency,
		}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
