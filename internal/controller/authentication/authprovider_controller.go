package authentication

import (
	"context"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	authenticationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authentication/v1alpha1"
	idpclient "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Helper function to extract usernames from Owners and Members
func extractUsernames(users []idpclient.User) []string {
	usernames := make([]string, len(users))
	for i, user := range users {
		usernames[i] = user.Username
	}
	return usernames
}

// Function to check if two slices of strings match after sorting
func slicesMatch(authprovider, idp []string) (bool, bool) {
	sort.Strings(authprovider)
	sort.Strings(idp)
	for i, v := range authprovider {
		if i >= len(idp) || v != idp[i] {
			return false, len(authprovider) <= len(idp)
		}
	}
	return true, len(authprovider) <= len(idp)
}

// AuthProviderReconciler reconciles a AuthProvider object
type AuthProviderReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	IDPClient idpclient.IDPClient
	Recorder  record.EventRecorder
}

func (r *AuthProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Pass the same Logger into IDPClient
	r.IDPClient.Log = &log

	// Declare some static vars for IDP interaction
	// Tenant IDP variables
	var idpTenantGroups idpclient.Groups
	var idpTenantOwners idpclient.Owners
	var idpTenantMembers idpclient.Members
	var idpTenantMemberGroups idpclient.Groups

	// Third party IDP variables
	var idpThirdPartyGroups idpclient.Groups
	var idpThirdPartyOwners idpclient.Owners
	var idpThirdPartyMembers idpclient.Members
	var idpThirdPartyMemberGroups idpclient.Groups

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
	if err := r.IDPClient.RefreshAccessToken("/api/token-issuer/v1/apikey/refresh"); err != nil {
		return ctrl.Result{}, err
	}

	// Assign values from K8s API to OIDC client for tenants and third parties
	for _, group := range authProvider.Spec.Tenant.Groups {
		for _, groupName := range group.GroupNames {
			idpTenantGroups.IDPGroups = append(idpTenantGroups.IDPGroups, idpclient.Group{
				Name:   groupName,
				Type:   group.GroupType,
				Parent: group.ParentGroup,
			})
		}
	}

	for _, thirdparty := range authProvider.Spec.ThirdParty {
		for _, group := range thirdparty.Groups {
			for _, groupName := range group.GroupNames {
				idpThirdPartyGroups.IDPGroups = append(idpThirdPartyGroups.IDPGroups, idpclient.Group{
					Name:   groupName,
					Type:   group.GroupType,
					Parent: group.ParentGroup,
				})
			}
		}
	}

	// Check if AuthProvider is marked to be deleted
	if authProvider.ObjectMeta.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer) {
			log.Info("Adding Finalizer for the AuthProvider")
			controllerutil.AddFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer)
			if err := r.Update(ctx, authProvider); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// AuthProvider is marked to be deleted
		log.Info("Deleting generated IDP Groups for the AuthProvider, as it is marked for deletion")
		if controllerutil.ContainsFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer) {
			for _, idpgroup := range idpTenantGroups.IDPGroups {
				idpgroup.Name = "S - " + idpgroup.Name
				idpGroupsResponse, err := r.IDPClient.GetGroup(idpgroup)
				if len(idpGroupsResponse) == 0 { // implement a idpclient.IsNotFound(err) method
					log.Info("IDP Groups not found or already deleted", "Group", idpgroup.Name)
				}
				if err != nil {
					log.Info("Unforseen error occured", "ERROR", err)
					return ctrl.Result{}, err
				}
				idpResponse := []idpclient.Response{}
				idpResponse, err = r.IDPClient.DeleteGroup(idpgroup)
				if err != nil {
					log.Info("Failed to delete IDP Group", "IDPGROUP", idpgroup.Name)
					return ctrl.Result{}, err
				}
				log.Info("Group deletion status", "STATUS", idpResponse)
			}

			for _, idpgroup := range idpThirdPartyGroups.IDPGroups {
				idpgroup.Name = "S - " + idpgroup.Name
				idpGroupsResponse, err := r.IDPClient.GetGroup(idpgroup)
				if len(idpGroupsResponse) == 0 { // implement a idpclient.IsNotFound(err) method
					log.Info("IDP Groups not found or already deleted", "Group", idpgroup.Name)
				}
				if err != nil {
					log.Info("Unforseen error occured", "ERROR", err)
					return ctrl.Result{}, err
				}
				idpResponse := []idpclient.Response{}
				idpResponse, err = r.IDPClient.DeleteGroup(idpgroup)
				if err != nil {
					log.Info("Failed to delete IDP Group", "IDPGROUP", idpgroup.Name)
					return ctrl.Result{}, err
				}
				log.Info("Group deletion status", "STATUS", idpResponse)
			}

			log.Info("Removing Finalizer for the AuthProvider")
			controllerutil.RemoveFinalizer(authProvider, authenticationv1alpha1.AuthProviderFinalizer)
			if err := r.Update(ctx, authProvider); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		log.Info("AuthProvider is marked to be deleted, but has no finalizer")
		return ctrl.Result{}, nil
	}

	// Otherwise create groups
	for _, idpgroup := range idpTenantGroups.IDPGroups {
		idpgroup.Name = "S - " + idpgroup.Name
		idpGroupsResponse, err := r.IDPClient.GetGroup(idpgroup)
		if len(idpGroupsResponse) == 0 { // implement a idpclient.IsNotFound(err) method
			log.Info("IDP Group not found in TDI IDP", "Group", idpgroup.Name)
			idpResponse := []idpclient.Response{}
			idpgroup.Name = strings.TrimPrefix(idpgroup.Name, "S - ")
			idpResponse, err = r.IDPClient.CreateGroup(idpgroup)
			if err != nil {
				log.Info("Failed to create IDP Group", "IDPGROUP", idpgroup.Name)
				return ctrl.Result{}, err
			}
			log.Info("Group creation status", "STATUS", idpResponse)
		}
		if err != nil {
			log.Info("Unforseen error occured", "ERROR", err)
			return ctrl.Result{}, err
		}
	}
	for _, idpgroup := range idpThirdPartyGroups.IDPGroups {
		idpgroup.Name = "S - " + idpgroup.Name
		idpGroupsResponse, err := r.IDPClient.GetGroup(idpgroup)
		if len(idpGroupsResponse) == 0 { // implement a idpclient.IsNotFound(err) method
			log.Info("IDP Group not found in TDI IDP", "Group", idpgroup.Name)
			idpResponse := []idpclient.Response{}
			idpgroup.Name = strings.TrimPrefix(idpgroup.Name, "S - ")
			idpResponse, err = r.IDPClient.CreateGroup(idpgroup)
			if err != nil {
				log.Info("Failed to create IDP Group", "IDPGROUP", idpgroup.Name)
				return ctrl.Result{}, err
			}
			log.Info("Group creation status", "STATUS", idpResponse)
		}
		if err != nil {
			log.Info("Unforseen error occured", "ERROR", err)
			return ctrl.Result{}, err
		}
	}

	// Assign values from K8s API to OIDC client for tenants and third parties
	for _, ownerName := range authProvider.Spec.Tenant.Owners {
		idpTenantOwners.IDPOwners = append(idpTenantOwners.IDPOwners, idpclient.User{
			Username: ownerName,
		})
	}
	for _, memberName := range authProvider.Spec.Tenant.Members {
		idpTenantMembers.IDPMembers = append(idpTenantMembers.IDPMembers, idpclient.User{
			Username: memberName.Name,
		})
		for _, memberGroup := range memberName.GroupNames {
			idpTenantMemberGroups.IDPGroups = append(idpTenantMemberGroups.IDPGroups, idpclient.Group{
				Name: memberGroup,
			})
		}
	}
	// Process third parties
	for _, thirdparty := range authProvider.Spec.ThirdParty {
		for _, ownerName := range thirdparty.Owners {
			idpThirdPartyOwners.IDPOwners = append(idpThirdPartyOwners.IDPOwners, idpclient.User{
				Username: ownerName,
			})
		}
		for _, memberName := range thirdparty.Members {
			idpThirdPartyMembers.IDPMembers = append(idpThirdPartyMembers.IDPMembers, idpclient.User{
				Username: memberName.Name,
			})
			for _, memberGroup := range memberName.GroupNames {
				idpThirdPartyMemberGroups.IDPGroups = append(idpThirdPartyMemberGroups.IDPGroups, idpclient.Group{
					Name: memberGroup,
				})
			}
		}
	}

	// For each group check Owners
	for _, idpgroup := range idpTenantGroups.IDPGroups {
		if idpgroup.Parent == "M - T_CaaS_Tenant" {
			idpgroup.Name = "S - " + idpgroup.Name
			// Get owners, extract usernames and check if there is a match
			idpOwnersResponse, err := r.IDPClient.GetGroupOwners(idpgroup, idpTenantOwners.IDPOwners)
			if err != nil {
				log.Info("Unforseen error occured", "ERROR", err)
				return ctrl.Result{}, err
			}
			idpOwnersUsernames := extractUsernames(idpOwnersResponse)
			matchOwner, delOwner := slicesMatch(authProvider.Spec.Tenant.Owners, idpOwnersUsernames)
			if !matchOwner {
				log.Info("AuthProvider group owners mismatch with TDI IDP", "Group", idpgroup.Name, "Owners", idpTenantOwners.IDPOwners)
				if delOwner {
					idpResponse, err := r.IDPClient.DeleteGroupOwners(idpgroup, idpTenantOwners.IDPOwners)
					if err != nil {
						log.Info("Failed to delete IDP Group owners", "IDPGROUPOWNERS", idpTenantOwners.IDPOwners)
						return ctrl.Result{}, err
					}
					log.Info("Owner deletion status", "STATUS", idpResponse)
				} else {
					idpResponse, err := r.IDPClient.CreateGroupOwners(idpgroup, idpTenantOwners.IDPOwners)
					if err != nil {
						log.Info("Failed to create IDP Group owners", "IDPGROUPOWNERS", idpTenantOwners.IDPOwners)
						return ctrl.Result{}, err
					}
					log.Info("Owner creation status", "STATUS", idpResponse)
				}
			}
		}
	}

	for _, idpMember := range idpTenantMembers.IDPMembers {
		for _, authProviderMember := range authProvider.Spec.Tenant.Members {
			if idpMember.Username == authProviderMember.Name {
				for _, idpMemberGroup := range idpTenantMemberGroups.IDPGroups {
					for _, authProviderMemberGroup := range authProviderMember.GroupNames {
						if idpMemberGroup.Name == authProviderMemberGroup {
							if strings.Contains(idpMemberGroup.Name, "m2m") {
								idpMemberGroup.Name = "S - " + idpMemberGroup.Name
								var idpFilteredTenantMembers idpclient.Members
								idpFilteredTenantMembers.IDPMembers = append(idpFilteredTenantMembers.IDPMembers, idpMember)
								// Get members, extract usernames and check if there is a match
								idpMembersResponse, err := r.IDPClient.GetGroupMembers(idpMemberGroup, idpFilteredTenantMembers.IDPMembers)
								if err != nil {
									log.Info("Unforseen error occured", "ERROR", err)
									return ctrl.Result{}, err
								}
								idpMembersUsernames := extractUsernames(idpMembersResponse)
								apiSlice := []string{}
								apiSlice = append(apiSlice, authProviderMember.Name)
								matchMember, delMember := slicesMatch(apiSlice, idpMembersUsernames)
								if !matchMember {
									log.Info("AuthProvider group members mismatch with TDI IDP", "Group", idpMemberGroup.Name, "Members", idpFilteredTenantMembers.IDPMembers)
									if delMember {
										idpResponse, err := r.IDPClient.DeleteGroupMembers(idpMemberGroup, idpFilteredTenantMembers.IDPMembers)
										if err != nil {
											log.Info("Failed to delete IDP Group members", "IDPGROUPMEMBERS", idpFilteredTenantMembers.IDPMembers)
											return ctrl.Result{}, err
										}
										log.Info("Member deletion status", "STATUS", idpResponse)
									} else {
										idpResponse, err := r.IDPClient.CreateGroupMembers(idpMemberGroup, idpFilteredTenantMembers.IDPMembers)
										if err != nil {
											log.Info("Failed to create IDP Group members", "IDPGROUPMEMBERS", idpFilteredTenantMembers.IDPMembers)
											return ctrl.Result{}, err
										}
										log.Info("Member creation status", "STATUS", idpResponse)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// For each group check Owners
	for _, idpgroup := range idpThirdPartyGroups.IDPGroups {
		if idpgroup.Parent == "M - T_CaaS_Third_Party" {
			idpgroup.Name = "S - " + idpgroup.Name
			// Get owners, extract usernames and check if there is a match
			idpOwnersResponse, err := r.IDPClient.GetGroupOwners(idpgroup, idpThirdPartyOwners.IDPOwners)
			if err != nil {
				log.Info("Unforseen error occured", "ERROR", err)
				return ctrl.Result{}, err
			}
			idpOwnersUsernames := extractUsernames(idpOwnersResponse)
			apiSlice := []string{}
			for _, thirdparty := range authProvider.Spec.ThirdParty {
				for _, owner := range thirdparty.Owners {
					apiSlice = append(apiSlice, owner)
				}
			}
			matchOwner, delOwner := slicesMatch(apiSlice, idpOwnersUsernames)
			if !matchOwner {
				log.Info("AuthProvider group owners mismatch with TDI IDP", "Group", idpgroup.Name, "Owners", idpThirdPartyOwners.IDPOwners)
				if delOwner {
					idpResponse, err := r.IDPClient.DeleteGroupOwners(idpgroup, idpThirdPartyOwners.IDPOwners)
					if err != nil {
						log.Info("Failed to delete IDP Group owners", "IDPGROUPOWNERS", idpThirdPartyOwners.IDPOwners)
						return ctrl.Result{}, err
					}
					log.Info("Owner deletion status", "STATUS", idpResponse)
				} else {
					idpResponse, err := r.IDPClient.CreateGroupOwners(idpgroup, idpThirdPartyOwners.IDPOwners)
					if err != nil {
						log.Info("Failed to create IDP Group owners", "IDPGROUPOWNERS", idpThirdPartyOwners.IDPOwners)
						return ctrl.Result{}, err
					}
					log.Info("Owner creation status", "STATUS", idpResponse)
				}
			}
		}
	}

	// For each member group check Members (only assigned for m2m)
	for _, idpMember := range idpThirdPartyMembers.IDPMembers {
		for _, thirdparty := range authProvider.Spec.ThirdParty {
			for _, authProviderMember := range thirdparty.Members {
				if idpMember.Username == authProviderMember.Name {
					for _, idpMemberGroup := range idpThirdPartyMemberGroups.IDPGroups {
						for _, authProviderMemberGroup := range authProviderMember.GroupNames {
							if idpMemberGroup.Name == authProviderMemberGroup {
								if strings.Contains(idpMemberGroup.Name, "m2m") {
									idpMemberGroup.Name = "S - " + idpMemberGroup.Name
									var idpFilteredThirdPartyMembers idpclient.Members
									idpFilteredThirdPartyMembers.IDPMembers = append(idpFilteredThirdPartyMembers.IDPMembers, idpMember)
									// Get members, extract usernames and check if there is a match
									idpMembersResponse, err := r.IDPClient.GetGroupMembers(idpMemberGroup, idpFilteredThirdPartyMembers.IDPMembers)
									if err != nil {
										log.Info("Unforseen error occured", "ERROR", err)
										return ctrl.Result{}, err
									}
									idpMembersUsernames := extractUsernames(idpMembersResponse)
									apiSlice := []string{}
									apiSlice = append(apiSlice, authProviderMember.Name)
									matchMember, delMember := slicesMatch(apiSlice, idpMembersUsernames)
									if !matchMember {
										log.Info("AuthProvider group members mismatch with TDI IDP", "Group", idpMemberGroup.Name, "Members", idpFilteredThirdPartyMembers.IDPMembers)
										if delMember {
											idpResponse, err := r.IDPClient.DeleteGroupMembers(idpMemberGroup, idpFilteredThirdPartyMembers.IDPMembers)
											if err != nil {
												log.Info("Failed to delete IDP Group members", "IDPGROUPMEMBERS", idpFilteredThirdPartyMembers.IDPMembers)
												return ctrl.Result{}, err
											}
											log.Info("Member deletion status", "STATUS", idpResponse)
										} else {
											idpResponse, err := r.IDPClient.CreateGroupMembers(idpMemberGroup, idpFilteredThirdPartyMembers.IDPMembers)
											if err != nil {
												log.Info("Failed to create IDP Group members", "IDPGROUPMEMBERS", idpFilteredThirdPartyMembers.IDPMembers)
												return ctrl.Result{}, err
											}
											log.Info("Member creation status", "STATUS", idpResponse)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authenticationv1alpha1.AuthProvider{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
