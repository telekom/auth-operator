package idpclient

import (
	"fmt"
	"net/http"
)

const (
	IDPGroupPrefix = "S - "
)

type Group struct {
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	Parent string `json:"parent,omitempty"`
}

type Groups struct {
	IDPGroups []Group `json:"groups"`
}

type User struct {
	Username      string `json:"userName,omitempty"`
	Fullname      string `json:"fullName,omitempty"`
	Email         string `json:"email,omitempty"`
	SSHKey        string `json:"sshKey,omitempty"`
	PGPKey        string `json:"pgpKey,omitempty"`
	Status        string `json:"status,omitempty"`
	LockoutStatus string `json:"lockoutStatus,omitempty"`
}

type Members struct {
	IDPMembers []User `json:"members"`
}

type MembersSlice struct {
	IDPMembers []string `json:"users"`
}

type Owners struct {
	IDPOwners []User `json:"owners"`
}

type OwnersSlice struct {
	IDPOwners []string `json:"users"`
}

type Response struct {
	Name    string `json:"name,omitempty"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

type Responses struct {
	Responses []Response `json:"responses,omitempty"`
}

// Group operations
func (c *IDPClient) GetGroup(group Group) ([]Group, error) {
	c.Log.V(3).Info("DEBUG: GetGroup called", "groupName", group.Name, "groupType", group.Type)

	c.sanitizeGroupName(&group)
	groups := Groups{}
	_, err := c.RequestResponse(http.MethodGet, fmt.Sprintf("/api/idm-portal/v2/group/%s", group.Name), nil, &groups)
	if err != nil {
		c.Log.Error(err, "ERROR: GetGroup failed", "groupName", group.Name)
		return groups.IDPGroups, err
	}
	c.Log.V(3).Info("DEBUG: GetGroup succeeded", "groupName", group.Name, "foundGroupCount", len(groups.IDPGroups))
	return groups.IDPGroups, err
}

// CreateGroup creates a group in the IDP.
// Group name is not sanitized here, as IDP expects group name without prefix.
func (c *IDPClient) CreateGroup(group Group) ([]Response, error) {
	c.Log.V(2).Info("DEBUG: CreateGroup called", "groupName", group.Name, "groupType", group.Type, "parent", group.Parent)

	response := Responses{}
	groups := Groups{
		IDPGroups: []Group{group},
	}
	_, err := c.RequestResponse(http.MethodPost, "/api/idm-portal/v2/group/", groups, &response)
	if err != nil {
		c.Log.Error(err, "ERROR: CreateGroup failed", "groupName", group.Name)
		return response.Responses, err
	}
	c.Log.V(2).Info("DEBUG: CreateGroup succeeded", "groupName", group.Name, "responseCount", len(response.Responses))
	return response.Responses, err
}

func (c *IDPClient) DeleteGroup(group Group) ([]Response, error) {
	c.Log.V(2).Info("DEBUG: DeleteGroup called", "groupName", group.Name, "groupType", group.Type)

	c.sanitizeGroupName(&group)
	response := Responses{}
	groups := Groups{
		IDPGroups: []Group{group},
	}
	_, err := c.RequestResponse(http.MethodDelete, "/api/idm-portal/v2/group/", groups, &response)
	if err != nil {
		c.Log.Error(err, "ERROR: DeleteGroup failed", "groupName", group.Name)
		return response.Responses, err
	}
	c.Log.V(2).Info("DEBUG: DeleteGroup succeeded", "groupName", group.Name, "responseCount", len(response.Responses))
	return response.Responses, err
}

// Group Owner operations
func (c *IDPClient) GetGroupOwners(group Group) ([]User, error) {
	c.Log.V(3).Info("DEBUG: GetGroupOwners called", "groupName", group.Name)

	c.sanitizeGroupName(&group)
	existingOwners := Owners{}
	_, err := c.RequestResponse(http.MethodGet, fmt.Sprintf("/api/idm-portal/v2/group/%s/owner", group.Name), nil, &existingOwners)
	if err != nil {
		c.Log.Error(err, "ERROR: GetGroupOwners failed", "groupName", group.Name)
		return existingOwners.IDPOwners, err
	}
	c.Log.V(3).Info("DEBUG: GetGroupOwners succeeded", "groupName", group.Name, "ownerCount", len(existingOwners.IDPOwners))
	return existingOwners.IDPOwners, err
}

func (c *IDPClient) CreateGroupOwners(group Group, owners []User) ([]Response, error) {
	c.Log.V(2).Info("DEBUG: CreateGroupOwners called", "groupName", group.Name, "ownerCount", len(owners))

	c.sanitizeGroupName(&group)
	response := Responses{}
	ownersSlice := OwnersSlice{}
	for _, owner := range owners {
		ownersSlice.IDPOwners = append(ownersSlice.IDPOwners, owner.Username)
	}
	_, err := c.RequestResponse(http.MethodPost, fmt.Sprintf("/api/idm-portal/v2/group/%s/owner", group.Name), ownersSlice, &response)
	if err != nil {
		c.Log.Error(err, "ERROR: CreateGroupOwners failed", "groupName", group.Name, "ownerCount", len(owners))
		return response.Responses, err
	}
	c.Log.V(2).Info("DEBUG: CreateGroupOwners succeeded", "groupName", group.Name, "addedOwnerCount", len(owners))
	return response.Responses, err
}

func (c *IDPClient) DeleteGroupOwners(group Group, owners []User) ([]Response, error) {
	c.Log.V(2).Info("DEBUG: DeleteGroupOwners called", "groupName", group.Name, "ownerCount", len(owners))

	c.sanitizeGroupName(&group)
	response := Responses{}
	ownersSlice := OwnersSlice{}
	for _, owner := range owners {
		ownersSlice.IDPOwners = append(ownersSlice.IDPOwners, owner.Username)
	}
	_, err := c.RequestResponse(http.MethodDelete, fmt.Sprintf("/api/idm-portal/v2/group/%s/owner", group.Name), ownersSlice, &response)
	if err != nil {
		c.Log.Error(err, "ERROR: DeleteGroupOwners failed", "groupName", group.Name, "ownerCount", len(owners))
		return response.Responses, err
	}
	c.Log.V(2).Info("DEBUG: DeleteGroupOwners succeeded", "groupName", group.Name, "deletedOwnerCount", len(owners))
	return response.Responses, err
}

// Group Member operations
func (c *IDPClient) GetGroupMembers(group Group) ([]User, error) {
	c.Log.V(3).Info("DEBUG: GetGroupMembers called", "groupName", group.Name)

	c.sanitizeGroupName(&group)
	existingMembers := Members{}
	_, err := c.RequestResponse(http.MethodGet, fmt.Sprintf("/api/idm-portal/v2/group/%s/member", group.Name), nil, &existingMembers)
	if err != nil {
		c.Log.Error(err, "ERROR: GetGroupMembers failed", "groupName", group.Name)
		return existingMembers.IDPMembers, err
	}
	c.Log.V(3).Info("DEBUG: GetGroupMembers succeeded", "groupName", group.Name, "memberCount", len(existingMembers.IDPMembers))
	return existingMembers.IDPMembers, err
}

func (c *IDPClient) CreateGroupMembers(group Group, members []User) ([]Response, error) {
	c.Log.V(2).Info("DEBUG: CreateGroupMembers called", "groupName", group.Name, "memberCount", len(members))

	c.sanitizeGroupName(&group)
	response := Responses{}
	membersSlice := MembersSlice{}
	for _, member := range members {
		membersSlice.IDPMembers = append(membersSlice.IDPMembers, member.Username)
	}
	_, err := c.RequestResponse(http.MethodPost, fmt.Sprintf("/api/idm-portal/v2/group/%s/member", group.Name), membersSlice, &response)
	if err != nil {
		c.Log.Error(err, "ERROR: CreateGroupMembers failed", "groupName", group.Name, "memberCount", len(members))
		return response.Responses, err
	}
	c.Log.V(2).Info("DEBUG: CreateGroupMembers succeeded", "groupName", group.Name, "addedMemberCount", len(members))
	return response.Responses, err
}

func (c *IDPClient) DeleteGroupMembers(group Group, members []User) ([]Response, error) {
	c.Log.V(2).Info("DEBUG: DeleteGroupMembers called", "groupName", group.Name, "memberCount", len(members))

	c.sanitizeGroupName(&group)
	response := Responses{}
	membersSlice := MembersSlice{}
	for _, member := range members {
		membersSlice.IDPMembers = append(membersSlice.IDPMembers, member.Username)
	}
	_, err := c.RequestResponse(http.MethodDelete, fmt.Sprintf("/api/idm-portal/v2/group/%s/member", group.Name), membersSlice, &response)
	if err != nil {
		c.Log.Error(err, "ERROR: DeleteGroupMembers failed", "groupName", group.Name, "memberCount", len(members))
		return response.Responses, err
	}
	c.Log.V(2).Info("DEBUG: DeleteGroupMembers succeeded", "groupName", group.Name, "deletedMemberCount", len(members))
	return response.Responses, err
}

func (c *IDPClient) sanitizeGroupName(group *Group) {
	if group.Name[0:4] != IDPGroupPrefix {
		group.Name = IDPGroupPrefix + group.Name
	}
}
