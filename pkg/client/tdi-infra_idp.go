package idpclient

import (
	"fmt"
	"net/http"
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
	groups := Groups{}
	_, err := c.RequestResponse(http.MethodGet, fmt.Sprintf("/api/idm-portal/v2/group/%s", group.Name), nil, &groups)
	return groups.IDPGroups, err
}

func (c *IDPClient) CreateGroup(group Group) ([]Response, error) {
	response := Responses{}
	groups := Groups{
		IDPGroups: []Group{group},
	}
	_, err := c.RequestResponse(http.MethodPost, fmt.Sprintf("/api/idm-portal/v2/group/"), groups, &response)
	return response.Responses, err
}

func (c *IDPClient) DeleteGroup(group Group) ([]Response, error) {
	response := Responses{}
	groups := Groups{
		IDPGroups: []Group{group},
	}
	_, err := c.RequestResponse(http.MethodDelete, fmt.Sprintf("/api/idm-portal/v2/group/"), groups, &response)
	return response.Responses, err
}

// Group Owner operations
func (c *IDPClient) GetGroupOwners(group Group) ([]User, error) {
	existingOwners := Owners{}
	_, err := c.RequestResponse(http.MethodGet, fmt.Sprintf("/api/idm-portal/v2/group/%s/owner", group.Name), nil, &existingOwners)
	return existingOwners.IDPOwners, err
}

func (c *IDPClient) CreateGroupOwners(group Group, owners []User) ([]Response, error) {
	response := Responses{}
	ownersSlice := OwnersSlice{}
	for _, owner := range owners {
		ownersSlice.IDPOwners = append(ownersSlice.IDPOwners, owner.Username)
	}
	_, err := c.RequestResponse(http.MethodPost, fmt.Sprintf("/api/idm-portal/v2/group/%s/owner", group.Name), ownersSlice, &response)
	return response.Responses, err
}

func (c *IDPClient) DeleteGroupOwners(group Group, owners []User) ([]Response, error) {
	response := Responses{}
	ownersSlice := OwnersSlice{}
	for _, owner := range owners {
		ownersSlice.IDPOwners = append(ownersSlice.IDPOwners, owner.Username)
	}
	_, err := c.RequestResponse(http.MethodDelete, fmt.Sprintf("/api/idm-portal/v2/group/%s/owner", group.Name), ownersSlice, &response)
	return response.Responses, err
}

// Group Member operations
func (c *IDPClient) GetGroupMembers(group Group) ([]User, error) {
	existingMembers := Members{}
	_, err := c.RequestResponse(http.MethodGet, fmt.Sprintf("/api/idm-portal/v2/group/%s/member", group.Name), nil, &existingMembers)
	return existingMembers.IDPMembers, err
}

func (c *IDPClient) CreateGroupMembers(group Group, members []User) ([]Response, error) {
	response := Responses{}
	membersSlice := MembersSlice{}
	for _, member := range members {
		membersSlice.IDPMembers = append(membersSlice.IDPMembers, member.Username)
	}
	_, err := c.RequestResponse(http.MethodPost, fmt.Sprintf("/api/idm-portal/v2/group/%s/member", group.Name), membersSlice, &response)
	return response.Responses, err
}

func (c *IDPClient) DeleteGroupMembers(group Group, members []User) ([]Response, error) {
	response := Responses{}
	membersSlice := MembersSlice{}
	for _, member := range members {
		membersSlice.IDPMembers = append(membersSlice.IDPMembers, member.Username)
	}
	_, err := c.RequestResponse(http.MethodDelete, fmt.Sprintf("/api/idm-portal/v2/group/%s/member", group.Name), membersSlice, &response)
	return response.Responses, err
}
