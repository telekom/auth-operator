package idpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-logr/logr"
)

type Client interface {
	RefreshAccessToken() error
	GetGroup(group Group) ([]Group, error)
	CreateGroup(group Group) ([]Response, error)
	DeleteGroup(group Group) ([]Response, error)
	GetGroupOwners(group Group) ([]User, error)
	CreateGroupOwners(group Group, owners []User) ([]Response, error)
	DeleteGroupOwners(group Group, owners []User) ([]Response, error)
	GetGroupMembers(group Group) ([]User, error)
	CreateGroupMembers(group Group, members []User) ([]Response, error)
	DeleteGroupMembers(group Group, members []User) ([]Response, error)
	SetLogger(logger logr.Logger)
}

type IDPClient struct {
	HTTPClient        *http.Client
	APIToken          string
	BearerToken       string
	IDPServiceURL     url.URL
	RefreshServiceURL url.URL
	Log               *logr.Logger
}

type Config struct {
	IDPURL     string
	APIToken   string
	Timeout    time.Duration
	HTTPClient *http.Client
}

type Options struct {
	TLSClientConfig *tls.Config
}

func NewIDPClient(config Config, options Options) (*IDPClient, error) {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: config.Timeout}
	}

	idpUrl := url.URL{
		Scheme: "https",
		Host:   config.IDPURL,
	}

	apiTokenRefreshUrl := url.URL{
		Scheme: "https",
		Host:   config.IDPURL,
		Path:   "/api/token-issuer/v1/apikey/refresh",
	}

	if options.TLSClientConfig != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: options.TLSClientConfig,
		}
	}

	client := &IDPClient{
		HTTPClient:        httpClient,
		IDPServiceURL:     idpUrl,
		APIToken:          config.APIToken,
		RefreshServiceURL: apiTokenRefreshUrl,
	}
	return client, nil
}

func (c *IDPClient) SetLogger(logger logr.Logger) {
	c.Log = &logger
}

func (c *IDPClient) RefreshAccessToken() error {
	request, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, c.RefreshServiceURL.String(), nil)
	if err != nil {
		c.Log.Info("Failed to create request for access token")
		return err
	}

	request.Header.Add("X-Pannet-API-Key", c.APIToken)
	request.Header.Add("Content-Type", "application/json") // or "accept" instead of content-type
	request.Header.Add("User-Agent", "auth.t-caas.telekom.com")

	c.Log.Info(fmt.Sprintf("Executing %s request on URL: %s", http.MethodPost, request.URL.String()))
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		c.Log.Info("Failed executing the request for access token")
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode > 300 {
		c.Log.Info("Got bad HTTP status code for URL", "HTTP_STATUS_CODE", response.StatusCode, "URL", response.Request.URL)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		c.Log.Info("Failed to read the response body")
		return err
	}

	var responseBody struct {
		Token   string `json:"token"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &responseBody); err != nil {
		c.Log.Info("Failed to unmarshal the response body")
		return err
	}

	c.BearerToken = responseBody.Token
	c.Log.Info("Successfully refreshed the access token!")
	return nil
}

func (c *IDPClient) RequestResponse(method string, path string, requestData interface{}, responseData interface{}) ([]byte, error) {
	c.IDPServiceURL.Path = path

	var requestDataJson []byte
	var err error

	if requestData != nil {
		requestDataJson, err = json.Marshal(requestData)
		if err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequestWithContext(context.TODO(), method, c.IDPServiceURL.String(), bytes.NewReader(requestDataJson))
	if err != nil {
		c.Log.Info("Failed to create request for IDP group manipulation")
		return nil, err
	}
	request.Header.Add("Authorization", "Bearer "+c.BearerToken)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("User-Agent", "auth.t-caas.telekom.com")

	c.Log.Info(fmt.Sprintf("Executing %s request on URL: %s", method, request.URL.String()))
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		c.Log.Info("Failed executing the request for IDP group manipulation")
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		c.Log.Info("Got bad HTTP status code for URL", "HTTP_STATUS_CODE", response.StatusCode, "URL", response.Request.URL)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		c.Log.Info("Failed to read the response body")
		return nil, err
	}

	if err := json.Unmarshal(body, &responseData); err != nil {
		c.Log.Info("Failed to unmarshal the response body", "ERROR", err)
		return nil, err
	}
	return body, nil
}
