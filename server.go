package main

import (
	"encoding/json"
	"fmt"
	// "io/ioutil"
	"net/http"
	"os"
	// "path"
	// "regexp"
	// "strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	// yaml "gopkg.in/yaml.v2"
	"github.com/Azure/go-autorest/autorest/date"
	azsecurity "github.com/Azure/azure-sdk-for-go/services/preview/security/mgmt/v3.0/security"
	azresourcegraph "github.com/Azure/azure-sdk-for-go/services/resourcegraph/mgmt/2019-04-01/resourcegraph"

	//acrmgmt "github.com/Azure/azure-sdk-for-go/services/preview/containerregistry/mgmt/2018-02-01/containerregistry"
	//acr "github.com/Azure/azure-sdk-for-go/services/preview/containerregistry/runtime/2019-08-15-preview/containerregistry"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"

	"github.com/pkg/errors"
)

// auth
const (
	// OAuthGrantTypeServicePrincipal for client credentials flow
	OAuthGrantTypeServicePrincipal OAuthGrantType = iota
	cloudName string = ""
)

// OAuthGrantType specifies which grant type to use.
type OAuthGrantType int

// AuthGrantType ...
func AuthGrantType() OAuthGrantType {
	return OAuthGrantTypeServicePrincipal
}

// Server 
type Server struct {
	// subscriptionId to azure
	SubscriptionID string
	// tenantID in AAD
	TenantID string
	// AAD app client secret (if not using POD AAD Identity)
	AADClientSecret string
	// AAD app client secret id (if not using POD AAD Identity)
	AADClientID string
	// Location of security center
	Location string
	// Scope of assessment
	Scope string
}

// Response
type Response struct {
	// ID - Vulnerability ID
	ID *string `json:"id,omitempty"`
	// DisplayName - User friendly display name of the sub-assessment
	DisplayName *string `json:"displayName,omitempty"`
	Status      *azsecurity.SubAssessmentStatus `json:"status,omitempty"`
	// Remediation - Information on how to remediate this sub-assessment
	Remediation *string `json:"remediation,omitempty"`
	// Impact - Description of the impact of this sub-assessment
	Impact *string `json:"impact,omitempty"`
	// Category - Category of the sub-assessment
	Category *string `json:"category,omitempty"`
	// Description - Human readable description of the assessment status
	Description *string `json:"description,omitempty"`
	// TimeGenerated - The date and time the sub-assessment was generated
	TimeGenerated   *date.Time           `json:"timeGenerated,omitempty"`
	ResourceDetails azsecurity.AzureResourceDetails `json:"resourceDetails,omitempty"`
	AdditionalData  ResponseContainerRegistryVulnerabilityProperties  `json:"additionalData,omitempty"`
}

// ResponseContainerRegistryVulnerabilityProperties additional context fields for container registry Vulnerability
// assessment
type ResponseContainerRegistryVulnerabilityProperties struct {
	// Type - READ-ONLY; Vulnerability Type. e.g: Vulnerability, Potential Vulnerability, Information Gathered, Vulnerability
	Type *string `json:"type,omitempty"`
	// Cvss - READ-ONLY; Dictionary from cvss version to cvss details object
	Cvss map[string]*azsecurity.CVSS `json:"cvss"`
	// Patchable - READ-ONLY; Indicates whether a patch is available or not
	Patchable *bool `json:"patchable,omitempty"`
	// Cve - READ-ONLY; List of CVEs
	Cve *[]azsecurity.CVE `json:"cve,omitempty"`
	// PublishedTime - READ-ONLY; Published time
	PublishedTime *date.Time `json:"publishedTime,omitempty"`
	// VendorReferences - READ-ONLY
	VendorReferences *[]azsecurity.VendorReference `json:"vendorReferences,omitempty"`
	// RepositoryName - READ-ONLY; Name of the repository which the vulnerable image belongs to
	RepositoryName *string `json:"repositoryName,omitempty"`
	// ImageDigest - READ-ONLY; Digest of the vulnerable image
	ImageDigest *string `json:"imageDigest,omitempty"`
	// AssessedResourceType - Possible values include: 'AssessedResourceTypeAdditionalData', 'AssessedResourceTypeSQLServerVulnerability', 'AssessedResourceTypeContainerRegistryVulnerability', 'AssessedResourceTypeServerVulnerabilityAssessment'
	AssessedResourceType azsecurity.AssessedResourceType `json:"assessedResourceType,omitempty"`
}

// NewServer creates a new server instance.
func NewServer() (*Server, error) {
	log.Debugf("NewServer")
	var s Server
	s.SubscriptionID = os.Getenv("SUBSCRIPTION_ID")
	s.AADClientID = os.Getenv("CLIENT_ID")
	s.AADClientSecret = os.Getenv("CLIENT_SECRET")
	s.TenantID = os.Getenv("TENANT_ID")

	if s.SubscriptionID == "" {
		return nil, fmt.Errorf("could not find SUBSCRIPTION_ID")
	}
	if s.AADClientID == "" {
		return nil, fmt.Errorf("could not find CLIENT_ID")
	}
	if s.AADClientSecret == "" {
		return nil, fmt.Errorf("could not find CLIENT_SECRET")
	}
	if s.TenantID == "" {
		return nil, fmt.Errorf("could not find TENANT_ID")
	}

	return &s, nil
}

// ParseAzureEnvironment returns azure environment by name
func ParseAzureEnvironment(cloudName string) (*azure.Environment, error) {
	var env azure.Environment
	var err error
	if cloudName == "" {
		env = azure.PublicCloud
	} else {
		env, err = azure.EnvironmentFromName(cloudName)
	}
	return &env, err
}

// GetManagementToken retrieves a new service principal token
func (s *Server) GetManagementToken(grantType OAuthGrantType, cloudName string) (authorizer autorest.Authorizer, err error) {

	env, err := ParseAzureEnvironment(cloudName)
	if err != nil {
		return nil, err
	}

	rmEndPoint := env.ResourceManagerEndpoint
	servicePrincipalToken, err := s.GetServicePrincipalToken(env, rmEndPoint)
	if err != nil {
		return nil, err
	}
	authorizer = autorest.NewBearerAuthorizer(servicePrincipalToken)
	return authorizer, nil
}

// GetServicePrincipalToken creates a new service principal token based on the configuration
func (s *Server) GetServicePrincipalToken(env *azure.Environment, resource string) (*adal.ServicePrincipalToken, error) {
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, s.TenantID)
	if err != nil {
		return nil, fmt.Errorf("creating the OAuth config: %v", err)
	}

	if len(s.AADClientSecret) > 0 {
		log.Infof("azure: using client_id+client_secret to retrieve access token")
		return adal.NewServicePrincipalToken(
			*oauthConfig,
			s.AADClientID,
			s.AADClientSecret,
			resource)
	}
	return nil, fmt.Errorf("No credentials provided for AAD application %s", s.AADClientID)
}

// ProcessAssessmentImageDigest uses resource group to get all vulnerable image digests
//func (s *Server) ProcessAssessmentImageDigest(ctx context.Context, req *http.Request) (resps []Response, err error) {
func (s *Server) Process(ctx context.Context, req *http.Request) (resps []Response, err error) {
	image := req.URL.Query().Get("image") // e.g. : oss/kubernetes/aks/etcd-operator
  	if image == "" {
		return nil, fmt.Errorf("Failed to provide image to query")
	}
	myClient := azresourcegraph.New()
	token, tokenErr := s.GetManagementToken(AuthGrantType(), cloudName)
	if tokenErr != nil {
		return nil, errors.Wrapf(tokenErr, "failed to get management token")
	}
	myClient.Authorizer = token
	subs := []string{s.SubscriptionID}
	rawQuery := `
	securityresources | where type == "microsoft.security/assessments/subassessments" 
	| extend resourceType = tostring(properties["additionalData"].assessedResourceType) 
	| extend status = tostring(properties["status"].code)
	| where resourceType == "ContainerRegistryVulnerability" 
	| extend repoName = tostring(properties["additionalData"].repositoryName) 
	| where status == "Unhealthy"
	| where repoName == "` + image + `"`

	options := azresourcegraph.QueryRequestOptions {
		ResultFormat: azresourcegraph.ResultFormatObjectArray,
	}
	query := azresourcegraph.QueryRequest{
		Subscriptions: &subs,
		Query: &rawQuery,
		Options: &options,
	}
	results, err := myClient.Resources(ctx, query)
	if err != nil {
		return nil, err
	}
	var data []azsecurity.SubAssessment
	count := *results.Count
	resps = make([]Response, 0)
	if count > 0 {
		raw, err := json.Marshal(results.Data)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(raw, &data)
		if err != nil {
			return nil, err
		}
		
		for _, v := range data {
			rd, _ := v.SubAssessmentProperties.ResourceDetails.AsAzureResourceDetails()
			ad, _ := v.SubAssessmentProperties.AdditionalData.AsContainerRegistryVulnerabilityProperties()
			resp := Response{
				ID: v.ID,
				DisplayName: v.DisplayName,
				Status: v.Status,
				Remediation: v.Remediation,
				Impact: v.Impact,
				Category: v.Category,
				Description: v.Description,
				TimeGenerated: v.TimeGenerated,
				ResourceDetails: *rd,
				AdditionalData: ResponseContainerRegistryVulnerabilityProperties{
					AssessedResourceType: ad.AssessedResourceType,
					RepositoryName: ad.RepositoryName,
					Type: ad.Type,
					Cvss: ad.Cvss,
					Patchable: ad.Patchable,
					Cve: ad.Cve,
					PublishedTime: ad.PublishedTime,
					VendorReferences: ad.VendorReferences,
					ImageDigest: ad.ImageDigest,
				},
			}
			//log.Debugf("resp: %s", *resp.AdditionalData.RepositoryName)
			resps = append(resps, resp)
			// prop, _ := v.SubAssessmentProperties.AdditionalData.AsContainerRegistryVulnerabilityProperties()
		
			// //message = message + fmt.Sprintf("name: %s | repo: %s \n", *v.DisplayName, *prop.RepositoryName)
			//log.Debugf("name: %s | repo: %s ", *v.DisplayName, *prop.RepositoryName)

		}
	}

	log.Debugf("total unhealthy images: %d", count)

	return resps, nil
}

// ProcessAssessmentAPIs uses assessment apis to return all vulnerable image digests
func (s *Server) ProcessAssessmentAPIs(ctx context.Context) (msg *string, err error) {
	assessmentName := "dbd0cb49-b563-45e7-9724-889e799fa648"
	
	myClient := azsecurity.NewSubAssessmentsClient(s.SubscriptionID, s.Location)
	token, tokenErr := s.GetManagementToken(AuthGrantType(), cloudName)
	if tokenErr != nil {
		return nil, errors.Wrapf(tokenErr, "failed to get management token")
	}
	myClient.Authorizer = token
	results, err := myClient.List(ctx, s.Scope, assessmentName)
	if err != nil {
		return nil, err
	}
	count := 0
	message := ""
	for _, v := range results.Values() {
		//log.Debugf("result: %s", *v.Name)
		subAssess, err := myClient.Get(ctx, s.Scope, assessmentName, *v.Name)
		if err != nil {
			return nil, err
		}
		if subAssess.Status.Code == azsecurity.SubAssessmentStatusCodeUnhealthy {
			prop, exist := subAssess.SubAssessmentProperties.AdditionalData.AsContainerRegistryVulnerabilityProperties()
			if exist {
				message = message + fmt.Sprintf("name: %s | repo: %s \n", *subAssess.DisplayName, *prop.RepositoryName)
				log.Debugf("name: %s | repo: %s ", *subAssess.DisplayName, *prop.RepositoryName)
				count++
			}
		}
	}

	log.Debugf("total unhealthy images: %d", count)

	return &message, nil
}

func wrapObjectTypeError(err error, objectType string, objectName string, objectVersion string) error {
	return errors.Wrapf(err, "failed to get objectType:%s, objectName:%s, objectVersion:%s", objectType, objectName, objectVersion)
}
