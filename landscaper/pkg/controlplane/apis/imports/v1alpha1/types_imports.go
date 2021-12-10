// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	"encoding/json"

	landscaperv1alpha1 "github.com/gardener/landscaper/apis/core/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Imports defines the import for the Gardener landscaper control plane component.
type Imports struct {
	metav1.TypeMeta `json:",inline"`
	// Identity is the id that uniquely identifies this Gardener installation
	// If not set, uses the existing identity of the installation or generates a default identity ("landscape-").
	// +optional
	Identity *string `json:"identity"`
	// RuntimeCluster contains the kubeconfig for the cluster where the Gardener
	// control plane pods will run.
	// if you do NOT configure a "virtual Garden" installation, the API server of this cluster will
	// be aggregated by the Gardener Extension API server and in turn serves the Gardener API.
	// Using the "virtual Garden" installation, this cluster is solely used to run the Gardener control plane pods
	// as well as the  Kubernetes API server pods of the "virtual Garden".
	RuntimeCluster landscaperv1alpha1.Target `json:"runtimeCluster"`
	// VirtualGarden contains configuration for the "Virtual Garden" setup option of Gardener
	// +optional
	VirtualGarden *VirtualGarden `json:"virtualGarden,omitempty"`
	// InternalDomain contains the internal domain configuration for the Gardener installation
	InternalDomain DNS `json:"internalDomain"`
	// DefaultDomains contains optional default domain configurations to use for the Shoot clusters of the Gardener installation
	// +optional
	DefaultDomains []DNS `json:"defaultDomains,omitempty"`
	// Alerting optionally configures the Gardener installation with alerting
	// +optional
	Alerting []Alerting `json:"alerting,omitempty"`
	// OpenVPNDiffieHellmanKey is the Diffie-Hellman key used for OpenVPN.
	// The VPN bridge from a Shoot's control plane running in the Seed cluster to the worker nodes of the Shoots is based
	// on OpenVPN. It requires a Diffie Hellman key.
	// If no such key is explicitly provided as secret in the garden namespace
	// then the Gardener will use a default one (not recommended, but useful for local development).
	// If a secret is specified its key will be used for all Shoots.
	// Can be generated by `openssl dhparam -out dh2048.pem 2048`
	// +optional
	OpenVPNDiffieHellmanKey *string `json:"openVPNDiffieHellmanKey,omitempty"`
	// GardenerAPIServer contains the configuration for the Gardener API Server
	GardenerAPIServer GardenerAPIServer `json:"gardenerAPIServer"`
	// GardenerControllerManager contains the configuration for the Gardener Controller Manager
	// +optional
	GardenerControllerManager *GardenerControllerManager `json:"gardenerControllerManager,omitempty"`
	// GardenerScheduler contains the configuration for the Gardener Scheduler
	// +optional
	GardenerScheduler *GardenerScheduler `json:"gardenerScheduler,omitempty"`
	// GardenerAdmissionController contains the configuration for the Gardener Admission Controller
	// +optional
	GardenerAdmissionController *GardenerAdmissionController `json:"gardenerAdmissionController,omitempty"`
	// Rbac configures common RBAC configuration
	// +optional
	Rbac *Rbac `json:"rbac,omitempty"`
	// CertificateRotation determines whether to regenerate the certificates that are missing in the import configuration
	// per default, missing configurations are taking from an existing Gardener installation
	CertificateRotation *CertificateRotation `json:"certificateRotation,omitempty"`
}

// VirtualGarden contains configuration for the "Virtual Garden" setup option of Gardener
type VirtualGarden struct {
	// Enabled configures whether to setup Gardener with the "Virtual Garden" setup option of Gardener
	// Please note that as a prerequisite, the API server pods of the "Virtual Garden" already need to be deployed to
	// the runtime cluster (this should be done automatically by a preceding component when using the standard installation via the landscaper)
	// and must be able to communicate with the Gardener Extension API server pod that will
	// be deployed to the Garden namespace
	Enabled bool `json:"enabled"`
	// Kubeconfig is the landscaper target containing the kubeconfig to an existing "Virtual Garden" API server
	// deployed in the runtime cluster.
	// This is the kubeconfig of the Cluster
	//  - that will be aggregated by the Gardener Extension API server with Gardener resource groups
	//  - where the Gardener configuration is created (garden namespace, default & internal domain secrets, Gardener webhooks)
	//  - essentially, this helm chart will be applied: charts/gardener/controlplane/charts/application
	//
	// The Gardener control plane (Gardener Controller Manager, Gardener Scheduler, ...)
	// will in turn run in the runtime cluster, but use kubeconfigs with credentials to this API server.
	// +optional
	Kubeconfig *landscaperv1alpha1.Target `json:"kubeconfig,omitempty"`
	// ClusterIP is an arbitrary private ipV4 IP that is used to enable the virtual Garden API server
	// running as a pod in the runtime cluster to talk to the Gardener Extension API server pod also running
	// as a pod in the runtime cluster
	// This IP
	//  - In the Virtual Garden cluster: is written into the endpoints resource of the "gardener-apiserver" service.
	//    This service is used by the APIService resources to register Gardener resource groups.
	//  - In the runtime cluster: is the ClusterIP of the "gardener-apiserver" service selecting the Gardener Extension
	//    API server pods.
	//
	// Exposed to accommodate existing Gardener installation
	// defaults to 10.0.1.0
	// +optional
	ClusterIP *string `json:"clusterIP,omitempty"`
}

// DNS contains the configuration for Domains used by the gardener installation
// for more information, please see:
// https://github.com/gardener/gardener/blob/master/docs/extensions/dns.md
type DNS struct {
	// Domain is the DNS domain
	Domain string `json:"domain"`
	// Provider is the DNS provider name of the given domain's zone
	// depends on the DNS extension of your choice
	// For instance, when using Gardener External-dns-management as the DNS extension, you can find
	// all the supported providers in the controller registration
	// at https://github.com/gardener/external-dns-management/blob/master/examples/controller-registration.yaml
	Provider string `json:"provider"`
	// Zone is the applicable cloud provider zone
	// +optional
	Zone *string `json:"zone,omitempty"`
	// Credentials contains the credentials for the dns provider
	// Expected format of the credentials depends on the the provider
	Credentials json.RawMessage `json:"credentials"`
}

// Alerting configures the Gardener installation with alerting
// please see the docs for more details:
// https://github.com/gardener/gardener/blob/master/docs/monitoring/alerting.md#alerting-for-operators
type Alerting struct {
	// AuthType is the authentication type to use
	// allowed values: smtp, none, basic, certificate
	AuthType string `json:"authType,omitempty"`
	// Url is the URL to post alerts to
	// only required for authentication types none, basic and certificate
	// +optional
	Url *string `json:"url,omitempty"`

	// SMTP Auth
	// ToEmailAddress is the email address to send alerts to
	// +optional
	ToEmailAddress *string `json:"toEmailAddress,omitempty"`
	// FromEmailAddress is the email address to send alerts from
	// +optional
	FromEmailAddress *string `json:"fromEmailAddress,omitempty"`
	// Smarthost is the smtp host used for sending
	// +optional
	Smarthost *string `json:"smarthost,omitempty"`
	// AuthUsername is the username used for authentication when using SMTP
	// +optional
	AuthUsername *string `json:"authUsername,omitempty"`
	// AuthUsername is the identity used for authentication when using SMTP
	// +optional
	AuthIdentity *string `json:"authIdentity,omitempty"`
	// AuthUsername is the password used for authentication when using SMTP
	// +optional
	AuthPassword *string `json:"authPassword,omitempty"`

	// Basic Auth
	// Username is the username to use for basic authentication with the external (non-Gardener managed) alert manager
	// +optional
	Username *string `json:"username,omitempty"`
	// Password is the password to use for basic authentication with the external (non-Gardener managed) alert manager
	// +optional
	Password *string `json:"password,omitempty"`

	// Certificate Auth
	// CaCert is the CA certificate the TLS certificate presented at the url endpoint
	// of the external (non-Gardener managed) alert manager needs to be signed with
	// +optional
	CaCert *string `json:"caCert,omitempty"`
	// TlsCert is the TLS certificate to use for authentication with the external (non-Gardener managed) alert manager
	// +optional
	TlsCert *string `json:"tlsCert,omitempty"`
	// TlsCert is the TLS key to use for authentication with the external (non-Gardener managed) alert manager
	// +optional
	TlsKey *string `json:"tlsKey,omitempty"`
}

// Rbac configures common RBAC configuration
type Rbac struct {
	// SeedAuthorizer configures RBAC for the SeedAuthorizer
	// +optional
	SeedAuthorizer *SeedAuthorizer `json:"seedAuthorizer,omitempty"`
}

// SeedAuthorizer configures RBAC for the SeedAuthorizer
type SeedAuthorizer struct {
	// Enabled configures whether the Seed Authorizer is enabled
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
}

// CertificateRotation contains settings related to certificate rotation
// Also, see here: https://github.com/gardener/gardener/issues/4856
type CertificateRotation struct {
	// Rotate defines that all certificates (except from the etcd certificates) should be rotated
	// This includes the CA of the Gardener API Server, the CA of the Gardener Admission Controller as well as all the TLS serving certificates of the Gardener Control Plane.
	// Please note: certificates are automatically rotated after 80% of their lifetime.
	// This is just a manual flag to force regeneration.
	Rotate bool `json:"rotate,omitempty"`
}
