// Copyright 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package dependencywatchdog_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/component"
	. "github.com/gardener/gardener/pkg/component/nodemanagement/dependencywatchdog"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	fakesecretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager/fake"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
)

var _ = Describe("Access", func() {
	var (
		fakeClient client.Client
		sm         secretsmanager.Interface
		access     component.Deployer

		ctx       = context.TODO()
		namespace = "shoot--foo--bar"

		probeSecretName = "shoot-access-dependency-watchdog-probe"

		serverInCluster = "in-cluster"

		expectedProbeSecret           *corev1.Secret
		expectedManagedResource       *resourcesv1alpha1.ManagedResource
		expectedManagedResourceSecret *corev1.Secret

		roleYAML = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  creationTimestamp: null
  name: gardener.cloud:target:dependency-watchdog
  namespace: kube-node-lease
rules:
- apiGroups:
  - coordination.k8s.io
  resources:
  - leases
  verbs:
  - get
  - list
`

		roleBindingYAML = `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: null
  name: gardener.cloud:target:dependency-watchdog
  namespace: kube-node-lease
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: gardener.cloud:target:dependency-watchdog
subjects:
- kind: ServiceAccount
  name: dependency-watchdog-probe
  namespace: kube-system
`
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(kubernetes.SeedScheme).Build()
		sm = fakesecretsmanager.New(fakeClient, namespace)

		By("Create secrets managed outside of this package for whose secretsmanager.Get() will be called")
		Expect(fakeClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: namespace}})).To(Succeed())

		access = NewAccess(fakeClient, namespace, sm, AccessValues{
			ServerInCluster: serverInCluster,
		})

		expectedProbeSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            probeSecretName,
				Namespace:       namespace,
				ResourceVersion: "1",
				Annotations: map[string]string{
					"serviceaccount.resources.gardener.cloud/name":      "dependency-watchdog-probe",
					"serviceaccount.resources.gardener.cloud/namespace": "kube-system",
				},
				Labels: map[string]string{
					"resources.gardener.cloud/purpose": "token-requestor",
					"resources.gardener.cloud/class":   "shoot",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"kubeconfig": []byte(`apiVersion: v1
clusters:
- cluster:
    server: https://` + serverInCluster + `
  name: ` + namespace + `
contexts:
- context:
    cluster: ` + namespace + `
    user: ` + namespace + `
  name: ` + namespace + `
current-context: ` + namespace + `
kind: Config
preferences: {}
users:
- name: ` + namespace + `
  user: {}
`)},
		}

		expectedManagedResource = &resourcesv1alpha1.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "shoot-core-dependency-watchdog",
				Namespace:       namespace,
				Labels:          map[string]string{"origin": "gardener"},
				Annotations:     map[string]string{"reference.resources.gardener.cloud/secret-2c6a3fae": "managedresource-shoot-core-dependency-watchdog-967328e8"},
				ResourceVersion: "1",
			},
			Spec: resourcesv1alpha1.ManagedResourceSpec{
				SecretRefs: []corev1.LocalObjectReference{
					{
						Name: "managedresource-shoot-core-dependency-watchdog-967328e8",
					},
				},
				InjectLabels: map[string]string{"shoot.gardener.cloud/no-cleanup": "true"},
				KeepObjects:  pointer.Bool(false),
			},
		}
		expectedManagedResourceSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "managedresource-shoot-core-dependency-watchdog-967328e8",
				Namespace:       namespace,
				ResourceVersion: "1",
				Labels: map[string]string{
					"resources.gardener.cloud/garbage-collectable-reference": "true",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"role__kube-node-lease__gardener.cloud_target_dependency-watchdog.yaml":        []byte(roleYAML),
				"rolebinding__kube-node-lease__gardener.cloud_target_dependency-watchdog.yaml": []byte(roleBindingYAML),
			},
			Immutable: pointer.Bool(true),
		}
	})

	AfterEach(func() {
		Expect(fakeClient.Delete(ctx, expectedProbeSecret)).To(Or(Succeed(), BeNotFoundError()))
		Expect(fakeClient.Delete(ctx, expectedManagedResourceSecret)).To(Or(Succeed(), BeNotFoundError()))
		Expect(fakeClient.Delete(ctx, expectedManagedResource)).To(Or(Succeed(), BeNotFoundError()))
	})

	Describe("#Deploy", func() {
		It("should successfully deploy all resources", func() {
			Expect(access.Deploy(ctx)).To(Succeed())

			reconciledInternalProbeSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: probeSecretName, Namespace: namespace}}
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(reconciledInternalProbeSecret), reconciledInternalProbeSecret)).To(Succeed())
			Expect(reconciledInternalProbeSecret).To(DeepEqual(expectedProbeSecret))

			reconciledManagedResource := &resourcesv1alpha1.ManagedResource{ObjectMeta: metav1.ObjectMeta{Name: "shoot-core-dependency-watchdog", Namespace: namespace}}
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(reconciledManagedResource), reconciledManagedResource)).To(Succeed())
			Expect(reconciledManagedResource).To(DeepEqual(expectedManagedResource))

			reconciledManagedResourceSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "managedresource-shoot-core-dependency-watchdog-967328e8", Namespace: namespace}}
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(reconciledManagedResourceSecret), reconciledManagedResourceSecret)).To(Succeed())
			Expect(reconciledManagedResourceSecret).To(DeepEqual(expectedManagedResourceSecret))
		})
	})

	Describe("#Destroy", func() {
		It("should delete the secrets", func() {
			reconciledInternalProbeSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: probeSecretName, Namespace: namespace}}
			Expect(fakeClient.Create(ctx, reconciledInternalProbeSecret)).To(Succeed())
			reconciledManagedResource := &resourcesv1alpha1.ManagedResource{ObjectMeta: metav1.ObjectMeta{Name: "shoot-core-dependency-watchdog", Namespace: namespace}}
			Expect(fakeClient.Create(ctx, reconciledManagedResource)).To(Succeed())
			reconciledManagedResourceSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "managedresource-shoot-core-dependency-watchdog-967328e8", Namespace: namespace}}
			Expect(fakeClient.Create(ctx, reconciledManagedResourceSecret)).To(Succeed())

			Expect(access.Destroy(ctx)).To(Succeed())

			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(reconciledInternalProbeSecret), &corev1.Secret{})).To(BeNotFoundError())
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(reconciledManagedResource), &resourcesv1alpha1.ManagedResource{})).To(BeNotFoundError())
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(reconciledManagedResourceSecret), &resourcesv1alpha1.ManagedResource{})).To(BeNotFoundError())
		})
	})
})
