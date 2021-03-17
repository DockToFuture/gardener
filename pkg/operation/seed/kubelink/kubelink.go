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

package kubelink

import (
	"context"
	"path/filepath"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
)

type kubelink struct {
	namespace    string
	chartApplier kubernetes.ChartApplier
	chartPath    string
	values       *KubelinkResources
}

type KubelinkResources struct {
	Resources *KubelinkValues `json:"kubelink-resources,omitempty"`
}

type KubelinkValues struct {
	NodeCIDR       string `json:"nodeCIDR,omitempty"`
	PodCIDR        string `json:"podCIDR,omitempty"`
	ClusterAddress string `json:"clusterAddress,omitempty"`
	PrivateKey     string `json:"privateKey,omitempty"`
	PublicKey      string `json:"publicKey,omitempty"`
}

// NewKubelink creates a new DeployWaiter for kubelink.
func NewKubelink(
	namespace string,
	chartApplier kubernetes.ChartApplier,
	chartsRootPath string,
	values *KubelinkResources,
) component.DeployWaiter {
	return &kubelink{
		namespace:    namespace,
		chartApplier: chartApplier,
		chartPath:    filepath.Join(chartsRootPath, kubelinkReleaseName),
		values:       values,
	}
}

func (k *kubelink) Deploy(ctx context.Context) error {
	applierOptions := kubernetes.CopyApplierOptions(kubernetes.DefaultMergeFuncs)
	applierOptions[appsv1.SchemeGroupVersion.WithKind("Deployment").GroupKind()] = kubernetes.DeploymentKeepReplicasMergeFunc
	return k.chartApplier.Apply(ctx, k.chartPath, k.namespace, kubelinkReleaseName, kubernetes.Values(k.values), applierOptions)
}

func (k *kubelink) Destroy(ctx context.Context) error {
	return k.chartApplier.Delete(
		ctx,
		k.chartPath,
		k.namespace,
		kubelinkReleaseName,
		kubernetes.TolerateErrorFunc(meta.IsNoMatchError),
	)
}

func (k *kubelink) Wait(ctx context.Context) error {
	return nil
}

func (k *kubelink) WaitCleanup(ctx context.Context) error {
	return nil
}
