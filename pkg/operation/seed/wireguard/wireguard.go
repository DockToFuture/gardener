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

package wireguard

import (
	"context"
	"path/filepath"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
)

type wireguard struct {
	namespace    string
	chartApplier kubernetes.ChartApplier
	chartPath    string
	values       *IntermediateValues
}

type IntermediateValues struct {
	Wireguard *WireguardValues `json:"wireguard,omitempty"`
}

type WireguardValues struct {
	Address    string `json:"address,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
}

// NewWireguard creates a new DeployWaiter for wireguard.
func NewWireguard(
	namespace string,
	chartApplier kubernetes.ChartApplier,
	chartsRootPath string,
	values *IntermediateValues,
) component.DeployWaiter {
	return &wireguard{
		namespace:    namespace,
		chartApplier: chartApplier,
		chartPath:    filepath.Join(chartsRootPath, wireguardReleaseName),
		values:       values,
	}
}

func (w *wireguard) Deploy(ctx context.Context) error {
	applierOptions := kubernetes.CopyApplierOptions(kubernetes.DefaultMergeFuncs)
	applierOptions[appsv1.SchemeGroupVersion.WithKind("Deployment").GroupKind()] = kubernetes.DeploymentKeepReplicasMergeFunc
	return w.chartApplier.Apply(ctx, w.chartPath, w.namespace, wireguardReleaseName, kubernetes.Values(w.values), applierOptions)
}

func (w *wireguard) Destroy(ctx context.Context) error {
	return w.chartApplier.Delete(
		ctx,
		w.chartPath,
		w.namespace,
		wireguardReleaseName,
		kubernetes.TolerateErrorFunc(meta.IsNoMatchError),
	)
}

func (w *wireguard) Wait(ctx context.Context) error {
	return nil
}

func (w *wireguard) WaitCleanup(ctx context.Context) error {
	return nil
}
