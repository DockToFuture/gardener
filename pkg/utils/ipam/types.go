/*
 * Copyright 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package ipam

import (
	"net"
	"sync"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
)

// Provides a list of IP addresses as an array
type AddressProvider interface {
	Addresses() ([]string, error)
}

type ipamManager struct {
	providers    []AddressProvider
	reservations []AddressProvider
	networkRange *net.IPNet
}

// Manages a map of address reservations, which are removed after a certain period of time
// Assumes external locking/mutual exclusion
type reservationManager struct {
	reservationDuration time.Duration
	reservedAddresses   map[string]bool
}

type LockedIpamManager struct {
	ipam         *ipamManager
	mutex        sync.Mutex
	reservations *reservationManager
}

type WireguardSeedAddressProvider struct {
	Seed *gardencorev1beta1.Seed
}

type WireguardShootAddressProvider struct {
	K8sGardenClient kubernetes.Interface
	SeedName        *string
}
