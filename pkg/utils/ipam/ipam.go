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
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gardener/gardener/pkg/apis/core/v1alpha1"
	"github.com/gardener/gardener/pkg/operation/common"
	"github.com/gardener/gardener/pkg/utils/infodata"
	"github.com/gardener/gardener/pkg/utils/secrets"
)

// Acquire the next free IP address in the configured CIDR range respecting already reserved, but not used IPs
func (ipam *ipamManager) acquireIP() (net.IP, error) {
	addressesInUse := make(map[string]bool)
	// Get all IPs currently in use, duplicates not allowed
	for _, p := range ipam.providers {
		err := addAddresses(&addressesInUse, p, ipam.networkRange, true)
		if err != nil {
			return nil, err
		}
	}
	// Get all current IP reservations, duplicates allowed for a restricted amount of time as reservations should expire after some time and be actually used
	for _, r := range ipam.reservations {
		err := addAddresses(&addressesInUse, r, ipam.networkRange, false)
		if err != nil {
			return nil, err
		}
	}
	// Walk the CIDR range until a free IP is found
	for ip := nextIP(duplicateIP(ipam.networkRange.IP)); ipam.networkRange.Contains(ip); ip = nextIP(ip) {
		if _, found := addressesInUse[ip.String()]; found {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("No IP available in range %s", ipam.networkRange.String())
}

func duplicateIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)
	return result
}

// Add the IP addresses of the given address provider to the address map, report duplicates in case they are not allowed
func addAddresses(addressMap *map[string]bool, provider AddressProvider, cidr *net.IPNet, reportDuplicates bool) error {
	addresses, err := provider.Addresses()
	if err != nil {
		return err
	}
	addressesInUse := *addressMap
	for _, addr := range addresses {
		if reportDuplicates {
			if _, found := addressesInUse[addr]; found {
				return fmt.Errorf("Duplicate address %s found in range %s", addr, cidr.String())
			}
		}
		addressesInUse[addr] = true
	}
	return nil
}

// Return the next IP address, returning nil on overflow
func nextIP(ip net.IP) net.IP {
	length := len(ip)
	result := ip
	for i := length - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			return result
		}
		if i == length-1 {
			// Always ensure that the last segment is at least 1
			result[i]++
		}
	}
	// Overflow
	return nil
}

func newIpamManager(addressProviders []AddressProvider, reservationProviders []AddressProvider, cidr *net.IPNet) *ipamManager {
	return &ipamManager{
		providers:    addressProviders,
		reservations: reservationProviders,
		networkRange: cidr,
	}
}

func (rm *reservationManager) Addresses() ([]string, error) {
	result := []string{}
	for k := range rm.reservedAddresses {
		result = append(result, k)
	}
	return result, nil
}

// Acquires the next free IP address in the CIDR range ensuring mutual exclusion and temporary reservations
func (m *LockedIpamManager) AcquireIP() (string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	ip, err := m.ipam.acquireIP()
	if err != nil {
		return "", err
	}
	ipString := ip.String()
	m.reservations.reservedAddresses[ipString] = true
	time.AfterFunc(m.reservations.reservationDuration, func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		delete(m.reservations.reservedAddresses, ipString)
	})
	return ipString, nil
}

func NewLockedIpamManager(addressProviders []AddressProvider, cidr string, reservationDuration time.Duration) (*LockedIpamManager, error) {
	rm := &reservationManager{
		reservationDuration: reservationDuration,
		reservedAddresses:   make(map[string]bool),
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &LockedIpamManager{
		ipam:         newIpamManager(addressProviders, []AddressProvider{rm}, ipNet),
		mutex:        sync.Mutex{},
		reservations: rm,
	}, nil
}

func (p *WireguardSeedAddressProvider) Addresses() ([]string, error) {
	if p.Seed.Status.Wireguard.IP != nil {
		return []string{*p.Seed.Status.Wireguard.IP}, nil
	}
	return []string{}, nil
}

func (p *WireguardShootAddressProvider) Addresses() ([]string, error) {
	shootStates := &v1alpha1.ShootStateList{}
	if err := p.K8sGardenClient.Client().List(context.TODO(), shootStates); err != nil {
		fmt.Printf("Error getting shootstate: %s\n", err.Error())
		return nil, err
	}
	result := make([]string, 0)
	for _, shootstate := range shootStates.Items {
		infoData, err := infodata.GetInfoData(shootstate.Spec.Gardener, common.WireguardSecretName)
		if err != nil {
			return nil, err
		}
		if infoData == nil {
			continue
		}
		wireguardInfoData, ok := infoData.(*secrets.WireguardInfoData)
		if !ok {
			return nil, fmt.Errorf("could not convert GardenerResourceData entry %s to wireguardInfoData", common.WireguardSecretName)
		}
		if wireguardInfoData.SeedName == *p.SeedName {
			result = append(result, wireguardInfoData.LocalWireguardIP)
		}
	}
	return result, nil
}
