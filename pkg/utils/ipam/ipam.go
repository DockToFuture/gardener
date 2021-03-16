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
func (ipam *IpamManager) AcquireIP() (net.IP, error) {
	addressesInUse := make(map[string]bool)
	// Get all IPs currently in use, duplicates not allowed
	for _, p := range ipam.Providers {
		err := AddAddresses(&addressesInUse, p, ipam.NetworkRange, true)
		if err != nil {
			return nil, err
		}
	}
	// Get all current IP reservations, duplicates allowed for a restricted amount of time as reservations should expire after some time and be actually used
	for _, r := range ipam.Reservations {
		err := AddAddresses(&addressesInUse, r, ipam.NetworkRange, false)
		if err != nil {
			return nil, err
		}
	}
	// Walk the CIDR range until a free IP is found
	for ip := NextIP(DuplicateIP(ipam.NetworkRange.IP)); ipam.NetworkRange.Contains(ip); ip = NextIP(ip) {
		if _, found := addressesInUse[ip.String()]; found {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("No IP available in range %s", ipam.NetworkRange.String())
}

func DuplicateIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)
	return result
}

// Add the IP addresses of the given address provider to the address map, report duplicates in case they are not allowed
func AddAddresses(addressMap *map[string]bool, provider AddressProvider, cidr *net.IPNet, reportDuplicates bool) error {
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
func NextIP(ip net.IP) net.IP {
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

func NewIpamManager(addressProviders []AddressProvider, reservationProviders []AddressProvider, cidr *net.IPNet) *IpamManager {
	return &IpamManager{
		Providers:    addressProviders,
		Reservations: reservationProviders,
		NetworkRange: cidr,
	}
}

func (rm *ReservationManager) Addresses() ([]string, error) {
	result := []string{}
	for k := range rm.ReservedAddresses {
		result = append(result, k)
	}
	return result, nil
}

// Acquires the next free IP address in the CIDR range ensuring mutual exclusion and temporary reservations
func (m *LockedIpamManager) AcquireIP() (string, error) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	ip, err := m.Ipam.AcquireIP()
	if err != nil {
		return "", err
	}
	ipString := ip.String()
	m.Reservations.ReservedAddresses[ipString] = true
	time.AfterFunc(m.Reservations.ReservationDuration, func() {
		m.Mutex.Lock()
		defer m.Mutex.Unlock()
		delete(m.Reservations.ReservedAddresses, ipString)
	})
	return ipString, nil
}

func NewLockedIpamManager(addressProviders []AddressProvider, cidr string, reservationDuration time.Duration) (*LockedIpamManager, error) {
	rm := &ReservationManager{
		ReservationDuration: reservationDuration,
		ReservedAddresses:   make(map[string]bool),
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &LockedIpamManager{
		Ipam:         NewIpamManager(addressProviders, []AddressProvider{rm}, ipNet),
		Mutex:        sync.Mutex{},
		Reservations: rm,
	}, nil
}

func (p *WireguardSeedAddressProvider) Addresses() ([]string, error) {
	if p.Seed.Status.WireguardIP != nil {
		return []string{*p.Seed.Status.WireguardIP}, nil
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
