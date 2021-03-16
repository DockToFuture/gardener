// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package secrets

import (
	"fmt"

	"github.com/gardener/gardener/pkg/logger"
	"github.com/gardener/gardener/pkg/utils/infodata"
	wg "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (

	// DataKeyLocalWireguardIP is the key in a secret data holding the local wireguard IP.
	DataKeyLocalWireguardIP = "localWireguardIP"
	// DataKeyRemoteWireguardIP is the key in a secret data holding the remote wireguard IP.
	DataKeyRemoteWireguardIP = "remoteWireguardIP"
	// DataKeyPeerPublicKey is the key in a secret data holding the peer public key.
	DataKeyPeerPublicKey = "peerPublicKey"
	// DataKeyWireguardPrivateKey is the key in a secret data holding the private key.
	DataKeyWireguardPrivateKey = "privateKey"
	// DataKeyWireguardPublicKey is the key in a secret data holding the public key.
	DataKeyWireguardPublicKey = "publicKey"
	// DataKeyPeerPresharedKey is the key in a secret data holding the peer preshared key.
	DataKeyPeerPresharedKey = "peerPresharedKey"
	// DataKeyRemoteEndpoint is the key in a secret data holding the remote endpoint.
	DataKeyRemoteEndpoint = "remoteEndpoint"
	// DataKeySeedName is the key in a secret data holding the seed name.
	DataKeySeedName = "seedName"
)

// WireguardSecretConfig contains the specification for a to-be-generated wireguard secret.
type WireguardSecretConfig struct {
	Name              string
	RemoteWireguardIP string
	PeerPublicKey     string
	RemoteEndpoint    string
	SeedName          string
	GetIP             func() (*string, error)
}

// Wireguard contains the keys for serializing the wireguard credentials
type Wireguard struct {
	Name              string
	LocalWireguardIP  string
	RemoteWireguardIP string
	PeerPresharedKey  string
	PrivateKey        string
	PublicKey         string
	PeerPublicKey     string
	RemoteEndpoint    string
	SeedName          string
}

// GetName returns the name of the secret.
func (w *WireguardSecretConfig) GetName() string {
	return w.Name
}

// Generate implements ConfigInterface.
func (w *WireguardSecretConfig) Generate() (DataInterface, error) {
	return w.GenerateWireguard()
}

// GenerateInfoData implements ConfigInterface.
func (w *WireguardSecretConfig) GenerateInfoData() (infodata.InfoData, error) {
	shootPrivateKey, err := wg.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	shootPublicKey := shootPrivateKey.PublicKey()
	peerPresharedKey, err := wg.GenerateKey()
	if err != nil {
		return nil, err
	}
	localWireguardIP, err := w.GetIP()
	if err != nil {
		return nil, err
	}
	logger.Logger.Errorf("-------------------GenerateInfoData--------------peerPresharedKEy%s,shootprivatek%s,shootpublickey%s", peerPresharedKey.String(), shootPrivateKey.String(), shootPublicKey.String())
	return NewWireguardInfoData(*localWireguardIP, w.RemoteWireguardIP, peerPresharedKey.String(), shootPrivateKey.String(), shootPublicKey.String(), w.PeerPublicKey, w.RemoteEndpoint, w.SeedName), nil
}

// GenerateFromInfoData implements ConfigInteface
func (w *WireguardSecretConfig) GenerateFromInfoData(infoData infodata.InfoData) (DataInterface, error) {
	data, ok := infoData.(*WireguardInfoData)
	if !ok {
		return nil, fmt.Errorf("could not convert InfoData entry %s to WireguardInfoData", w.Name)
	}

	peerPresharedKey := data.PeerPresharedKey
	shootPrivateKey := data.ShootPrivateKey
	shootPublicKey := data.ShootPublicKey
	localWireguardIP := data.LocalWireguardIP

	return w.generateWithKeys(localWireguardIP, peerPresharedKey, shootPrivateKey, shootPublicKey)
}

// LoadFromSecretData implements infodata.Loader
func (w *WireguardSecretConfig) LoadFromSecretData(secretData map[string][]byte) (infodata.InfoData, error) {

	localWireguardIP := string(secretData[DataKeyLocalWireguardIP])
	remoteWireguardIP := string(secretData[DataKeyRemoteWireguardIP])
	peerPresharedKey := string(secretData[DataKeyPeerPresharedKey])
	shootPrivateKey := string(secretData[DataKeyWireguardPrivateKey])
	shootPublicKey := string(secretData[DataKeyWireguardPublicKey])
	peerPublicKey := string(secretData[DataKeyPeerPublicKey])
	remoteEndpoint := string(secretData[DataKeyRemoteEndpoint])
	seedName := string(secretData[DataKeySeedName])

	return NewWireguardInfoData(localWireguardIP, remoteWireguardIP, peerPresharedKey, shootPrivateKey, shootPublicKey, peerPublicKey, remoteEndpoint, seedName), nil
}

// GenerateWireguard
func (w *WireguardSecretConfig) GenerateWireguard() (*Wireguard, error) {
	shootPrivateKey, err := wg.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	shootPublicKey := shootPrivateKey.PublicKey()
	peerPresharedKey, err := wg.GenerateKey()
	if err != nil {
		return nil, err
	}
	localWireguardIP, err := w.GetIP()
	if err != nil {
		return nil, err
	}
	logger.Logger.Errorf("-------------------GenerateWireguard--------------peerPresharedKEy%s,shootprivatek%s,shootpublickey%s", peerPresharedKey.String(), shootPrivateKey.String(), shootPublicKey.String())
	return w.generateWithKeys(*localWireguardIP, peerPresharedKey.String(), shootPrivateKey.String(), shootPublicKey.String())
}

// generateWithKeys returns a Wireguard secret DataInterface with the given keys.
func (w *WireguardSecretConfig) generateWithKeys(localWireguardIP, peerPresharedKey, shootPrivateKey, shootPublicKey string) (*Wireguard, error) {
	wireguard := &Wireguard{
		Name:              w.Name,
		LocalWireguardIP:  localWireguardIP,
		RemoteWireguardIP: w.RemoteWireguardIP,
		PeerPublicKey:     w.PeerPublicKey,
		PeerPresharedKey:  peerPresharedKey,
		PrivateKey:        shootPrivateKey,
		PublicKey:         shootPublicKey,
		RemoteEndpoint:    w.RemoteEndpoint,
		SeedName:          w.SeedName,
	}

	return wireguard, nil
}

// SecretData computes the data map which can be used in a Kubernetes secret.
func (w *Wireguard) SecretData() map[string][]byte {
	data := map[string][]byte{}
	data[DataKeyLocalWireguardIP] = []byte(w.LocalWireguardIP)
	data[DataKeyRemoteWireguardIP] = []byte(w.RemoteWireguardIP)
	data[DataKeyPeerPublicKey] = []byte(w.PeerPublicKey)
	data[DataKeyPeerPresharedKey] = []byte(w.PeerPresharedKey)
	data[DataKeyWireguardPrivateKey] = []byte(w.PrivateKey)
	data[DataKeyWireguardPublicKey] = []byte(w.PublicKey)
	data[DataKeyRemoteEndpoint] = []byte(w.RemoteEndpoint)
	data[DataKeySeedName] = []byte(w.SeedName)

	return data
}
