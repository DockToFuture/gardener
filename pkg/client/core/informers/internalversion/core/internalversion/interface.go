/*
Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package internalversion

import (
	internalinterfaces "github.com/gardener/gardener/pkg/client/core/informers/internalversion/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// BackupBuckets returns a BackupBucketInformer.
	BackupBuckets() BackupBucketInformer
	// BackupEntries returns a BackupEntryInformer.
	BackupEntries() BackupEntryInformer
	// CloudProfiles returns a CloudProfileInformer.
	CloudProfiles() CloudProfileInformer
	// ControllerInstallations returns a ControllerInstallationInformer.
	ControllerInstallations() ControllerInstallationInformer
	// ControllerRegistrations returns a ControllerRegistrationInformer.
	ControllerRegistrations() ControllerRegistrationInformer
	// Plants returns a PlantInformer.
	Plants() PlantInformer
	// Projects returns a ProjectInformer.
	Projects() ProjectInformer
	// Quotas returns a QuotaInformer.
	Quotas() QuotaInformer
	// SecretBindings returns a SecretBindingInformer.
	SecretBindings() SecretBindingInformer
	// Seeds returns a SeedInformer.
	Seeds() SeedInformer
	// Shoots returns a ShootInformer.
	Shoots() ShootInformer
	// ShootExtensionStatuses returns a ShootExtensionStatusInformer.
	ShootExtensionStatuses() ShootExtensionStatusInformer
	// ShootStates returns a ShootStateInformer.
	ShootStates() ShootStateInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// BackupBuckets returns a BackupBucketInformer.
func (v *version) BackupBuckets() BackupBucketInformer {
	return &backupBucketInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// BackupEntries returns a BackupEntryInformer.
func (v *version) BackupEntries() BackupEntryInformer {
	return &backupEntryInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// CloudProfiles returns a CloudProfileInformer.
func (v *version) CloudProfiles() CloudProfileInformer {
	return &cloudProfileInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ControllerInstallations returns a ControllerInstallationInformer.
func (v *version) ControllerInstallations() ControllerInstallationInformer {
	return &controllerInstallationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ControllerRegistrations returns a ControllerRegistrationInformer.
func (v *version) ControllerRegistrations() ControllerRegistrationInformer {
	return &controllerRegistrationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Plants returns a PlantInformer.
func (v *version) Plants() PlantInformer {
	return &plantInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Projects returns a ProjectInformer.
func (v *version) Projects() ProjectInformer {
	return &projectInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Quotas returns a QuotaInformer.
func (v *version) Quotas() QuotaInformer {
	return &quotaInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// SecretBindings returns a SecretBindingInformer.
func (v *version) SecretBindings() SecretBindingInformer {
	return &secretBindingInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Seeds returns a SeedInformer.
func (v *version) Seeds() SeedInformer {
	return &seedInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Shoots returns a ShootInformer.
func (v *version) Shoots() ShootInformer {
	return &shootInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// ShootExtensionStatuses returns a ShootExtensionStatusInformer.
func (v *version) ShootExtensionStatuses() ShootExtensionStatusInformer {
	return &shootExtensionStatusInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// ShootStates returns a ShootStateInformer.
func (v *version) ShootStates() ShootStateInformer {
	return &shootStateInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
