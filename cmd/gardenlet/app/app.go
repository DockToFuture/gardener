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

package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	goruntime "runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/version/verflag"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gardener/gardener/cmd/gardenlet/app/bootstrappers"
	cmdutils "github.com/gardener/gardener/cmd/utils"
	"github.com/gardener/gardener/pkg/api/indexer"
	gardencore "github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/apis/operations"
	operationsv1alpha1 "github.com/gardener/gardener/pkg/apis/operations/v1alpha1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	clientmapbuilder "github.com/gardener/gardener/pkg/client/kubernetes/clientmap/builder"
	dwd "github.com/gardener/gardener/pkg/component/nodemanagement/dependencywatchdog"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/controllerutils/routes"
	"github.com/gardener/gardener/pkg/features"
	"github.com/gardener/gardener/pkg/gardenlet/apis/config"
	gardenlethelper "github.com/gardener/gardener/pkg/gardenlet/apis/config/helper"
	"github.com/gardener/gardener/pkg/gardenlet/bootstrap"
	"github.com/gardener/gardener/pkg/gardenlet/bootstrap/certificate"
	"github.com/gardener/gardener/pkg/gardenlet/controller"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	resourcemanagerv1alpha1 "github.com/gardener/gardener/pkg/resourcemanager/apis/config/v1alpha1"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/pkg/utils/flow"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	utilclient "github.com/gardener/gardener/pkg/utils/kubernetes/client"
	"github.com/gardener/gardener/pkg/utils/managedresources"
)

const (
	// Name is a const for the name of this component.
	Name = "gardenlet"
)

// NewCommand creates a new cobra.Command for running gardenlet.
func NewCommand() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   Name,
		Short: "Launch the " + Name,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := cmdutils.InitRun(cmd, opts, Name)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithCancel(cmd.Context())
			return run(ctx, cancel, log, opts.config)
		},
	}

	flags := cmd.Flags()
	verflag.AddFlags(flags)
	opts.addFlags(flags)

	return cmd
}

func run(ctx context.Context, cancel context.CancelFunc, log logr.Logger, cfg *config.GardenletConfiguration) error {
	log.Info("Feature Gates", "featureGates", features.DefaultFeatureGate)

	if kubeconfig := os.Getenv("GARDEN_KUBECONFIG"); kubeconfig != "" {
		cfg.GardenClientConnection.Kubeconfig = kubeconfig
	}
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		cfg.SeedClientConnection.Kubeconfig = kubeconfig
	}

	log.Info("Getting rest config for seed")
	seedRESTConfig, err := kubernetes.RESTConfigFromClientConnectionConfiguration(&cfg.SeedClientConnection.ClientConnectionConfiguration, nil)
	if err != nil {
		return err
	}

	var extraHandlers map[string]http.Handler
	if cfg.Debugging != nil && cfg.Debugging.EnableProfiling {
		extraHandlers = routes.ProfilingHandlers
		if cfg.Debugging.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
	}

	log.Info("Setting up manager")
	mgr, err := manager.New(seedRESTConfig, manager.Options{
		Logger:                  log,
		Scheme:                  kubernetes.SeedScheme,
		GracefulShutdownTimeout: ptr.To(5 * time.Second),

		HealthProbeBindAddress: net.JoinHostPort(cfg.Server.HealthProbes.BindAddress, strconv.Itoa(cfg.Server.HealthProbes.Port)),
		Metrics: metricsserver.Options{
			BindAddress:   net.JoinHostPort(cfg.Server.Metrics.BindAddress, strconv.Itoa(cfg.Server.Metrics.Port)),
			ExtraHandlers: extraHandlers,
		},

		LeaderElection:                cfg.LeaderElection.LeaderElect,
		LeaderElectionResourceLock:    cfg.LeaderElection.ResourceLock,
		LeaderElectionID:              cfg.LeaderElection.ResourceName,
		LeaderElectionNamespace:       cfg.LeaderElection.ResourceNamespace,
		LeaderElectionReleaseOnCancel: true,
		LeaseDuration:                 &cfg.LeaderElection.LeaseDuration.Duration,
		RenewDeadline:                 &cfg.LeaderElection.RenewDeadline.Duration,
		RetryPeriod:                   &cfg.LeaderElection.RetryPeriod.Duration,
		Controller: controllerconfig.Controller{
			RecoverPanic: ptr.To(true),
		},

		MapperProvider: apiutil.NewDynamicRESTMapper,
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{
					&corev1.Event{},
					&eventsv1.Event{},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	log.Info("Setting up periodic health manager")
	healthGracePeriod := time.Duration((*cfg.Controllers.Seed.LeaseResyncSeconds)*(*cfg.Controllers.Seed.LeaseResyncMissThreshold)) * time.Second
	healthManager := gardenerhealthz.NewPeriodicHealthz(clock.RealClock{}, healthGracePeriod)
	healthManager.Set(true)

	log.Info("Setting up health check endpoints")
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("periodic-health", gardenerhealthz.CheckerFunc(healthManager)); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("seed-informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return err
	}

	log.Info("Adding runnables to manager for bootstrapping")
	kubeconfigBootstrapResult := &bootstrappers.KubeconfigBootstrapResult{}

	if err := mgr.Add(&controllerutils.ControlledRunner{
		Manager: mgr,
		BootstrapRunnables: []manager.Runnable{
			&bootstrappers.SeedConfigChecker{
				SeedClient: mgr.GetClient(),
				SeedConfig: cfg.SeedConfig,
			},
			&bootstrappers.GardenKubeconfig{
				SeedClient: mgr.GetClient(),
				Log:        mgr.GetLogger().WithName("bootstrap"),
				Config:     cfg,
				Result:     kubeconfigBootstrapResult,
			},
		},
		ActualRunnables: []manager.Runnable{
			&garden{
				cancel:                    cancel,
				mgr:                       mgr,
				config:                    cfg,
				healthManager:             healthManager,
				kubeconfigBootstrapResult: kubeconfigBootstrapResult,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed adding runnables to manager: %w", err)
	}

	log.Info("Starting manager")
	return mgr.Start(ctx)
}

type garden struct {
	cancel                    context.CancelFunc
	mgr                       manager.Manager
	config                    *config.GardenletConfiguration
	healthManager             gardenerhealthz.Manager
	kubeconfigBootstrapResult *bootstrappers.KubeconfigBootstrapResult
}

func (g *garden) Start(ctx context.Context) error {
	log := g.mgr.GetLogger()

	log.Info("Getting rest config for garden")
	gardenRESTConfig, err := kubernetes.RESTConfigFromClientConnectionConfiguration(&g.config.GardenClientConnection.ClientConnectionConfiguration, g.kubeconfigBootstrapResult.Kubeconfig)
	if err != nil {
		return err
	}

	log.Info("Setting up cluster object for garden")
	gardenCluster, err := cluster.New(gardenRESTConfig, func(opts *cluster.Options) {
		opts.Scheme = kubernetes.GardenScheme
		opts.Logger = log

		opts.Client.Cache = &client.CacheOptions{
			DisableFor: []client.Object{
				&corev1.Event{},
				&eventsv1.Event{},
			},
		}

		seedNamespace := gardenerutils.ComputeGardenNamespace(g.config.SeedConfig.SeedTemplate.Name)

		opts.NewCache = func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			// gardenlet should watch only objects which are related to the seed it is responsible for.
			opts.ByObject = map[client.Object]cache.ByObject{
				&gardencorev1beta1.ControllerInstallation{}: {
					Field: fields.SelectorFromSet(fields.Set{gardencore.SeedRefName: g.config.SeedConfig.SeedTemplate.Name}),
				},
				&gardencorev1beta1.Shoot{}: {
					Label: labels.SelectorFromSet(labels.Set{v1beta1constants.LabelPrefixSeedName + g.config.SeedConfig.SeedTemplate.Name: "true"}),
				},
				&operationsv1alpha1.Bastion{}: {
					Field: fields.SelectorFromSet(fields.Set{operations.BastionSeedName: g.config.SeedConfig.SeedTemplate.Name}),
				},
				// Gardenlet should watch secrets/serviceAccounts only in the seed namespace of the seed it is responsible for.
				&corev1.Secret{}: {
					Namespaces: map[string]cache.Config{seedNamespace: {}},
				},
				&corev1.ServiceAccount{}: {
					Namespaces: map[string]cache.Config{seedNamespace: {}},
				},
			}

			return kubernetes.AggregatorCacheFunc(
				kubernetes.NewRuntimeCache,
				map[client.Object]cache.NewCacheFunc{
					// Gardenlet does not have the required RBAC permissions for listing/watching the following
					// resources on cluster level. Hence, we need to watch them individually with the help of a
					// SingleObject cache.
					&corev1.ConfigMap{}:                         kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &corev1.ConfigMap{}),
					&corev1.Namespace{}:                         kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &corev1.Namespace{}),
					&coordinationv1.Lease{}:                     kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &coordinationv1.Lease{}),
					&certificatesv1.CertificateSigningRequest{}: kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &certificatesv1.CertificateSigningRequest{}),
					&gardencorev1beta1.CloudProfile{}:           kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &gardencorev1beta1.CloudProfile{}),
					&gardencorev1beta1.ControllerDeployment{}:   kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &gardencorev1beta1.ControllerDeployment{}),
					&gardencorev1beta1.ExposureClass{}:          kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &gardencorev1beta1.ExposureClass{}),
					&gardencorev1beta1.InternalSecret{}:         kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &gardencorev1beta1.InternalSecret{}),
					&gardencorev1beta1.Project{}:                kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &gardencorev1beta1.Project{}),
					&gardencorev1beta1.SecretBinding{}:          kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &gardencorev1beta1.SecretBinding{}),
					&gardencorev1beta1.ShootState{}:             kubernetes.SingleObjectCacheFunc(log, kubernetes.GardenScheme, &gardencorev1beta1.ShootState{}),
				},
				kubernetes.GardenScheme,
			)(config, opts)
		}

		// The created multi-namespace cache does not fall back to an uncached reader in case the gardenlet tries to
		// read a secret from another namespace. There might be secrets in namespace other than the seed-specific
		// namespace (e.g., backup secret in the SeedSpec). Hence, let's use a fallback client which falls back to an
		// uncached reader in case it fails to read objects from the cache.
		opts.NewClient = func(config *rest.Config, options client.Options) (client.Client, error) {
			uncachedOptions := options
			uncachedOptions.Cache = nil
			uncachedClient, err := client.New(config, uncachedOptions)
			if err != nil {
				return nil, err
			}

			cachedClient, err := client.New(config, options)
			if err != nil {
				return nil, err
			}

			return &kubernetes.FallbackClient{
				Client: cachedClient,
				Reader: uncachedClient,
				KindToNamespaces: map[string]sets.Set[string]{
					"Secret":         sets.New[string](seedNamespace),
					"ServiceAccount": sets.New[string](seedNamespace),
				},
			}, nil
		}

		opts.MapperProvider = apiutil.NewDynamicRESTMapper
	})
	if err != nil {
		return fmt.Errorf("failed creating garden cluster object: %w", err)
	}

	log.Info("Cleaning bootstrap authentication data used to request a certificate if needed")
	if len(g.kubeconfigBootstrapResult.CSRName) > 0 && len(g.kubeconfigBootstrapResult.SeedName) > 0 {
		if err := bootstrap.DeleteBootstrapAuth(ctx, gardenCluster.GetClient(), gardenCluster.GetClient(), g.kubeconfigBootstrapResult.CSRName); err != nil {
			return fmt.Errorf("failed cleaning bootstrap auth data: %w", err)
		}
	}

	log.Info("Adding field indexes to informers")
	if err := addAllFieldIndexes(ctx, gardenCluster.GetFieldIndexer()); err != nil {
		return fmt.Errorf("failed adding indexes: %w", err)
	}

	log.Info("Adding garden cluster to manager")
	if err := g.mgr.Add(gardenCluster); err != nil {
		return fmt.Errorf("failed adding garden cluster to manager: %w", err)
	}

	waitForSyncCtx, waitForSyncCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitForSyncCancel()

	log.V(1).Info("Waiting for cache to be synced")
	if !gardenCluster.GetCache().WaitForCacheSync(waitForSyncCtx) {
		return fmt.Errorf("failed waiting for cache to be synced")
	}

	log.Info("Registering Seed object in garden cluster")
	if err := g.registerSeed(ctx, gardenCluster.GetClient()); err != nil {
		return err
	}

	log.Info("Updating last operation status of processing Shoots to 'Aborted'")
	if err := g.updateProcessingShootStatusToAborted(ctx, gardenCluster.GetClient()); err != nil {
		return err
	}

	log.Info("Cleaning up GRM secret finalizers")
	if err := cleanupGRMSecretFinalizers(ctx, g.mgr.GetClient(), log); err != nil {
		return fmt.Errorf("failed to clean up GRM secret finalizers: %w", err)
	}

	log.Info("Updating shoot Prometheus config for connection to cache Prometheus and seed Alertmanager")
	if err := updateShootPrometheusConfigForConnectionToCachePrometheusAndSeedAlertManager(ctx, g.mgr.GetClient()); err != nil {
		return err
	}

	log.Info("Creating new secret and managed resource required by dependency-watchdog")
	if err := g.createNewDWDResources(ctx, g.mgr.GetClient()); err != nil {
		return err
	}

	log.Info("Cleaning up legacy 'shoot-core' ManagedResource")
	if err := cleanupShootCoreManagedResource(ctx, g.mgr.GetClient()); err != nil {
		return err
	}

	log.Info("Reconciling labels for PVC migrations")
	if err := reconcileLabelsForPVCMigrations(ctx, log, g.mgr.GetClient()); err != nil {
		return err
	}

	log.Info("Setting up shoot client map")
	shootClientMap, err := clientmapbuilder.
		NewShootClientMapBuilder().
		WithGardenClient(gardenCluster.GetClient()).
		WithSeedClient(g.mgr.GetClient()).
		WithClientConnectionConfig(&g.config.ShootClientConnection.ClientConnectionConfiguration).
		Build(log)
	if err != nil {
		return fmt.Errorf("failed to build shoot ClientMap: %w", err)
	}

	log.Info("Adding runnables now that bootstrapping is finished")
	runnables := []manager.Runnable{
		g.healthManager,
		shootClientMap,
	}

	if g.config.GardenClientConnection.KubeconfigSecret != nil {
		certificateManager, err := certificate.NewCertificateManager(log, gardenCluster, g.mgr.GetClient(), g.config)
		if err != nil {
			return fmt.Errorf("failed to create a new certificate manager: %w", err)
		}

		runnables = append(runnables, manager.RunnableFunc(func(ctx context.Context) error {
			return certificateManager.ScheduleCertificateRotation(ctx, g.cancel, g.mgr.GetEventRecorderFor("certificate-manager"))
		}))
	}

	if err := controllerutils.AddAllRunnables(g.mgr, runnables...); err != nil {
		return err
	}

	log.Info("Adding controllers to manager")
	if err := controller.AddToManager(
		ctx,
		g.mgr,
		g.cancel,
		gardenCluster,
		g.mgr,
		shootClientMap,
		g.config,
		g.healthManager,
	); err != nil {
		return fmt.Errorf("failed adding controllers to manager: %w", err)
	}

	return nil
}

// TODO(aaronfern): Remove this code after v1.93 has been released.
func (g *garden) createNewDWDResources(ctx context.Context, seedClient client.Client) error {
	namespaceList := &corev1.NamespaceList{}
	if err := seedClient.List(ctx, namespaceList, client.MatchingLabels(map[string]string{v1beta1constants.GardenRole: v1beta1constants.GardenRoleShoot})); err != nil {
		return err
	}

	var tasks []flow.TaskFn
	for _, ns := range namespaceList.Items {
		if ns.DeletionTimestamp != nil || ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		namespace := ns
		tasks = append(tasks, func(ctx context.Context) error {
			dwdOldSecret := &corev1.Secret{}
			if err := seedClient.Get(ctx, types.NamespacedName{Namespace: namespace.Name, Name: dwd.InternalProbeSecretName}, dwdOldSecret); err != nil {
				// If ns does not contain old DWD secret, do not procees.
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}

			// Fetch GRM deployment
			grmDeploy := &appsv1.Deployment{}
			if err := seedClient.Get(ctx, types.NamespacedName{Namespace: namespace.Name, Name: "gardener-resource-manager"}, grmDeploy); err != nil {
				if apierrors.IsNotFound(err) {
					// Do not proceed if GRM deployment is not present
					return nil
				}
				return err
			}

			// Create a DWDAccess object
			inClusterServerURL := fmt.Sprintf("%s.%s.svc", v1beta1constants.DeploymentNameKubeAPIServer, namespace.Name)
			dwdAccess := dwd.NewAccess(seedClient, namespace.Name, nil, dwd.AccessValues{ServerInCluster: inClusterServerURL})

			if err := dwdAccess.DeployMigrate(ctx); err != nil {
				return err
			}

			// Delete old DWD secrets
			if err := kubernetesutils.DeleteObjects(ctx, seedClient,
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: dwd.InternalProbeSecretName, Namespace: namespace.Name}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: dwd.ExternalProbeSecretName, Namespace: namespace.Name}},
			); err != nil {
				return err
			}

			// Fetch and update the GRM configmap
			var grmCMName string
			var grmCMVolumeIndex int
			for n, vol := range grmDeploy.Spec.Template.Spec.Volumes {
				if vol.Name == "config" {
					grmCMName = vol.ConfigMap.Name
					grmCMVolumeIndex = n
					break
				}
			}
			if len(grmCMName) == 0 {
				return nil
			}

			grmConfigMap := &corev1.ConfigMap{}
			if err := seedClient.Get(ctx, types.NamespacedName{Namespace: namespace.Name, Name: grmCMName}, grmConfigMap); err != nil {
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}

			cmData := grmConfigMap.Data["config.yaml"]
			rmConfig := resourcemanagerv1alpha1.ResourceManagerConfiguration{}

			// create codec
			var codec runtime.Codec
			configScheme := runtime.NewScheme()
			utilruntime.Must(resourcemanagerv1alpha1.AddToScheme(configScheme))
			utilruntime.Must(apiextensionsv1.AddToScheme(configScheme))
			ser := json.NewSerializerWithOptions(json.DefaultMetaFactory, configScheme, configScheme, json.SerializerOptions{
				Yaml:   true,
				Pretty: false,
				Strict: false,
			})
			versions := schema.GroupVersions([]schema.GroupVersion{
				resourcemanagerv1alpha1.SchemeGroupVersion,
				apiextensionsv1.SchemeGroupVersion,
			})
			codec = serializer.NewCodecFactory(configScheme).CodecForVersions(ser, ser, versions, versions)

			obj, err := runtime.Decode(codec, []byte(cmData))
			if err != nil {
				return err
			}
			rmConfig = *(obj.(*resourcemanagerv1alpha1.ResourceManagerConfiguration))

			if rmConfig.TargetClientConnection == nil || slices.Contains(rmConfig.TargetClientConnection.Namespaces, corev1.NamespaceNodeLease) {
				return nil
			}

			rmConfig.TargetClientConnection.Namespaces = append(rmConfig.TargetClientConnection.Namespaces, corev1.NamespaceNodeLease)

			data, err := runtime.Encode(codec, &rmConfig)
			if err != nil {
				return err
			}

			newGRMConfigMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "gardener-resource-manager-dwd", Namespace: namespace.Name}}
			newGRMConfigMap.Data = map[string]string{"config.yaml": string(data)}
			utilruntime.Must(kubernetesutils.MakeUnique(newGRMConfigMap))

			if err = seedClient.Create(ctx, newGRMConfigMap); err != nil {
				if !apierrors.IsAlreadyExists(err) {
					return err
				}
			}

			patch := client.MergeFrom(grmDeploy.DeepCopy())
			grmDeploy.Spec.Template.Spec.Volumes[grmCMVolumeIndex].ConfigMap.Name = newGRMConfigMap.Name
			utilruntime.Must(references.InjectAnnotations(grmDeploy))

			return seedClient.Patch(ctx, grmDeploy, patch)
		})
	}
	return flow.Parallel(tasks...)(ctx)
}

// TODO(Kostov6): Remove this code after v1.91 has been released.
func cleanupGRMSecretFinalizers(ctx context.Context, seedClient client.Client, log logr.Logger) error {
	var (
		mrs      = &resourcesv1alpha1.ManagedResourceList{}
		selector = labels.NewSelector()
	)

	// Exclude seed system components while listing
	requirement, err := labels.NewRequirement(v1beta1constants.GardenRole, selection.NotIn, []string{v1beta1constants.GardenRoleSeedSystemComponent})
	if err != nil {
		return fmt.Errorf("failed to construct the requirement: %w", err)
	}
	labelSelector := selector.Add(*requirement)

	if err := seedClient.List(ctx, mrs, client.MatchingLabelsSelector{Selector: labelSelector}); err != nil {
		if meta.IsNoMatchError(err) {
			log.Info("Received a 'no match error' while trying to list managed resources. Will assume that the managed resources CRD is not yet installed (for example new Seed creation) and will skip cleaning up GRM finalizers")
			return nil
		}
		return fmt.Errorf("failed to list managed resources: %w", err)
	}

	return utilclient.ApplyToObjects(ctx, mrs, func(ctx context.Context, obj client.Object) error {
		mr, ok := obj.(*resourcesv1alpha1.ManagedResource)
		if !ok {
			return fmt.Errorf("expected *resourcesv1alpha1.ManagedResource but got %T", obj)
		}

		// only patch MR secrets in shoot namespaces
		if mr.Namespace == v1beta1constants.GardenNamespace {
			return nil
		}

		for _, ref := range mr.Spec.SecretRefs {
			secret := &corev1.Secret{}
			if err := seedClient.Get(ctx, client.ObjectKey{Namespace: mr.Namespace, Name: ref.Name}, secret); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return fmt.Errorf("failed to get secret '%s': %w", kubernetesutils.Key(mr.Namespace, ref.Name), err)
			}

			for _, finalizer := range secret.Finalizers {
				if strings.HasPrefix(finalizer, "resources.gardener.cloud/gardener-resource-manager") {
					if err := controllerutils.RemoveFinalizers(ctx, seedClient, secret, finalizer); err != nil {
						return fmt.Errorf("failed to remove finalizer from secret '%s': %w", client.ObjectKeyFromObject(secret), err)
					}
				}
			}
		}
		return nil
	})
}

// TODO(rfranzke): Remove this code after v1.92 has been released.
func updateShootPrometheusConfigForConnectionToCachePrometheusAndSeedAlertManager(ctx context.Context, seedClient client.Client) error {
	statefulSetList := &appsv1.StatefulSetList{}
	if err := seedClient.List(ctx, statefulSetList, client.MatchingLabels{"app": "prometheus", "role": "monitoring", "gardener.cloud/role": "monitoring"}); err != nil {
		return err
	}

	var taskFns []flow.TaskFn
	for _, obj := range statefulSetList.Items {
		if !strings.HasPrefix(obj.Namespace, v1beta1constants.TechnicalIDPrefix) {
			continue
		}

		statefulSet := obj.DeepCopy()

		taskFns = append(taskFns,
			func(ctx context.Context) error {
				patch := client.MergeFrom(statefulSet.DeepCopy())
				metav1.SetMetaDataLabel(&statefulSet.Spec.Template.ObjectMeta, "networking.resources.gardener.cloud/to-garden-prometheus-cache-tcp-9090", "allowed")
				metav1.SetMetaDataLabel(&statefulSet.Spec.Template.ObjectMeta, "networking.resources.gardener.cloud/to-garden-alertmanager-seed-tcp-9093", "allowed")
				return seedClient.Patch(ctx, statefulSet, patch)
			},
			func(ctx context.Context) error {
				configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-config", Namespace: statefulSet.Namespace}}
				if err := seedClient.Get(ctx, client.ObjectKeyFromObject(configMap), configMap); err != nil {
					if apierrors.IsNotFound(err) {
						return nil
					}
					return err
				}

				if configMap.Data == nil || configMap.Data["prometheus.yaml"] == "" {
					return nil
				}

				patch := client.MergeFrom(configMap.DeepCopy())
				configMap.Data["prometheus.yaml"] = strings.ReplaceAll(configMap.Data["prometheus.yaml"], "prometheus-web.garden.svc", "prometheus-cache.garden.svc")
				return seedClient.Patch(ctx, configMap, patch)
			},
		)
	}

	return flow.Parallel(taskFns...)(ctx)
}

// TODO(shafeeqes): Remove this code after gardener v1.92 has been released.
func cleanupShootCoreManagedResource(ctx context.Context, seedClient client.Client) error {
	shootNamespaceList := &corev1.NamespaceList{}
	if err := seedClient.List(ctx, shootNamespaceList, client.MatchingLabels{v1beta1constants.GardenRole: v1beta1constants.GardenRoleShoot}); err != nil {
		return err
	}

	var taskFns []flow.TaskFn

	for _, ns := range shootNamespaceList.Items {
		namespace := ns

		taskFns = append(taskFns, func(ctx context.Context) error {
			return managedresources.DeleteForShoot(ctx, seedClient, namespace.Name, "shoot-core")
		})
	}

	return flow.Parallel(taskFns...)(ctx)
}

// TODO(rfranzke): Remove this code after gardener v1.92 has been released.
func reconcileLabelsForPVCMigrations(ctx context.Context, log logr.Logger, seedClient client.Client) error {
	var (
		labelMigrationNamespace = "disk-migration.monitoring.gardener.cloud/namespace"
		labelMigrationPVCName   = "disk-migration.monitoring.gardener.cloud/pvc-name"
	)

	persistentVolumeList := &corev1.PersistentVolumeList{}
	if err := seedClient.List(ctx, persistentVolumeList, client.HasLabels{labelMigrationPVCName}); err != nil {
		return fmt.Errorf("failed listing persistent volumes with label %s: %w", labelMigrationPVCName, err)
	}

	var (
		persistentVolumeNamesWithoutClaimRef []string
		taskFns                              []flow.TaskFn
	)

	for _, pv := range persistentVolumeList.Items {
		persistentVolume := pv

		if persistentVolume.Labels[labelMigrationNamespace] != "" {
			continue
		}

		if persistentVolume.Status.Phase == corev1.VolumeReleased && persistentVolume.Spec.ClaimRef != nil {
			// check if namespace is already gone - if yes, just clean them up
			if err := seedClient.Get(ctx, client.ObjectKey{Name: persistentVolume.Spec.ClaimRef.Namespace}, &corev1.Namespace{}); err != nil {
				if !apierrors.IsNotFound(err) {
					return fmt.Errorf("failed checking if namespace %s still exists (due to PV %s): %w", persistentVolume.Spec.ClaimRef.Namespace, client.ObjectKeyFromObject(&persistentVolume), err)
				}

				taskFns = append(taskFns, func(ctx context.Context) error {
					log.Info("Deleting orphaned persistent volume in migration", "persistentVolume", client.ObjectKeyFromObject(&persistentVolume))
					return client.IgnoreNotFound(seedClient.Delete(ctx, &persistentVolume))
				})
				continue
			}
		} else if persistentVolume.Spec.ClaimRef == nil {
			persistentVolumeNamesWithoutClaimRef = append(persistentVolumeNamesWithoutClaimRef, persistentVolume.Name)
			continue
		}

		taskFns = append(taskFns, func(ctx context.Context) error {
			log.Info("Adding missing namespace label to persistent volume in migration", "persistentVolume", client.ObjectKeyFromObject(&persistentVolume), "namespace", persistentVolume.Spec.ClaimRef.Namespace)
			patch := client.MergeFrom(persistentVolume.DeepCopy())
			metav1.SetMetaDataLabel(&persistentVolume.ObjectMeta, labelMigrationNamespace, persistentVolume.Spec.ClaimRef.Namespace)
			return seedClient.Patch(ctx, &persistentVolume, patch)
		})
	}

	if err := flow.Parallel(taskFns...)(ctx); err != nil {
		return err
	}

	if len(persistentVolumeNamesWithoutClaimRef) > 0 {
		return fmt.Errorf("found persistent volumes with missing namespace in migration label and `.spec.claimRef=nil` - "+
			"cannot automatically determine the namespace this PV originated from. "+
			"A human operator needs to manually add the namespace and update the label to %s=<namespace> - "+
			"The names of such PVs are: %+v", labelMigrationNamespace, persistentVolumeNamesWithoutClaimRef)
	}

	return nil
}

func (g *garden) registerSeed(ctx context.Context, gardenClient client.Client) error {
	seed := &gardencorev1beta1.Seed{
		ObjectMeta: metav1.ObjectMeta{
			Name: g.config.SeedConfig.Name,
		},
	}

	// Convert gardenlet config to an external version
	cfg, err := gardenlethelper.ConvertGardenletConfigurationExternal(g.config)
	if err != nil {
		return fmt.Errorf("could not convert gardenlet configuration: %w", err)
	}

	if _, err := controllerutils.GetAndCreateOrMergePatch(ctx, gardenClient, seed, func() error {
		seed.Annotations = utils.MergeStringMaps(seed.Annotations, g.config.SeedConfig.Annotations)
		seed.Labels = utils.MergeStringMaps(map[string]string{
			v1beta1constants.GardenRole: v1beta1constants.GardenRoleSeed,
		}, g.config.SeedConfig.Labels)

		seed.Spec = cfg.SeedConfig.Spec
		return nil
	}); err != nil {
		return fmt.Errorf("could not register seed %q: %w", seed.Name, err)
	}

	// Verify that the gardener-controller-manager has created the seed-specific namespace. Here we also accept
	// 'forbidden' errors since the SeedAuthorizer (if enabled) forbid the gardenlet to read the namespace in case the
	// gardener-controller-manager has not yet created it.
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return wait.PollUntilContextCancel(timeoutCtx, 500*time.Millisecond, false, func(context.Context) (done bool, err error) {
		if err := gardenClient.Get(ctx, kubernetesutils.Key(gardenerutils.ComputeGardenNamespace(g.config.SeedConfig.Name)), &corev1.Namespace{}); err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
}

func (g *garden) updateProcessingShootStatusToAborted(ctx context.Context, gardenClient client.Client) error {
	shootList := &gardencorev1beta1.ShootList{}
	if err := gardenClient.List(ctx, shootList); err != nil {
		return err
	}

	var taskFns []flow.TaskFn

	for _, s := range shootList.Items {
		shoot := s

		if specSeedName, statusSeedName := gardenerutils.GetShootSeedNames(&shoot); gardenerutils.GetResponsibleSeedName(specSeedName, statusSeedName) != g.config.SeedConfig.Name {
			continue
		}

		// Check if the status indicates that an operation is processing and mark it as "aborted".
		if shoot.Status.LastOperation == nil || shoot.Status.LastOperation.State != gardencorev1beta1.LastOperationStateProcessing {
			continue
		}

		taskFns = append(taskFns, func(ctx context.Context) error {
			patch := client.MergeFrom(shoot.DeepCopy())
			shoot.Status.LastOperation.State = gardencorev1beta1.LastOperationStateAborted
			if err := gardenClient.Status().Patch(ctx, &shoot, patch); err != nil {
				return fmt.Errorf("failed to set status to 'Aborted' for shoot %q: %w", client.ObjectKeyFromObject(&shoot), err)
			}

			return nil
		})
	}

	return flow.Parallel(taskFns...)(ctx)
}

func addAllFieldIndexes(ctx context.Context, i client.FieldIndexer) error {
	for _, fn := range []func(context.Context, client.FieldIndexer) error{
		// core API group
		indexer.AddShootSeedName,
		indexer.AddShootStatusSeedName,
		indexer.AddBackupBucketSeedName,
		indexer.AddBackupEntrySeedName,
		indexer.AddBackupEntryBucketName,
		indexer.AddControllerInstallationSeedRefName,
		indexer.AddControllerInstallationRegistrationRefName,
		// operations API group
		indexer.AddBastionShootName,
		// seedmanagement API group
		indexer.AddManagedSeedShootName,
	} {
		if err := fn(ctx, i); err != nil {
			return err
		}
	}

	return nil
}
