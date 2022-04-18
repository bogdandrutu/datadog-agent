// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package autodiscovery

import (
	"fmt"
	"math"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/configresolver"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/listeners"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// configChanges contains the changes that occurred due to an event in a
// configManager.
type configChanges struct {

	// schedule contains configs that should be scheduled as a result of this
	// event.
	schedule []integration.Config

	// unschedule contains configs that should be unscheduled as a result of
	// this event.
	unschedule []integration.Config
}

// scheduleConfig adds a config to `schedule`
func (c *configChanges) scheduleConfig(config integration.Config) {
	c.schedule = append(c.schedule, config)
}

// sched adds a config to `unschedule`
func (c *configChanges) unscheduleConfig(config integration.Config) {
	c.unschedule = append(c.unschedule, config)
}

// isEmpty determines whether this set of changes is empty
func (c *configChanges) isEmpty() bool {
	return len(c.schedule) == 0 && len(c.unschedule) == 0
}

// merge merges the given configChanges into this one.
func (c *configChanges) merge(other configChanges) {
	c.schedule = append(c.schedule, other.schedule...)
	c.unschedule = append(c.unschedule, other.unschedule...)
}

// configManager implememnts the logic of handling additions and removals of
// configs (which may or may not be templates) and services, and reconciling
// those together to resolve templates.
//
// This type is threadsafe, internally using a mutex to serialize operations.
type configManager interface {
	// processNewService handles a new service, with the given AD identifiers
	processNewService(adIdentifiers []string, svc listeners.Service) configChanges

	// processDelService handles removal of a service.
	processDelService(svc listeners.Service) configChanges

	// processNewConfig handles a new config
	processNewConfig(config integration.Config) configChanges

	// processDelConfigs handles removal of a config.  Note that this
	// applies to a slice of configs, where the other methods in this
	// interface apply to only one config.
	processDelConfigs(configs []integration.Config) configChanges

	// mapOverLoadedConfigs calls the given function with a map of all
	// loaded configs (those which have been scheduled but not unscheduled).
	// The call is made with the manager's lock held, so callers should perform
	// minimal work within f.
	mapOverLoadedConfigs(func(map[string]integration.Config))
}

// serviceAndADIDs bundles a service and its associated AD identifiers.
type serviceAndADIDs struct {
	svc   listeners.Service
	adIDs []string
}

// a multimap is a string/string map that can contain multiple values for a
// single key.  Duplicate values are allowed (but not used in this package).
type multimap struct {
	data map[string][]string
}

// newMultimap creates a new multimap
func newMultimap() multimap {
	return multimap{data: map[string][]string{}}
}

// insert adds an item into a multimap
func (m *multimap) insert(k, v string) {
	var slice []string
	if existing, found := m.data[k]; found {
		slice = existing
	} else {
		slice = []string{}
	}
	m.data[k] = append(slice, v)
}

// remove removes an item from a multimap
func (m *multimap) remove(k, v string) {
	if values, found := m.data[k]; found {
		for i, u := range values {
			if u == v {
				// remove index i from the slice
				values[i] = values[len(values)-1]
				values = values[:len(values)-1]
				break
			}
		}
		if len(values) > 0 {
			m.data[k] = values
		} else {
			delete(m.data, k)
		}
	}
}

// get gets the set of items with the given key.  The returned slice must not
// be modified, and is only valid until the next multimap operation.
func (m *multimap) get(k string) []string {
	if values, found := m.data[k]; found {
		return values
	}
	return []string{}
}

// priorityConfigManager implements the a config manager that reconciles
// services and templates.
type priorityConfigManager struct {
	// updates to this data structure work from the top down:
	//
	//  1. update activeConfigs / activeServices
	//  2. update templatesByADID / servicesByADID to match
	//  3. update serviceResolutions, generating changes (see reconcileService)
	//  4. update scheduledConfigs
	//
	// For non-template configs, only steps 1 and 5 are required.

	// m synchronizes all operations on this struct.
	m sync.Mutex

	// activeConfigs contains an entry for each config from the config
	// providers, keyed by its digest.  This is the "base truth" of configs --
	// the set of new configs processed net deleted configs.
	activeConfigs map[string]integration.Config

	// activeServices contains an entry for each service from the listeners,
	// keyed by its serviceID and with its AD identifiers stored separately.
	// This is the "base truth" of services -- the set of new services
	// processed net deleted services.
	activeServices map[string]serviceAndADIDs

	// templatesByADID catalogs digests for all templates, indexed by their AD
	// identifiers.  It is an index to activeConfigs.
	templatesByADID multimap

	// servicesByADID catalogs serviceIDs for all services, indexed by their AD
	// identifiers.  It is an index to activeServices.
	servicesByADID multimap

	// serviceResolutions maps a serviceID to the resolutions performed for
	// that service: serviceID -> template digest -> resolved config digest.
	serviceResolutions map[string]map[string]string

	// scheduledConfigs contains an entry for each scheduled config, keyed by
	// its digest.  This is a mix of resolved templates and non-template
	// configs.  The returned configChanges from interface methods correspond
	// exactly to changes in this map.
	scheduledConfigs map[string]integration.Config
}

var _ configManager = &priorityConfigManager{}

// newPriorityConfigManager creates a new, empty priorityConfigManager.
func newPriorityConfigManager() configManager {
	return &priorityConfigManager{
		activeConfigs:      map[string]integration.Config{},
		activeServices:     map[string]serviceAndADIDs{},
		templatesByADID:    newMultimap(),
		servicesByADID:     newMultimap(),
		serviceResolutions: map[string]map[string]string{},
		scheduledConfigs:   map[string]integration.Config{},
	}
}

// processNewService implements configManager#processNewService.
func (cm *priorityConfigManager) processNewService(adIdentifiers []string, svc listeners.Service) configChanges {
	cm.m.Lock()
	defer cm.m.Unlock()

	svcID := svc.GetServiceID()
	if _, found := cm.activeServices[svcID]; found {
		log.Debugf("Service %s is already tracked by autodiscovery", svcID)
		return configChanges{}
	}

	//  1. update activeConfigs / activeServices
	cm.activeServices[svcID] = serviceAndADIDs{
		svc:   svc,
		adIDs: adIdentifiers,
	}

	//  2. update templatesByADID / servicesByADID to match
	for _, adID := range adIdentifiers {
		cm.servicesByADID.insert(adID, svcID)
	}

	//  3. update serviceResolutions, generating changes
	changes := cm.reconcileService(svcID)

	//  4. update scheduledConfigs
	return cm.applyChanges(changes)
}

// processDelService implements configManager#processDelService.
func (cm *priorityConfigManager) processDelService(svc listeners.Service) configChanges {
	cm.m.Lock()
	defer cm.m.Unlock()

	svcID := svc.GetServiceID()
	svcAndADIDs, found := cm.activeServices[svcID]
	if !found {
		log.Debugf("Service %s is not tracked by autodiscovery", svcID)
		return configChanges{}
	}

	//  1. update activeConfigs / activeServices
	delete(cm.activeServices, svcID)

	//  2. update templatesByADID / servicesByADID to match
	for _, adID := range svcAndADIDs.adIDs {
		cm.servicesByADID.remove(adID, svcID)
	}

	//  3. update serviceResolutions, generating changes
	changes := cm.reconcileService(svcID)

	//  4. update scheduledConfigs
	return cm.applyChanges(changes)
}

// processNewConfig implements configManager#processNewConfig.
func (cm *priorityConfigManager) processNewConfig(config integration.Config) configChanges {
	cm.m.Lock()
	defer cm.m.Unlock()

	digest := config.Digest()
	if _, found := cm.activeConfigs[digest]; found {
		log.Debug("Config %v is already tracked by autodiscovery", config.Name)
		return configChanges{}
	}

	//  1. update activeConfigs / activeServices
	cm.activeConfigs[digest] = config

	var changes configChanges
	if config.IsTemplate() {
		//  2. update templatesByADID / servicesByADID to match
		matchingServices := map[string]struct{}{}
		for _, adID := range config.ADIdentifiers {
			cm.templatesByADID.insert(adID, digest)
			for _, svcID := range cm.servicesByADID.get(adID) {
				matchingServices[svcID] = struct{}{}
			}
		}

		//  3. update serviceResolutions, generating changes
		for svcID := range matchingServices {
			changes.merge(cm.reconcileService(svcID))
		}
	} else {
		changes.scheduleConfig(config)
	}

	//  4. update scheduledConfigs
	return cm.applyChanges(changes)
}

// processDelConfigs implements configManager#processDelConfigs.
func (cm *priorityConfigManager) processDelConfigs(configs []integration.Config) configChanges {
	cm.m.Lock()
	defer cm.m.Unlock()

	var allChanges configChanges
	for _, config := range configs {
		digest := config.Digest()
		if _, found := cm.activeConfigs[digest]; !found {
			log.Debug("Config %v is not tracked by autodiscovery", config.Name)
			continue
		}

		//  1. update activeConfigs / activeServices
		delete(cm.activeConfigs, digest)

		var changes configChanges
		if config.IsTemplate() {
			//  2. update templatesByADID / servicesByADID to match
			matchingServices := map[string]struct{}{}
			for _, adID := range config.ADIdentifiers {
				cm.templatesByADID.remove(adID, digest)
				for _, svcID := range cm.servicesByADID.get(adID) {
					matchingServices[svcID] = struct{}{}
				}
			}

			//  3. update serviceResolutions, generating changes
			for svcID := range matchingServices {
				changes.merge(cm.reconcileService(svcID))
			}
		} else {
			changes.unscheduleConfig(config)
		}

		//  4. update scheduledConfigs
		allChanges.merge(cm.applyChanges(changes))
	}

	return allChanges
}

// mapOverLoadedConfigs implements configManager#mapOverLoadedConfigs.
func (cm *priorityConfigManager) mapOverLoadedConfigs(f func(map[string]integration.Config)) {
	cm.m.Lock()
	defer cm.m.Unlock()
	f(cm.scheduledConfigs)
}

// reconcileService calculates the current set of resolved templates for the
// given service and calculates the difference from what is currently recorded
// in cm.serviceResolutions.  It updates cm.serviceResolutions and returns the
// changes.
//
// This method must be called with cm.m locked.
func (cm *priorityConfigManager) reconcileService(svcID string) configChanges {
	var changes configChanges

	serviceAndADIDs := cm.activeServices[svcID]
	adIDs := serviceAndADIDs.adIDs // nil slice if service is not defined

	// get the existing resolutions for this service
	existingResolutions, found := cm.serviceResolutions[svcID]
	if !found {
		existingResolutions = map[string]string{}
	}

	// calculate the expected matching templates by template digest
	resolutionPriority := math.MinInt
	expectedResolutions := map[string]struct{}{}
	for _, adID := range adIDs {
		digests := cm.templatesByADID.get(adID)
		for _, digest := range digests {
			config := cm.activeConfigs[digest]
			if config.TemplatePriority > resolutionPriority {
				// this config has higher priority than any seen so far, so
				// drop all of the previous resolutions
				resolutionPriority = config.TemplatePriority
				expectedResolutions = map[string]struct{}{}
			}
			if config.TemplatePriority == resolutionPriority {
				expectedResolutions[digest] = struct{}{}
			}
		}
	}

	// compare existing to expected, generating changes and modifying
	// existingResolutions in-place
	for templateDigest, resolvedDigest := range existingResolutions {
		if _, found = expectedResolutions[templateDigest]; !found {
			changes.unscheduleConfig(cm.scheduledConfigs[resolvedDigest])
			delete(existingResolutions, templateDigest)
		}
	}

	for digest := range expectedResolutions {
		if _, found := existingResolutions[digest]; !found {
			config := cm.activeConfigs[digest]
			resolved, ok := cm.resolveTemplateForService(config, serviceAndADIDs.svc)
			if !ok {
				continue
			}
			changes.scheduleConfig(resolved)
			existingResolutions[digest] = resolved.Digest()
		}
	}

	if len(existingResolutions) == 0 {
		delete(cm.serviceResolutions, svcID)
	} else {
		cm.serviceResolutions[svcID] = existingResolutions
	}

	return changes
}

// resolveTemplateForService resolves a template config for the given service,
// updating errorStats in the process.  If the resolution fails, this method
// returns false.
func (cm *priorityConfigManager) resolveTemplateForService(tpl integration.Config, svc listeners.Service) (integration.Config, bool) {
	config, err := configresolver.Resolve(tpl, svc)
	if err != nil {
		msg := fmt.Sprintf("error resolving template %s for service %s: %v", tpl.Name, svc.GetServiceID(), err)
		errorStats.setResolveWarning(tpl.Name, msg)
		return tpl, false
	}
	resolvedConfig, err := decryptConfig(config)
	if err != nil {
		msg := fmt.Sprintf("error decrypting secrets in config %s for service %s: %v", config.Name, svc.GetServiceID(), err)
		errorStats.setResolveWarning(tpl.Name, msg)
		return config, false
	}
	errorStats.removeResolveWarnings(tpl.Name)
	return resolvedConfig, true
}

// applyChanges applies the given changes to cm.scheduledConfigs
//
// This method must be called with cm.m locked.
func (cm *priorityConfigManager) applyChanges(changes configChanges) configChanges {
	for _, cfg := range changes.unschedule {
		digest := cfg.Digest()
		delete(cm.scheduledConfigs, digest)
	}
	for _, cfg := range changes.schedule {
		digest := cfg.Digest()
		cm.scheduledConfigs[digest] = cfg
	}

	return changes
}