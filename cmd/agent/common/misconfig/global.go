// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package misconfig

import "github.com/DataDog/datadog-agent/pkg/util/log"

// ToLog outputs warnings about common misconfigurations in the logs
func ToLog(agent AgentType) {
	for name, check := range checks {
		if _, ok := check.supportedAgents[agent]; ok {
			if err := check.run(); err != nil {
				log.Warnf("misconfig: %s: %v", name, err)
			}
		}
	}
}

type AgentType int
type checkFn func() error
type check struct {
	name            string
	run             checkFn
	supportedAgents map[AgentType]struct{}
}

const (
	CoreAgent = iota
	ProcessAgent
)

var checks = map[string]check{}

// nolint: deadcode, unused
func registerCheck(name string, c checkFn) {
	supportedAgentsSet := map[AgentType]struct{}{CoreAgent: {}, ProcessAgent: {}}
	checks[name] = check{name: name, run: c, supportedAgents: supportedAgentsSet}
}
