// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package module

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/stretchr/testify/assert"
)

func TestSECLRuleRilter(t *testing.T) {
	m := &RuleFilterModel{}
	seclRuleFilter := rules.NewSECLRuleFilter(m)

	t.Run("true", func(t *testing.T) {
		result, err := seclRuleFilter.IsRuleAccepted(
			&rules.RuleDefinition{
				Filters: []string{
					"true",
				},
			},
		)
		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("kernel-version", func(t *testing.T) {
		result, err := seclRuleFilter.IsRuleAccepted(
			&rules.RuleDefinition{
				Filters: []string{
					"kernel.version.major > 6",
				},
			},
		)
		assert.NoError(t, err)
		assert.True(t, result)
	})
}
