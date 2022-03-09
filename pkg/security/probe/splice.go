// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

var spliceCapabilities = Capabilities{
	"splice.file.path": {
		PolicyFlags:     PolicyFlagBasename,
		FieldValueTypes: eval.ScalarValueType | eval.PatternValueType,
		ValidateFnc:     validateBasenameFilter,
	},
	"splice.file.name": {
		PolicyFlags:     PolicyFlagBasename,
		FieldValueTypes: eval.ScalarValueType,
	},
	"splice.pipe_flag": {
		PolicyFlags:     PolicyFlagFlags,
		FieldValueTypes: eval.ScalarValueType | eval.BitmaskValueType,
	},
}

func spliceOnNewApprovers(probe *Probe, approvers rules.Approvers) (activeApprovers, error) {
	intValues := func(fvs rules.FilterValues) []int {
		var values []int
		for _, v := range fvs {
			values = append(values, v.Value.(int))
		}
		return values
	}

	spliceApprovers, err := onNewBasenameApprovers(probe, model.SpliceEventType, "file", approvers)
	if err != nil {
		return nil, err
	}

	for field, values := range approvers {
		switch field {
		case "splice.file.name", "splice.file.path": // already handled by onNewBasenameApprovers
		case "splice.pipe_flag":
			var approver activeApprover
			approver, err = approveFlags("splice_flags_approvers", intValues(values)...)
			if err != nil {
				return nil, err
			}
			spliceApprovers = append(spliceApprovers, approver)

		default:
			return nil, fmt.Errorf("unknown field '%s'", field)
		}
	}
	return newActiveKFilters(spliceApprovers...), nil
}
