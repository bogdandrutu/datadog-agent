// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !python
// +build !python

package subcommands

import (
	"github.com/DataDog/datadog-agent/cmd/agent/app"
)

// pythonSubcommands returns SubcommandFactories for subcommands dependent on the `python` build tag.
func pythonSubcommands() []app.SubcommandFactory {
	return []app.SubcommandFactory{}
}
