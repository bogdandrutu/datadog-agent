// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build secrets
// +build secrets

// Package secrethelper implement an agent sub-command.
package secrethelper

import (
	"github.com/spf13/cobra"

	"github.com/DataDog/datadog-agent/cmd/agent/app"
	"github.com/DataDog/datadog-agent/cmd/secrets"
)

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalArgs *app.GlobalArgs) []*cobra.Command {
	// TODO: move to cmd/common/secrethelper?
	return []*cobra.Command{secrets.SecretHelperCmd}
}