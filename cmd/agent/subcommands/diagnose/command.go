// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package diagnose implement an agent sub-command.
package diagnose

import (
	"fmt"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/diagnose"
	"github.com/DataDog/datadog-agent/pkg/diagnose/connectivity"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	// confFilePath is the value of the --cfgpath flag.
	confFilePath string

	// noTrace is the value of the --no-trace flag
	noTrace bool
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalArgs *command.GlobalArgs) []*cobra.Command {
	var noTrace bool

	diagnoseMetadataAvailabilityCommand := &cobra.Command{
		Use:   "metadata-availability",
		Short: "Check availability of cloud provider and container metadata endpoints",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(runAll,
				fx.Supply(&cliParams{
					confFilePath: globalArgs.ConfFilePath,
					noTrace:      false,
				}),
			)
		},
	}

	diagnoseDatadogConnectivityCommand := &cobra.Command{
		Use:   "datadog-connectivity",
		Short: "Check connectivity between your system and Datadog endpoints",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(runDatadogConnectivityDiagnose,
				fx.Supply(&cliParams{
					confFilePath: globalArgs.ConfFilePath,
					noTrace:      noTrace,
				}),
			)
		},
	}
	diagnoseDatadogConnectivityCommand.PersistentFlags().BoolVarP(&noTrace, "no-trace", "", false, "mute extra information about connection establishment, DNS lookup and TLS handshake")

	diagnoseCommand := &cobra.Command{
		Use:   "diagnose",
		Short: "Check availability of cloud provider and container metadata endpoints",
		Long:  ``,
		RunE:  diagnoseMetadataAvailabilityCommand.RunE, // default to 'diagnose metadata-availability'
	}
	diagnoseCommand.AddCommand(diagnoseMetadataAvailabilityCommand)
	diagnoseCommand.AddCommand(diagnoseDatadogConnectivityCommand)

	return []*cobra.Command{diagnoseCommand}
}

func configAndLogSetup(cliParams *cliParams) error {
	// Global config setup
	err := common.SetupConfig(cliParams.confFilePath)
	if err != nil {
		return fmt.Errorf("unable to set up global agent configuration: %v", err)
	}

	// log level is always off since this might be use by other agent to get the hostname
	err = config.SetupLogger(config.CoreLoggerName, config.GetEnvDefault("DD_LOG_LEVEL", "info"), "", "", false, true, false)

	if err != nil {
		return fmt.Errorf("error while setting up logging, exiting: %v", err)
	}

	return nil
}

func runAll(cliParams *cliParams) error {
	if err := configAndLogSetup(cliParams); err != nil {
		return err
	}

	return diagnose.RunAll(color.Output)
}

func runDatadogConnectivityDiagnose(cliParams *cliParams) error {
	if err := configAndLogSetup(cliParams); err != nil {
		return err
	}

	return connectivity.RunDatadogConnectivityDiagnose(color.Output, cliParams.noTrace)
}
