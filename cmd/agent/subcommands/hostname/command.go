// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package hostname implement an agent sub-command.
package hostname

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/hostname"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	// confFilePath is the value of the --cfgpath flag.
	confFilePath string
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalArgs *command.GlobalArgs) []*cobra.Command {
	getHostnameCommand := &cobra.Command{
		Use:   "hostname",
		Short: "Print the hostname used by the Agent",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(getHostname,
				fx.Supply(&cliParams{
					confFilePath: globalArgs.ConfFilePath,
				}),
			)
		},
	}

	return []*cobra.Command{getHostnameCommand}
}

func getHostname(cliParams *cliParams) error {
	err := common.SetupConfigWithoutSecrets(cliParams.confFilePath, "")
	if err != nil {
		return fmt.Errorf("unable to set up global agent configuration: %v", err)
	}

	// log level is always off since this might be use by other agent to get the hostname
	err = config.SetupLogger(config.CoreLoggerName, "off", "", "", false, true, false)
	if err != nil {
		fmt.Printf("Cannot setup logger, exiting: %v\n", err)
		return err
	}

	hname, err := hostname.Get(context.TODO())
	if err != nil {
		return fmt.Errorf("Error getting the hostname: %v", err)
	}

	fmt.Println(hname)
	return nil
}
