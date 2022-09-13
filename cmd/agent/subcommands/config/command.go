// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package config implement an agent sub-command.
package config

import (
	"fmt"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"

	"github.com/spf13/cobra"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	// args are the positional command line args
	args []string

	// confFilePath is the value of the --cfgpath flag.
	confFilePath string
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalArgs *command.GlobalArgs) []*cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Print the runtime configuration of a running agent",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(showRuntimeConfiguration,
				fx.Supply(&cliParams{
					args:         args,
					confFilePath: globalArgs.ConfFilePath,
				}),
			)
		},
	}

	listRuntimeCmd := &cobra.Command{
		Use:   "list-runtime",
		Short: "List settings that can be changed at runtime",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(listRuntimeConfigurableValue,
				fx.Supply(&cliParams{
					args:         args,
					confFilePath: globalArgs.ConfFilePath,
				}),
			)
		},
	}
	cmd.AddCommand(listRuntimeCmd)

	setCmd := &cobra.Command{
		Use:   "set [setting] [value]",
		Short: "Set, for the current runtime, the value of a given configuration setting",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(setConfigValue,
				fx.Supply(&cliParams{
					args:         args,
					confFilePath: globalArgs.ConfFilePath,
				}),
			)
		},
	}
	cmd.AddCommand(setCmd)

	getCmd := &cobra.Command{
		Use:   "get [setting]",
		Short: "Get, for the current runtime, the value of a given configuration setting",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(getConfigValue,
				fx.Supply(&cliParams{
					args:         args,
					confFilePath: globalArgs.ConfFilePath,
				}),
			)
		},
	}
	cmd.AddCommand(getCmd)

	return []*cobra.Command{cmd}
}

// setupConfigAndLogs is a utility function to set up logging and config, and
// initialize the IPC auth token, shared between 'agent config' subcommands.
func setupConfigAndLogs(cliParams *cliParams) error {
	err := common.SetupConfigWithoutSecrets(cliParams.confFilePath, "")
	if err != nil {
		return fmt.Errorf("unable to set up global agent configuration: %v", err)
	}

	err = config.SetupLogger(config.CoreLoggerName, config.GetEnvDefault("DD_LOG_LEVEL", "off"), "", "", false, true, false)
	if err != nil {
		fmt.Printf("Cannot setup logger, exiting: %v\n", err)
		return err
	}

	util.SetAuthToken()

	return nil
}

func showRuntimeConfiguration(cliParams *cliParams) error {
	if err := setupConfigAndLogs(cliParams); err != nil {
		return err
	}
	c, err := common.NewSettingsClient()
	if err != nil {
		return err
	}

	runtimeConfig, err := c.FullConfig()
	if err != nil {
		return err
	}

	fmt.Println(runtimeConfig)

	return nil
}

func listRuntimeConfigurableValue(cliParams *cliParams) error {
	if err := setupConfigAndLogs(cliParams); err != nil {
		return err
	}
	c, err := common.NewSettingsClient()
	if err != nil {
		return err
	}

	settingsList, err := c.List()
	if err != nil {
		return err
	}

	fmt.Println("=== Settings that can be changed at runtime ===")
	for setting, details := range settingsList {
		if !details.Hidden {
			fmt.Printf("%-30s %s\n", setting, details.Description)
		}
	}

	return nil
}

func setConfigValue(cliParams *cliParams) error {
	if len(cliParams.args) != 2 {
		return fmt.Errorf("exactly two parameters are required: the setting name and its value")
	}

	if err := setupConfigAndLogs(cliParams); err != nil {
		return err
	}

	c, err := common.NewSettingsClient()
	if err != nil {
		return err
	}

	hidden, err := c.Set(cliParams.args[0], cliParams.args[1])
	if err != nil {
		return err
	}

	if hidden {
		fmt.Printf("IMPORTANT: you have modified a hidden option, this may incur billing charges or have other unexpected side-effects.\n")
	}

	fmt.Printf("Configuration setting %s is now set to: %s\n", cliParams.args[0], cliParams.args[1])

	return nil
}

func getConfigValue(cliParams *cliParams) error {
	if len(cliParams.args) != 1 {
		return fmt.Errorf("a single setting name must be specified")
	}

	if err := setupConfigAndLogs(cliParams); err != nil {
		return err
	}

	c, err := common.NewSettingsClient()
	if err != nil {
		return err
	}

	value, err := c.Get(cliParams.args[0])
	if err != nil {
		return err
	}

	fmt.Printf("%s is set to: %v\n", cliParams.args[0], value)

	return nil
}
