// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package secret implement an agent sub-command.
package secret

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/secrets"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	// confFilePath is the value of the --cfgpath flag.
	confFilePath string
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalArgs *command.GlobalArgs) []*cobra.Command {
	secretInfoCommand := &cobra.Command{
		Use:   "secret",
		Short: "Print information about decrypted secrets in configuration.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(secret,
				fx.Supply(&cliParams{
					confFilePath: globalArgs.ConfFilePath,
				}),
			)
		},
	}

	return []*cobra.Command{secretInfoCommand}
}

func secret(cliParams *cliParams) error {
	err := common.SetupConfigWithoutSecrets(cliParams.confFilePath, "")
	if err != nil {
		fmt.Printf("unable to set up global agent configuration: %v\n", err)
		return nil
	}

	err = config.SetupLogger(config.CoreLoggerName, config.GetEnvDefault("DD_LOG_LEVEL", "off"), "", "", false, true, false)
	if err != nil {
		fmt.Printf("Cannot setup logger, exiting: %v\n", err)
		return err
	}

	if err := util.SetAuthToken(); err != nil {
		fmt.Println(err)
		return nil
	}

	if err := showSecretInfo(); err != nil {
		fmt.Println(err)
		return nil
	}
	return nil
}

func showSecretInfo() error {
	c := util.GetClient(false)
	ipcAddress, err := config.GetIPCAddress()
	if err != nil {
		return err
	}
	apiConfigURL := fmt.Sprintf("https://%v:%v/agent/secrets", ipcAddress, config.Datadog.GetInt("cmd_port"))

	r, err := util.DoGet(c, apiConfigURL, util.LeaveConnectionOpen)
	if err != nil {
		var errMap = make(map[string]string)
		json.Unmarshal(r, &errMap) //nolint:errcheck
		// If the error has been marshalled into a json object, check it and return it properly
		if e, found := errMap["error"]; found {
			return fmt.Errorf("%s", e)
		}

		return fmt.Errorf("Could not reach agent: %v\nMake sure the agent is running before requesting the runtime configuration and contact support if you continue having issues", err)
	}

	info := &secrets.SecretInfo{}
	err = json.Unmarshal(r, info)
	if err != nil {
		return fmt.Errorf("Could not Unmarshal agent answer: %s", r)
	}
	info.Print(os.Stdout)
	return nil
}
