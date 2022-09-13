// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package status implement an agent sub-command.
package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/status"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/scrubber"

	"github.com/spf13/cobra"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	// confFilePath is the value of the --cfgpath flag.
	confFilePath string

	// sysProbeConfFilePath is the value of the --sysprobecfgpath flag.
	sysProbeConfFilePath string

	// args are the positional command-line arguments
	args []string

	jsonStatus      bool
	prettyPrintJSON bool
	statusFilePath  string
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalArgs *command.GlobalArgs) []*cobra.Command {
	cliParams := &cliParams{}
	statusCmd := &cobra.Command{
		Use:   "status [component [name]]",
		Short: "Print the current status",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.confFilePath = globalArgs.ConfFilePath
			cliParams.sysProbeConfFilePath = globalArgs.SysProbeConfFilePath
			cliParams.args = args
			return fxutil.OneShot(statusCmd,
				fx.Supply(cliParams),
			)
		},
	}
	statusCmd.Flags().BoolVarP(&cliParams.jsonStatus, "json", "j", false, "print out raw json")
	statusCmd.Flags().BoolVarP(&cliParams.prettyPrintJSON, "pretty-json", "p", false, "pretty print JSON")
	statusCmd.Flags().StringVarP(&cliParams.statusFilePath, "file", "o", "", "Output the status command to a file")

	componentCmd := &cobra.Command{
		Use:   "component",
		Short: "Print the component status",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.confFilePath = globalArgs.ConfFilePath
			cliParams.sysProbeConfFilePath = globalArgs.SysProbeConfFilePath
			cliParams.args = args
			return fxutil.OneShot(componentStatusCmd,
				fx.Supply(cliParams),
			)
		},
	}
	componentCmd.Flags().BoolVarP(&cliParams.prettyPrintJSON, "pretty-json", "p", false, "pretty print JSON")
	componentCmd.Flags().StringVarP(&cliParams.statusFilePath, "file", "o", "", "Output the status command to a file")
	statusCmd.AddCommand(componentCmd)

	return []*cobra.Command{statusCmd}
}

func scrubMessage(message string) string {
	msgScrubbed, err := scrubber.ScrubBytes([]byte(message))
	if err == nil {
		return string(msgScrubbed)
	}
	return "[REDACTED] - failure to clean the message"
}

func redactError(unscrubbedError error) error {
	if unscrubbedError == nil {
		return unscrubbedError
	}

	errMsg := unscrubbedError.Error()
	scrubbedMsg, scrubOperationErr := scrubber.ScrubBytes([]byte(errMsg))
	var scrubbedError error
	if scrubOperationErr != nil {
		scrubbedError = errors.New("[REDACTED] failed to clean error")
	} else {
		scrubbedError = errors.New(string(scrubbedMsg))
	}

	return scrubbedError
}

func statusCmd(cliParams *cliParams) error {
	// Prevent autoconfig to run when running status as it logs before logger is setup
	// Cannot rely on config.Override as env detection is run before overrides are set
	os.Setenv("DD_AUTOCONFIG_FROM_ENVIRONMENT", "false")
	err := common.SetupConfigWithoutSecrets(cliParams.confFilePath, "")
	if err != nil {
		return fmt.Errorf("unable to set up global agent configuration: %v", err)
	}

	err = config.SetupLogger(config.CoreLoggerName, config.GetEnvDefault("DD_LOG_LEVEL", "off"), "", "", false, true, false)
	if err != nil {
		fmt.Printf("Cannot setup logger, exiting: %v\n", err)
		return err
	}

	_ = common.SetupSystemProbeConfig(cliParams.sysProbeConfFilePath)

	return redactError(requestStatus(cliParams))
}

func requestStatus(cliParams *cliParams) error {
	var s string

	if !cliParams.prettyPrintJSON && !cliParams.jsonStatus {
		fmt.Printf("Getting the status from the agent.\n\n")
	}
	ipcAddress, err := config.GetIPCAddress()
	if err != nil {
		return err
	}
	urlstr := fmt.Sprintf("https://%v:%v/agent/status", ipcAddress, config.Datadog.GetInt("cmd_port"))
	r, err := makeRequest(urlstr)
	if err != nil {
		return err
	}
	// attach trace-agent status, if obtainable
	temp := make(map[string]interface{})
	if err := json.Unmarshal(r, &temp); err == nil {
		temp["apmStats"] = getAPMStatus()
		if newr, err := json.Marshal(temp); err == nil {
			r = newr
		}
	}

	// The rendering is done in the client so that the agent has less work to do
	if cliParams.prettyPrintJSON {
		var prettyJSON bytes.Buffer
		json.Indent(&prettyJSON, r, "", "  ") //nolint:errcheck
		s = prettyJSON.String()
	} else if cliParams.jsonStatus {
		s = string(r)
	} else {
		formattedStatus, err := status.FormatStatus(r)
		if err != nil {
			return err
		}
		s = scrubMessage(formattedStatus)
	}

	if cliParams.statusFilePath != "" {
		ioutil.WriteFile(cliParams.statusFilePath, []byte(s), 0644) //nolint:errcheck
	} else {
		fmt.Println(s)
	}

	return nil
}

// getAPMStatus returns a set of key/value pairs summarizing the status of the trace-agent.
// If the status can not be obtained for any reason, the returned map will contain an "error"
// key with an explanation.
func getAPMStatus() map[string]interface{} {
	port := 8126
	if config.Datadog.IsSet("apm_config.receiver_port") {
		port = config.Datadog.GetInt("apm_config.receiver_port")
	}
	url := fmt.Sprintf("http://localhost:%d/debug/vars", port)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get(url)
	if err != nil {
		return map[string]interface{}{
			"port":  port,
			"error": err.Error(),
		}
	}
	defer resp.Body.Close()
	status := make(map[string]interface{})
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return map[string]interface{}{
			"port":  port,
			"error": err.Error(),
		}
	}
	return status
}

func componentStatusCmd(cliParams *cliParams) error {
	err := common.SetupConfigWithoutSecrets(cliParams.confFilePath, "")
	if err != nil {
		return fmt.Errorf("unable to set up global agent configuration: %v", err)
	}

	if len(cliParams.args) != 1 {
		return fmt.Errorf("a component name must be specified")
	}

	return redactError(componentStatus(cliParams, cliParams.args[0]))
}

func componentStatus(cliParams *cliParams, component string) error {
	var s string

	urlstr := fmt.Sprintf("https://localhost:%v/agent/%s/status", config.Datadog.GetInt("cmd_port"), component)

	r, err := makeRequest(urlstr)
	if err != nil {
		return err
	}

	// The rendering is done in the client so that the agent has less work to do
	if cliParams.prettyPrintJSON {
		var prettyJSON bytes.Buffer
		json.Indent(&prettyJSON, r, "", "  ") //nolint:errcheck
		s = prettyJSON.String()
	} else {
		s = scrubMessage(string(r))
	}

	if cliParams.statusFilePath != "" {
		ioutil.WriteFile(cliParams.statusFilePath, []byte(s), 0644) //nolint:errcheck
	} else {
		fmt.Println(s)
	}

	return nil
}

func makeRequest(url string) ([]byte, error) {
	var e error
	c := util.GetClient(false) // FIX: get certificates right then make this true

	// Set session token
	e = util.SetAuthToken()
	if e != nil {
		return nil, e
	}

	r, e := util.DoGet(c, url, util.LeaveConnectionOpen)
	if e != nil {
		var errMap = make(map[string]string)
		json.Unmarshal(r, &errMap) //nolint:errcheck
		// If the error has been marshalled into a json object, check it and return it properly
		if err, found := errMap["error"]; found {
			e = fmt.Errorf(err)
		}

		fmt.Printf("Could not reach agent: %v \nMake sure the agent is running before requesting the status and contact support if you continue having issues. \n", e)
		return nil, e
	}

	return r, nil

}
