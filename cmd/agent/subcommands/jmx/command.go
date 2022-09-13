// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build jmx
// +build jmx

// Package jmx implement an agent sub-command.
package jmx

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/cmd/internal/standalone"
	"github.com/DataDog/datadog-agent/pkg/collector"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

type cliParams struct {
	// command is the jmx console command to run
	command string

	// confFilePath is the value of the --cfgpath flag.
	confFilePath string

	cliSelectedChecks     []string
	jmxLogLevel           string
	saveFlare             bool
	discoveryTimeout      uint
	discoveryMinInstances uint
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalArgs *command.GlobalArgs) []*cobra.Command {
	cliParams := &cliParams{}
	var discoveryRetryInterval uint
	jmxCmd := &cobra.Command{
		Use:   "jmx",
		Short: "Run troubleshooting commands on JMXFetch integrations",
		Long:  ``,
	}
	jmxCmd.PersistentFlags().StringVarP(&cliParams.jmxLogLevel, "log-level", "l", "", "set the log level (default 'debug') (deprecated, use the env var DD_LOG_LEVEL instead)")
	jmxCmd.PersistentFlags().UintVarP(&cliParams.discoveryTimeout, "discovery-timeout", "", 5, "max retry duration until Autodiscovery resolves the check template (in seconds)")
	jmxCmd.PersistentFlags().UintVarP(&discoveryRetryInterval, "discovery-retry-interval", "", 1, "(unused)")
	jmxCmd.PersistentFlags().UintVarP(&cliParams.discoveryMinInstances, "discovery-min-instances", "", 1, "minimum number of config instances to be discovered before running the check(s)")

	jmxCollectCmd := &cobra.Command{
		Use:   "collect",
		Short: "Start the collection of metrics based on your current configuration and display them in the console.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "collect"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}
	jmxCollectCmd.PersistentFlags().StringSliceVar(&cliParams.cliSelectedChecks, "checks", []string{}, "JMX checks (ex: jmx,tomcat)")
	jmxCollectCmd.PersistentFlags().BoolVarP(&cliParams.saveFlare, "flare", "", false, "save jmx list results to the log dir so it may be reported in a flare")
	jmxCmd.AddCommand(jmxCollectCmd)

	jmxListEverythingCmd := &cobra.Command{
		Use:   "everything",
		Short: "List every attributes available that has a type supported by JMXFetch.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "list_everything"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}

	jmxListMatchingCmd := &cobra.Command{
		Use:   "matching",
		Short: "List attributes that match at least one of your instances configuration.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "list_matching_attributes"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}

	jmxListWithMetricsCmd := &cobra.Command{
		Use:   "with-metrics",
		Short: "List attributes and metrics data that match at least one of your instances configuration.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "list_with_metrics"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}

	jmxListWithRateMetricsCmd := &cobra.Command{
		Use:   "with-rate-metrics",
		Short: "List attributes and metrics data that match at least one of your instances configuration, including rates and counters.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "list_with_rate_metrics"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}

	jmxListLimitedCmd := &cobra.Command{
		Use:   "limited",
		Short: "List attributes that do match one of your instances configuration but that are not being collected because it would exceed the number of metrics that can be collected.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "list_limited_attributes"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}

	jmxListCollectedCmd := &cobra.Command{
		Use:   "collected",
		Short: "List attributes that will actually be collected by your current instances configuration.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "list_collected_attributes"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}

	jmxListNotMatchingCmd := &cobra.Command{
		Use:   "not-matching",
		Short: "List attributes that don’t match any of your instances configuration.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			cliParams.command = "list_not_matching_attributes"
			return fxutil.OneShot(runJmxCommandConsole,
				fx.Supply(cliParams),
			)
		},
	}

	jmxListCmd := &cobra.Command{
		Use:   "list",
		Short: "List attributes matched by JMXFetch.",
		Long:  ``,
	}
	jmxListCmd.AddCommand(
		jmxListEverythingCmd,
		jmxListMatchingCmd,
		jmxListLimitedCmd,
		jmxListCollectedCmd,
		jmxListNotMatchingCmd,
		jmxListWithMetricsCmd,
		jmxListWithRateMetricsCmd,
	)

	jmxListCmd.PersistentFlags().StringSliceVar(&cliParams.cliSelectedChecks, "checks", []string{}, "JMX checks (ex: jmx,tomcat)")
	jmxListCmd.PersistentFlags().BoolVarP(&cliParams.saveFlare, "flare", "", false, "save jmx list results to the log dir so it may be reported in a flare")
	jmxCmd.AddCommand(jmxListCmd)

	// attach the command to the root
	return []*cobra.Command{jmxCmd}
}

// runJmxCommandConsole sets up the common utils necessary for JMX, and executes the command
// with the Console reporter
func runJmxCommandConsole(cliParams *cliParams) error {
	logFile := ""
	if cliParams.saveFlare {
		// Windows cannot accept ":" in file names
		filenameSafeTimeStamp := strings.ReplaceAll(time.Now().UTC().Format(time.RFC3339), ":", "-")
		logFile = filepath.Join(common.DefaultJMXFlareDirectory, "jmx_"+cliParams.command+"_"+filenameSafeTimeStamp+".log")
		cliParams.jmxLogLevel = "debug"
	}

	logLevel, _, err := standalone.SetupCLI(
		config.CoreLoggerName, cliParams.confFilePath, "", logFile,
		cliParams.jmxLogLevel, "debug")
	if err != nil {
		fmt.Printf("Cannot initialize command: %v\n", err)
		return err
	}

	err = config.SetupJMXLogger(logFile, "", false, true, false)
	if err != nil {
		return fmt.Errorf("Unable to set up JMX logger: %v", err)
	}

	common.LoadComponents(context.Background(), config.Datadog.GetString("confd_path"))

	// Create the CheckScheduler, but do not attach it to
	// AutoDiscovery.  NOTE: we do not start common.Coll, either.
	collector.InitCheckScheduler(common.Coll)

	// Note: when no checks are selected, cliSelectedChecks will be the empty slice and thus
	//       WaitForConfigsFromAD will timeout and return no AD configs.
	waitCtx, cancelTimeout := context.WithTimeout(
		context.Background(), time.Duration(cliParams.discoveryTimeout)*time.Second)
	allConfigs := common.WaitForConfigsFromAD(waitCtx, cliParams.cliSelectedChecks, int(cliParams.discoveryMinInstances))
	cancelTimeout()

	err = standalone.ExecJMXCommandConsole(cliParams.command, cliParams.cliSelectedChecks, logLevel, allConfigs)

	if runtime.GOOS == "windows" {
		standalone.PrintWindowsUserWarning("jmx")
	}

	return err
}
