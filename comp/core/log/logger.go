// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import (
	"go.uber.org/fx"

	"github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/internal"
	seelogCfg "github.com/DataDog/datadog-agent/comp/core/log/internal/seelog"
)

// TODO: scrubbing
// TODO: interop with pkg/util/log (can we steal its LoggerInterface?)
// TODO: provide a way for config to log about issues (unknown keys, unknown env vars, etc.)

type logger struct {
	// embedding LoggerInterface gets all of the Foo and Foof methods
	// for Component, as well as Flush.
	seelog.LoggerInterface
}

type dependencies struct {
	fx.In

	Params internal.BundleParams
	Config config.Component
}

func newLogger(deps dependencies) (Component, error) {
	loggerName := deps.Params.LoggerName

	level, err := seelogCfg.ValidateLogLevel(deps.Config.GetString("log_level"))
	if err != nil {
		return nil, err
	}

	var logFile string
	if deps.Params.LogFileCfg != "" {
		logFile = deps.Config.GetString(deps.Params.LogFileCfg)
	}

	var syslogURI string
	var syslogRFC bool
	if deps.Params.LogToSyslog {
		syslogURI = getSyslogURI(deps.Config)
		syslogRFC = deps.Config.GetBool("syslog_rfc")
	}

	var logToConsole bool
	if deps.Params.ForceLogToConsole {
		logToConsole = true
	} else {
		logToConsole = deps.Config.GetBool("log_to_console")
	}

	jsonFormat := deps.Config.GetBool("log_format_json")

	cfg, err := seelogCfg.BuildLoggerConfig(deps.Config, seelogCfg.LoggerName(loggerName), level, logFile, syslogURI, syslogRFC, logToConsole, jsonFormat)
	if err != nil {
		return nil, err
	}

	iface, err := seelogCfg.GenerateLoggerInterface(cfg)
	if err != nil {
		return nil, err
	}

	return &logger{
		LoggerInterface: iface,
	}, nil
}
