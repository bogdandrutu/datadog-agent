// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package internal

// BundleParams defines the parameters for this bundle.
type BundleParams struct {
	// LoggerName is the name that appears in the logfile
	LoggerName string

	// LogFileCfg is the name of the config parameter giving the filename to
	// which logs should be written, or empty to disable writing to a file.
	LogFileCfg string

	// LogSyslog controls whether logs should be sent to syslog, if the necessary
	// configuration is in place.
	LogToSyslog bool

	// ForceLogToConsole determines whether log messages should be output to
	// the console.  If false then the config parmeter `log_to_console` is
	// consulted.
	ForceLogToConsole bool
}
