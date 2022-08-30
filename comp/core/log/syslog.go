// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import (
	"runtime"

	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const defaultSyslogURI string = "unixgram:///dev/log"

// getSyslogURI returns the configured/default syslog uri.
// Returns an empty string when syslog is disabled.
func getSyslogURI(config config.Component) string {
	enabled := config.GetBool("log_to_syslog")
	uri := config.GetString("syslog_uri")

	if enabled && runtime.GOOS == "windows" {
		log.Infof("logging to syslog is not available on windows.")
	}

	if !enabled {
		return ""
	}

	if uri == "" {
		return defaultSyslogURI
	}

	return uri
}
