// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package seelog

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/comp/core/config"
)

const logDateFormat = "2006-01-02 15:04:05 MST" // see time.Format for format syntax

var syslogTLSConfig *tls.Config

// LoggerName is the name of a logger
type LoggerName string

// ValidateLogLevel validates a log-level string and returns the selected value.
func ValidateLogLevel(logLevel string) (string, error) {
	seelogLogLevel := strings.ToLower(logLevel)
	if seelogLogLevel == "warning" { // Common gotcha when used to agent5
		seelogLogLevel = "warn"
	}

	if _, found := seelog.LogLevelFromString(seelogLogLevel); !found {
		return "", fmt.Errorf("unknown log level: %s", seelogLogLevel)
	}
	return seelogLogLevel, nil
}

// buildCommonFormat returns the log common format seelog string
func buildCommonFormat(config config.Component, loggerName LoggerName) string {
	if loggerName == "JMXFETCH" {
		return `%Msg%n`
	}
	return fmt.Sprintf("%%Date(%s) | %s | %%LEVEL | (%%ShortFilePath:%%Line in %%FuncShort) | %%ExtraTextContext%%Msg%%n", getLogDateFormat(config), loggerName)
}

func getLogDateFormat(config config.Component) string {
	if config.GetBool("log_format_rfc3339") {
		return time.RFC3339
	}
	return logDateFormat
}

func createQuoteMsgFormatter(params string) seelog.FormatterFunc {
	return func(message string, level seelog.LogLevel, context seelog.LogContextInterface) interface{} {
		return strconv.Quote(message)
	}
}

// buildJSONFormat returns the log JSON format seelog string
func buildJSONFormat(config config.Component, loggerName LoggerName) string {
	seelog.RegisterCustomFormatter("QuoteMsg", createQuoteMsgFormatter) //nolint:errcheck
	if loggerName == "JMXFETCH" {
		return `{"msg":%QuoteMsg}%n`
	}
	return fmt.Sprintf(`{"agent":"%s","time":"%%Date(%s)","level":"%%LEVEL","file":"%%ShortFilePath","line":"%%Line","func":"%%FuncShort","msg":%%QuoteMsg%%ExtraJSONContext}%%n`, strings.ToLower(string(loggerName)), getLogDateFormat(config))
}

func getSyslogTLSKeyPair(config config.Component) (*tls.Certificate, error) {
	var syslogTLSKeyPair *tls.Certificate
	if config.IsSet("syslog_pem") && config.IsSet("syslog_key") {
		cert := config.GetString("syslog_pem")
		key := config.GetString("syslog_key")

		if cert == "" && key == "" {
			return nil, nil
		} else if cert == "" || key == "" {
			return nil, fmt.Errorf("Both a PEM certificate and key must be specified to enable TLS")
		}

		keypair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}

		syslogTLSKeyPair = &keypair
	}

	return syslogTLSKeyPair, nil
}

// BuildLoggerConfig builds a Config object from the arguments.
func BuildLoggerConfig(config config.Component, loggerName LoggerName, seelogLogLevel, logFile, syslogURI string, syslogRFC, logToConsole, jsonFormat bool) (*Config, error) {
	formatID := "common"
	if jsonFormat {
		formatID = "json"
	}

	slCfg := NewSeelogConfig(string(loggerName), seelogLogLevel, formatID, buildJSONFormat(config, loggerName), buildCommonFormat(config, loggerName), syslogRFC)
	slCfg.EnableConsoleLog(logToConsole)
	slCfg.EnableFileLogging(logFile, config.GetSizeInBytes("log_file_max_size"), uint(config.GetInt("log_file_max_rolls")))

	if syslogURI != "" { // non-blank uri enables syslog
		syslogTLSKeyPair, err := getSyslogTLSKeyPair(config)
		if err != nil {
			return nil, err
		}
		var useTLS bool
		if syslogTLSKeyPair != nil {
			useTLS = true
			syslogTLSConfig = &tls.Config{
				Certificates:       []tls.Certificate{*syslogTLSKeyPair},
				InsecureSkipVerify: config.GetBool("syslog_tls_verify"),
			}
		}
		slCfg.ConfigureSyslog(syslogURI, useTLS)
	}
	return slCfg, nil
}

// GenerateLoggerInterface return a logger Interface from a log config
func GenerateLoggerInterface(logConfig *Config) (seelog.LoggerInterface, error) {
	configTemplate, err := logConfig.Render()
	if err != nil {
		return nil, err
	}

	loggerInterface, err := seelog.LoggerFromConfigAsString(configTemplate)
	if err != nil {
		return nil, err
	}

	return loggerInterface, nil
}
