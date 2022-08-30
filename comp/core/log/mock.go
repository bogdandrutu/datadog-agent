// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import (
	"testing"

	"github.com/cihub/seelog"
)

// tbWriter is an implementation of io.Writer that sends lines to
// testing.TB#Log.
type tbWriter struct {
	t testing.TB
}

// Write implements Writer#Write.
func (tbw *tbWriter) Write(p []byte) (n int, err error) {
	// this assumes that seelog always writes one log entry in one Write call
	tbw.t.Log(string(p))
	return len(p), nil
}

func newMockLogger(t testing.TB) (Component, error) {
	// Build a logger that only logs to t.Log(..)
	iface, err := seelog.LoggerFromWriterWithMinLevelAndFormat(&tbWriter{t}, seelog.TraceLvl,
		"%Date(2006-01-02 15:04:05 MST) | TEST | %LEVEL | (%ShortFilePath:%Line in %FuncShort) | %ExtraTextContext%Msg%n")
	if err != nil {
		return nil, err
	}

	return &logger{
		LoggerInterface: iface,
	}, nil
}
