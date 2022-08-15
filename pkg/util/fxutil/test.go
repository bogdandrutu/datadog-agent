// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package fxutil

import (
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

// IsTest is true if this is a test run.  This will always be false in
// "real" binaries.
//
// This can be used to ensure that undesirable behavior such as reporting
// metrics or accessing on-disk configuration files does not occur during
// tests.
var IsTest bool

// Test runs a test case within an fx.App.
//
// The given function is called after the app's startup has completed, with its
// arguments filled via Fx's depedency injection.  fxutil.IsTest is set for the
// duration of the function call.  Within the app, `t` is provided as type
// `testing.TB`.
//
// Use `fx.Options(..)` to bundle multiple fx.Option values into one.
func Test(t testing.TB, opts fx.Option, fn interface{}) {
	IsTest = true
	defer func() { IsTest = false }()

	delayed := newDelayedFxInvocation(fn)
	app := fxtest.New(
		t,
		fx.Supply(fx.Annotate(t, fx.As(new(testing.TB)))),
		delayed.option(),
		opts,
	)
	defer app.RequireStart().RequireStop()

	if err := delayed.call(); err != nil {
		t.Fatal(err.Error())
	}
}
