// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package fxutil

import (
	"context"

	"go.uber.org/fx"
)

// OneShot runs the given function in an fx.App using the supplied options.
// The function's arguments are supplied by Fx and can be any provided type.
// The function must return `error` or nothing.
//
// The resulting app starts all components, then invokes the function, then
// immediately shuts down.  This is typically used for command-line tools like
// `agent status`.
func OneShot(oneShotFunc interface{}, opts ...fx.Option) error {
	delayedCall := newDelayedFxInvocation(oneShotFunc)

	opts = append(opts,
		delayedCall.option(),
		fxLoggingOption(),
	)
	app := fx.New(opts...)

	// start the app
	startCtx, cancel := context.WithTimeout(context.Background(), app.StartTimeout())
	defer cancel()
	if err := app.Start(startCtx); err != nil {
		return err
	}

	// call the original oneShotFunc with the args captured during app startup
	err := delayedCall.call()
	if err != nil {
		return err
	}

	// stop the app
	stopCtx, cancel := context.WithTimeout(context.Background(), app.StopTimeout())
	defer cancel()
	if err := app.Stop(stopCtx); err != nil {
		return err
	}

	return nil
}
