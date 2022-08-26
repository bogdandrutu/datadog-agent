// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/internal"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// isConfigTest is set if a test in this package's test suite is running
var isConfigTest bool

// cfg implements the Component.
type cfg struct {
	// this component is currently implementing a thin wrapper around pkg/config.
	inner config.Config
}

type dependencies struct {
	fx.In

	Params internal.BundleParams
}

func newConfig(deps dependencies) Component {
	if fxutil.IsTest && !isConfigTest {
		panic("do not use the real comp/core/config component in tests")
	}
	if config.Datadog == nil {
		panic("pkg/config must be initialized first")
	}
	return &cfg{
		inner: config.Datadog,
	}
}

func (c *cfg) IsSet(key string) bool                { return c.inner.IsSet(key) }
func (c *cfg) Get(key string) interface{}           { return c.inner.Get(key) }
func (c *cfg) GetString(key string) string          { return c.inner.GetString(key) }
func (c *cfg) GetBool(key string) bool              { return c.inner.GetBool(key) }
func (c *cfg) GetInt(key string) int                { return c.inner.GetInt(key) }
func (c *cfg) GetInt32(key string) int32            { return c.inner.GetInt32(key) }
func (c *cfg) GetInt64(key string) int64            { return c.inner.GetInt64(key) }
func (c *cfg) GetFloat64(key string) float64        { return c.inner.GetFloat64(key) }
func (c *cfg) GetTime(key string) time.Time         { return c.inner.GetTime(key) }
func (c *cfg) GetDuration(key string) time.Duration { return c.inner.GetDuration(key) }
func (c *cfg) GetStringSlice(key string) []string   { return c.inner.GetStringSlice(key) }
func (c *cfg) GetFloat64SliceE(key string) ([]float64, error) {
	return c.inner.GetFloat64SliceE(key)
}
func (c *cfg) GetStringMap(key string) map[string]interface{} { return c.inner.GetStringMap(key) }
func (c *cfg) GetStringMapString(key string) map[string]string {
	return c.inner.GetStringMapString(key)
}
func (c *cfg) GetStringMapStringSlice(key string) map[string][]string {
	return c.inner.GetStringMapStringSlice(key)
}
func (c *cfg) GetSizeInBytes(key string) uint      { return c.inner.GetSizeInBytes(key) }
func (c *cfg) AllSettings() map[string]interface{} { return c.inner.AllSettings() }
func (c *cfg) AllSettingsWithoutDefault() map[string]interface{} {
	return c.inner.AllSettingsWithoutDefault()
}
func (c *cfg) AllKeys() []string                    { return c.inner.AllKeys() }
func (c *cfg) GetKnownKeys() map[string]interface{} { return c.inner.GetKnownKeys() }
func (c *cfg) GetEnvVars() []string                 { return c.inner.GetEnvVars() }
func (c *cfg) IsSectionSet(section string) bool     { return c.inner.IsSectionSet(section) }

type mock struct {
	cfg
	old config.Config
}

func newMock(deps dependencies, t testing.TB) Component {
	c := &mock{
		cfg: cfg{
			inner: config.NewConfig("mock", "XXXX", strings.NewReplacer()),
		},
		old: config.Datadog,
	}

	// call InitConfig to set defaults.
	config.InitConfig(c.cfg.inner)

	// Viper's `GetXxx` methods read environment variables at the time they are
	// called, if those names were passed explicitly to BindEnv*(), so we must
	// also strip all `DD_` environment variables for the duration of the test.
	oldEnv := os.Environ()
	for _, kv := range oldEnv {
		if strings.HasPrefix(kv, "DD_") {
			kvslice := strings.SplitN(kv, "=", 2)
			os.Unsetenv(kvslice[0])
		}
	}
	t.Cleanup(func() {
		for _, kv := range oldEnv {
			kvslice := strings.SplitN(kv, "=", 2)
			os.Setenv(kvslice[0], kvslice[1])
		}
	})

	// swap this new, blank config for config.Datadog, and swap it back at the
	// end of the test
	config.Datadog = c.cfg.inner
	t.Cleanup(func() { config.Datadog = c.old })

	return c
}

func (c *cfg) Set(key string, value interface{}) { c.inner.(Mock).Set(key, value) }
