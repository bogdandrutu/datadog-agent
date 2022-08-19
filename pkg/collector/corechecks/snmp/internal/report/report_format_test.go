// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package report

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/snmp/internal/valuestore"
)

func Test_formatValue(t *testing.T) {
	tests := []struct {
		name          string
		value         valuestore.ResultValue
		format        string
		expectedValue valuestore.ResultValue
		expectedError string
	}{
		{
			name: "format mac address",
			value: valuestore.ResultValue{
				Value: []byte{0x82, 0xa5, 0x6e, 0xa5, 0xc8, 0x01},
			},
			format: "mac_address",
			expectedValue: valuestore.ResultValue{
				Value: "82:a5:6e:a5:c8:01",
			},
		},
		{
			name: "error unknown value type",
			value: valuestore.ResultValue{
				Value: valuestore.ResultValue{},
			},
			format:        "mac_address",
			expectedError: "value type `valuestore.ResultValue` not supported (format `mac_address`)",
		},
		{
			name: "error unknown format type",
			value: valuestore.ResultValue{
				Value: []byte{0x82, 0xa5, 0x6e, 0xa5, 0xc8, 0x01},
			},
			format:        "unknown_format",
			expectedError: "unknown format `unknown_format` (value type `[]uint8`)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := FormatValue(tt.value, tt.format)
			assert.Equal(t, tt.expectedValue, value)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			}
		})
	}
}
