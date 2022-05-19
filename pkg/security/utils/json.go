// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package utils

import (
	"github.com/mailru/easyjson"
	"github.com/mailru/easyjson/jwriter"
)

func EasyjsonMarshal(v easyjson.Marshaler) ([]byte, error) {
	w := jwriter.Writer{
		Flags: jwriter.NilSliceAsEmpty | jwriter.NilMapAsEmpty,
	}

	v.MarshalEasyJSON(&w)
	return w.BuildBytes()
}