// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package classifier

import (
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/network/config"
)

//go:generate go run ../../../pkg/ebpf/include_headers.go ../../../pkg/network/ebpf/c/runtime/classifier.c ../../../pkg/ebpf/bytecode/build/runtime/classifier.c ../../../pkg/ebpf/c ../../../pkg/network/ebpf/c/runtime ../../../pkg/network/ebpf/c
//go:generate go run ../../../pkg/ebpf/bytecode/runtime/integrity.go ../../../pkg/ebpf/bytecode/build/runtime/classifier.c ../../../pkg/ebpf/bytecode/runtime/classifier.go runtime

func getRuntimeCompiledClassifier(config *config.Config) (runtime.CompiledOutput, error) {
	return runtime.Classifier.Compile(&config.Config, getCFlags(config))
}

func getCFlags(config *config.Config) []string {
	var cflags []string

	if config.CollectIPv6Conns {
		cflags = append(cflags, "-DFEATURE_IPV6_ENABLED")
	}
	if config.BPFDebug {
		cflags = append(cflags, "-DDEBUG=1")
	}
	return cflags
}
