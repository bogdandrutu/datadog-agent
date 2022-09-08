// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"debug/elf"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/DataDog/datadog-agent/pkg/network/http/gotls/lookup"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
	"os"
	"strconv"
	"strings"
)

const (
	probeDataMap     = "probe_data"
	goTLSReadArgsMap = "go_tls_read_args"

	writeFuncName      = "uprobe__crypto_tls_Conn_Write"
	readFuncName       = "uprobe__crypto_tls_Conn_Read"
	readReturnFuncName = "uprobe__crypto_tls_Conn_Read__return"
	closeFuncName      = "uprobe__crypto_tls_Conn_Close"

	writeProbe      = "uprobe/crypto/tls.(*Conn).Write"
	readProbe       = "uprobe/crypto/tls.(*Conn).Read"
	readReturnProbe = "uprobe/crypto/tls.(*Conn).Read/return"
	closeProbe      = "uprobe/crypto/tls.(*Conn).Close"
)

var functionsConfig = map[string]bininspect.FunctionConfiguration{
	bininspect.WriteGoTLSFunc: {
		IncludeReturnLocations: false,
		ParamLookupFunction:    lookup.GetWriteParams,
	},
	bininspect.ReadGoTLSFunc: {
		IncludeReturnLocations: true,
		ParamLookupFunction:    lookup.GetReadParams,
	},
	bininspect.CloseGoTLSFunc: {
		IncludeReturnLocations: false,
		ParamLookupFunction:    lookup.GetCloseParams,
	},
}

var structFieldsLookupFunctions = map[bininspect.FieldIdentifier]bininspect.StructLookupFunction{
	bininspect.StructOffsetTLSConn:     lookup.GetTLSConnInnerConnOffset,
	bininspect.StructOffsetTCPConn:     lookup.GetTCPConnInnerConnOffset,
	bininspect.StructOffsetNetConnFd:   lookup.GetConnFDOffset,
	bininspect.StructOffsetNetFdPfd:    lookup.GetNetFD_PFDOffset,
	bininspect.StructOffsetPollFdSysfd: lookup.GetFD_SysfdOffset,
}

type GoTLSProgram struct {
	manager  *manager.Manager
	probeIDs []manager.ProbeIdentificationPair
}

// Static evaluation to make sure we are not breaking the interface.
var _ subprogram = &GoTLSProgram{}

func newGoTLSProgram(c *config.Config) (*GoTLSProgram, error) {
	if !c.EnableHTTPSMonitoring {
		return nil, nil
	}
	return &GoTLSProgram{}, nil
}

func (p *GoTLSProgram) ConfigureManager(m *manager.Manager) {
	// TODO check if we support go TLS on the current arch
	if p == nil {
		return
	}

	p.manager = m
	p.manager.Maps = append(p.manager.Maps, []*manager.Map{
		{Name: probeDataMap},
		{Name: goTLSReadArgsMap},
	}...)
	// Hooks will be added in runtime for each binary
}

func (p *GoTLSProgram) ConfigureOptions(options *manager.Options) {}

func (p *GoTLSProgram) Start() {
	if p == nil {
		return
	}
	// In the future Start() should just initiate the new processes listener
	// and this implementation should be done for each new process found.

	binPath := os.Getenv("GO_TLS_TEST")
	p.handleNewBinary(binPath)

}

func (p *GoTLSProgram) handleNewBinary(binPath string) {
	f, err := os.Open(binPath)
	if err != nil {
		log.Errorf("could not open file %q due to %w", binPath, err)
		return
	}
	defer f.Close()
	elfFile, err := elf.NewFile(f)
	if err != nil {
		log.Errorf("file %q could not be parsed as elf: %w", binPath, err)
		return
	}
	result, err := bininspect.InspectNewProcessBinary(elfFile, functionsConfig, structFieldsLookupFunctions)
	if err != nil {
		log.Errorf("failed inspecting binary %q: %w", binPath, err)
		return
	}

	// result and bin path are being passed as parameters as a preparation for the future when we will have a process
	// watcher, so we will run on more than one binary in one goTLSProgram.
	p.addInspectionResultToMap(result, binPath)

	p.attachHooks(result, binPath)
}

// addInspectionResultToMap runs a binary inspection and adds the result to the map that's being read by the probes.
// It assumed the given path is from /proc dir and gets the pid from the path. It will fail otherwise.
func (p *GoTLSProgram) addInspectionResultToMap(result *bininspect.Result, binPath string) {
	probeData, err := inspectionResultToProbeData(result)
	if err != nil {
		log.Errorf("error while parsing inspection result: %w", err)
		return
	}
	dataMap, _, err := p.manager.GetMap(probeDataMap)
	if err != nil {
		log.Errorf("%q map not found: %w", probeDataMap, err)
		return
	}

	// Map key is the pid, so it will be identified in the probe as the relevant data
	splitPath := strings.Split(binPath, "/")
	if len(splitPath) != 4 {
		// parts should be "", "proc", "<pid>", "exe"
		log.Error("got an unexpected path format")
		return
	}
	pidStr := splitPath[2]
	pid, err := strconv.ParseInt(pidStr, 10, 32)
	if err != nil {
		log.Errorf("failed extracting pid number for binary %q: %w", binPath, err)
		return
	}
	err = dataMap.Put(uint32(pid), probeData)
	if err != nil {
		log.Errorf("failed writing binary inspection result to map for binary %q: %w", binPath, err)
		return
	}
}

func (p *GoTLSProgram) attachHooks(result *bininspect.Result, binPath string) {
	uid := getUID(binPath)
	attachFailed := false

	// Cleanup if failed
	defer func() {
		if attachFailed {
			p.detachHooks()
		}
	}()

	for i, offset := range result.Functions[bininspect.ReadGoTLSFunc].ReturnLocations {
		probeID := manager.ProbeIdentificationPair{
			EBPFSection:  readReturnProbe,
			EBPFFuncName: readReturnFuncName,
			UID:          makeReturnUID(uid, i),
		}
		err := p.manager.AddHook("", &manager.Probe{
			ProbeIdentificationPair: probeID,
			BinaryPath:              binPath,
			// Each return probe needs to have a unique uid value,
			// so add the index to the binary UID to make an overall UID.
			UprobeOffset: offset,
		})
		if err != nil {
			log.Errorf("could not add hook to read return in offset %d due to: %w", offset, err)
			attachFailed = true
			return
		}
		p.probeIDs = append(p.probeIDs, probeID)
	}

	probes := []*manager.Probe{
		{
			BinaryPath:   binPath,
			UprobeOffset: result.Functions[bininspect.WriteGoTLSFunc].EntryLocation,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  writeProbe,
				EBPFFuncName: writeFuncName,
				UID:          uid,
			},
		},
		{
			BinaryPath: binPath,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  readProbe,
				EBPFFuncName: readFuncName,
				UID:          uid,
			},
			UprobeOffset: result.Functions[bininspect.ReadGoTLSFunc].EntryLocation,
		},
		{
			BinaryPath: binPath,
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFSection:  closeProbe,
				EBPFFuncName: closeFuncName,
				UID:          uid,
			},
			UprobeOffset: result.Functions[bininspect.CloseGoTLSFunc].EntryLocation,
		},
	}

	for _, probe := range probes {
		err := p.manager.AddHook("", probe)
		if err != nil {
			log.Errorf("could not add hook for %q in offset %d due to: %w", probe.EBPFFuncName, probe.UprobeOffset, err)
			attachFailed = true
			return
		}
		p.probeIDs = append(p.probeIDs, probe.ProbeIdentificationPair)
	}
}

func (p *GoTLSProgram) detachHooks() {
	for _, probeID := range p.probeIDs {
		err := p.manager.DetachHook(probeID)
		if err != nil {
			log.Errorf("failed detaching hook %s: %w", probeID.UID, err)
		}
	}
}

func (p *GoTLSProgram) Stop() {
	if p == nil {
		return
	}
	// In the future, this should stop the new process listener.
	p.detachHooks()

}
