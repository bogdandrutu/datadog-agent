// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package filter

import (
	"fmt"
	"reflect"
	"syscall"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"

	"github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// AFPacketSource provides a RAW_SOCKET attached to an eBPF SOCKET_FILTER
type AFPacketSource struct {
	*afpacket.TPacket
	socketFilter *manager.Probe

	exit chan struct{}

	// telemetry
	metricGroup *telemetry.MetricGroup
	polls       *telemetry.Metric
	processed   *telemetry.Metric
	captured    *telemetry.Metric
	dropped     *telemetry.Metric
}

func NewPacketSource(filter *manager.Probe, bpfFilter []bpf.RawInstruction) (*AFPacketSource, error) {
	rawSocket, err := afpacket.NewTPacket(
		afpacket.OptPollTimeout(1*time.Second),
		// This setup will require ~4Mb that is mmap'd into the process virtual space
		// More information here: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
		afpacket.OptFrameSize(4096),
		afpacket.OptBlockSize(4096*128),
		afpacket.OptNumBlocks(8),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating raw socket: %s", err)
	}

	if filter != nil {
		// The underlying socket file descriptor is private, hence the use of reflection
		// Point socket filter program to the RAW_SOCKET file descriptor
		// Note the filter attachment itself is triggered by the ebpf.Manager
		filter.SocketFD = int(reflect.ValueOf(rawSocket).Elem().FieldByName("fd").Int())
	} else {
		err = rawSocket.SetBPF(bpfFilter)
		if err != nil {
			return nil, fmt.Errorf("error setting classic bpf filter: %w", err)
		}
	}

	metricGroup := telemetry.NewMetricGroup("dns", telemetry.OptMonotonic, telemetry.OptExpvar)
	ps := &AFPacketSource{
		TPacket:      rawSocket,
		socketFilter: filter,
		exit:         make(chan struct{}),
		// Telemetry
		metricGroup: metricGroup,
		polls:       metricGroup.NewMetric("socket_polls"),
		processed:   metricGroup.NewMetric("packets_processed", telemetry.OptTelemetry),
		captured:    metricGroup.NewMetric("packets_captured"),
		dropped:     metricGroup.NewMetric("packets_dropped", telemetry.OptTelemetry),
	}
	go ps.pollStats()

	return ps, nil
}

func (p *AFPacketSource) Stats() map[string]int64 {
	return p.metricGroup.Summary()
}

func (p *AFPacketSource) VisitPackets(exit <-chan struct{}, visit func([]byte, time.Time) error) error {
	for {
		// allow the read loop to be prematurely interrupted
		select {
		case <-exit:
			return nil
		default:
		}

		data, stats, err := p.ZeroCopyReadPacketData()

		// Immediately retry for EAGAIN
		if err == syscall.EAGAIN {
			continue
		}

		if err == afpacket.ErrTimeout {
			return nil
		}

		if err != nil {
			return err
		}

		if err := visit(data, stats.Timestamp); err != nil {
			return err
		}
	}
}

func (p *AFPacketSource) PacketType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}

func (p *AFPacketSource) Close() {
	p.metricGroup.Clear()
	close(p.exit)
	p.TPacket.Close()
}

func (p *AFPacketSource) pollStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var (
		prevPolls     int64
		prevProcessed int64
		prevCaptured  int64
		prevDropped   int64
	)

	for {
		select {
		case <-ticker.C:
			sourceStats, _ := p.TPacket.Stats()            // off TPacket
			_, socketStats, err := p.TPacket.SocketStats() // off TPacket
			if err != nil {
				log.Errorf("error polling socket stats: %s", err)
				continue
			}

			p.polls.Add(sourceStats.Polls - prevPolls)
			p.processed.Add(sourceStats.Packets - prevProcessed)
			p.captured.Add(int64(socketStats.Packets()) - prevCaptured)
			p.dropped.Add(int64(socketStats.Drops()) - prevDropped)

			prevPolls = sourceStats.Polls
			prevProcessed = sourceStats.Packets
			prevCaptured = int64(socketStats.Packets())
			prevDropped = int64(socketStats.Drops())
		case <-p.exit:
			return
		}
	}
}
