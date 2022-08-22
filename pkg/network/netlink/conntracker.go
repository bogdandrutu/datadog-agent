// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux && !android
// +build linux,!android

package netlink

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/hashicorp/golang-lru/simplelru"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

const (
	compactInterval      = time.Minute
	defaultOrphanTimeout = 2 * time.Minute
)

// Conntracker is a wrapper around go-conntracker that keeps a record of all connections in user space
type Conntracker interface {
	GetTranslationForConn(network.ConnectionStats) *network.IPTranslation
	DeleteTranslation(network.ConnectionStats)
	IsSampling() bool
	DumpCachedTable(context.Context) (map[uint32][]DebugConntrackEntry, error)
	Close()
}

type connKey struct {
	src netaddr.IPPort
	dst netaddr.IPPort

	// the transport protocol of the connection, using the same values as specified in the agent payload.
	transport network.ConnectionType
}

type translationEntry struct {
	*network.IPTranslation
	orphan *list.Element
}

type orphanEntry struct {
	key     connKey
	expires time.Time
}

type stats struct {
	metricGroup      *telemetry.MetricGroup
	gets             *telemetry.Metric
	registers        *telemetry.Metric
	registersDropped *telemetry.Metric
	unregisters      *telemetry.Metric
	evicts           *telemetry.Metric
	stateSize        *telemetry.Metric
	orphanSize       *telemetry.Metric
}

type realConntracker struct {
	sync.RWMutex
	consumer *Consumer
	cache    *conntrackCache
	decoder  *Decoder

	// The maximum size the state map will grow before we reject new entries
	maxStateSize int

	compactTicker *time.Ticker
	stats         stats
}

// NewConntracker creates a new conntracker with a short term buffer capped at the given size
func NewConntracker(config *config.Config) (Conntracker, error) {
	var (
		err         error
		conntracker Conntracker
	)

	done := make(chan struct{})

	go func() {
		conntracker, err = newConntrackerOnce(config.ProcRoot, config.ConntrackMaxStateSize, config.ConntrackRateLimit, config.EnableConntrackAllNamespaces)
		done <- struct{}{}
	}()

	select {
	case <-done:
		return conntracker, err
	case <-time.After(config.ConntrackInitTimeout):
		return nil, fmt.Errorf("could not initialize conntrack after: %s", config.ConntrackInitTimeout)
	}
}

func newStats() stats {
	metricGroup := telemetry.NewMetricGroup("conntrack", telemetry.OptExpvar)
	return stats{
		metricGroup:      metricGroup,
		gets:             metricGroup.NewMetric("gets"),
		registers:        metricGroup.NewMetric("registers"),
		registersDropped: metricGroup.NewMetric("registers_dropped"),
		unregisters:      metricGroup.NewMetric("unregisters"),
		evicts:           metricGroup.NewMetric("evicts"),
		stateSize:        metricGroup.NewMetric("state_size", telemetry.OptGauge),
		orphanSize:       metricGroup.NewMetric("orphan_size", telemetry.OptGauge),
	}
}

func newConntrackerOnce(procRoot string, maxStateSize, targetRateLimit int, listenAllNamespaces bool) (Conntracker, error) {
	consumer := NewConsumer(procRoot, targetRateLimit, listenAllNamespaces)
	ctr := &realConntracker{
		consumer:      consumer,
		cache:         newConntrackCache(maxStateSize, defaultOrphanTimeout),
		maxStateSize:  maxStateSize,
		compactTicker: time.NewTicker(compactInterval),
		decoder:       NewDecoder(),
		stats:         newStats(),
	}

	// init telemetry

	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		events, err := consumer.DumpTable(family)
		if err != nil {
			return nil, fmt.Errorf("error dumping conntrack table for family %d: %w", family, err)
		}
		ctr.loadInitialState(events)
	}

	if err := ctr.run(); err != nil {
		return nil, err
	}

	log.Infof("initialized conntrack with target_rate_limit=%d messages/sec", targetRateLimit)
	return ctr, nil
}

func (ctr *realConntracker) GetTranslationForConn(c network.ConnectionStats) *network.IPTranslation {
	ctr.stats.gets.Add(1)

	ctr.Lock()
	defer ctr.Unlock()

	k := connKey{
		src:       netaddr.IPPortFrom(ipFromAddr(c.Source), c.SPort),
		dst:       netaddr.IPPortFrom(ipFromAddr(c.Dest), c.DPort),
		transport: c.Type,
	}

	t, ok := ctr.cache.Get(k)
	if !ok {
		return nil
	}

	return t.IPTranslation
}

func (ctr *realConntracker) DeleteTranslation(c network.ConnectionStats) {
	ctr.Lock()
	defer ctr.Unlock()

	k := connKey{
		src:       netaddr.IPPortFrom(ipFromAddr(c.Source), c.SPort),
		dst:       netaddr.IPPortFrom(ipFromAddr(c.Dest), c.DPort),
		transport: c.Type,
	}

	if ctr.cache.Remove(k) {
		ctr.stats.unregisters.Add(1)
	}
}

func (ctr *realConntracker) IsSampling() bool {
	return ctr.consumer.SamplingPct() < 100
}

func (ctr *realConntracker) Close() {
	ctr.stats.metricGroup.Clear()
	ctr.consumer.Stop()
	ctr.compactTicker.Stop()
}

func (ctr *realConntracker) loadInitialState(events <-chan Event) {
	for e := range events {
		conns := ctr.decoder.DecodeAndReleaseEvent(e)
		for _, c := range conns {
			if !IsNAT(c) {
				continue
			}

			evicts := ctr.cache.Add(c, false)
			ctr.stats.registers.Add(1)
			ctr.stats.evicts.Add(int64(evicts))
		}
	}
}

// register is registered to be called whenever a conntrack update/create is called.
// it will keep being called until it returns nonzero.
func (ctr *realConntracker) register(c Con) int {
	// don't bother storing if the connection is not NAT
	if !IsNAT(c) {
		ctr.stats.registersDropped.Add(1)
		return 0
	}

	ctr.Lock()
	defer ctr.Unlock()

	evicts := ctr.cache.Add(c, true)

	ctr.stats.registers.Add(1)
	ctr.stats.evicts.Add(int64(evicts))
	ctr.stats.stateSize.Set(int64(ctr.cache.Len()))
	ctr.stats.orphanSize.Set(int64(ctr.cache.orphans.Len()))

	return 0
}

func (ctr *realConntracker) run() error {
	events, err := ctr.consumer.Events()
	if err != nil {
		return err
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ctr.compactTicker.C:
				ctr.compact()
			}
		}
	}()

	go func() {
		defer close(done)
		for e := range events {
			conns := ctr.decoder.DecodeAndReleaseEvent(e)
			for _, c := range conns {
				ctr.register(c)
			}
		}
	}()
	return nil
}

func (ctr *realConntracker) compact() {
	var removed int64
	defer func() {
		ctr.stats.unregisters.Add(removed)
		log.Debugf("removed %d orphans", removed)
	}()

	ctr.Lock()
	defer ctr.Unlock()

	removed = ctr.cache.removeOrphans(time.Now())
}

type conntrackCache struct {
	cache         *simplelru.LRU
	orphans       *list.List
	orphanTimeout time.Duration
}

func newConntrackCache(maxSize int, orphanTimeout time.Duration) *conntrackCache {
	c := &conntrackCache{
		orphans:       list.New(),
		orphanTimeout: orphanTimeout,
	}

	c.cache, _ = simplelru.NewLRU(maxSize, func(key, value interface{}) {
		t := value.(*translationEntry)
		if t.orphan != nil {
			c.orphans.Remove(t.orphan)
		}
	})

	return c
}

func (cc *conntrackCache) Get(k connKey) (*translationEntry, bool) {
	v, ok := cc.cache.Get(k)
	if !ok {
		return nil, false
	}

	t := v.(*translationEntry)
	if t.orphan != nil {
		cc.orphans.Remove(t.orphan)
		t.orphan = nil
	}

	return t, true
}

func (cc *conntrackCache) Remove(k connKey) bool {
	return cc.cache.Remove(k)
}

func (cc *conntrackCache) Add(c Con, orphan bool) (evicts int) {
	registerTuple := func(keyTuple, transTuple *ConTuple) {
		key, ok := formatKey(keyTuple)
		if !ok {
			return
		}

		if v, ok := cc.cache.Peek(key); ok {
			// value is going to get replaced
			// by the call to Add below, make
			// sure orphan is removed
			t := v.(*translationEntry)
			if t.orphan != nil {
				cc.orphans.Remove(t.orphan)
			}
		}

		t := &translationEntry{
			IPTranslation: formatIPTranslation(transTuple),
		}
		if orphan {
			t.orphan = cc.orphans.PushFront(&orphanEntry{
				key:     key,
				expires: time.Now().Add(cc.orphanTimeout),
			})
		}

		if cc.cache.Add(key, t) {
			evicts++
		}
	}

	log.Tracef("%s", c)

	registerTuple(&c.Origin, &c.Reply)
	registerTuple(&c.Reply, &c.Origin)
	return
}

func (cc *conntrackCache) Len() int {
	return cc.cache.Len()
}

func (cc *conntrackCache) removeOrphans(now time.Time) (removed int64) {
	for b := cc.orphans.Back(); b != nil; b = cc.orphans.Back() {
		o := b.Value.(*orphanEntry)
		if !o.expires.Before(now) {
			break
		}

		cc.cache.Remove(o.key)
		removed++
		log.Tracef("removed orphan %+v", o.key)
	}

	return removed
}

// IsNAT returns whether this Con represents a NAT translation
func IsNAT(c Con) bool {
	if c.Origin.Src.IsZero() ||
		c.Reply.Src.IsZero() ||
		c.Origin.Proto == 0 ||
		c.Reply.Proto == 0 ||
		c.Origin.Src.Port() == 0 ||
		c.Origin.Dst.Port() == 0 ||
		c.Reply.Src.Port() == 0 ||
		c.Reply.Dst.Port() == 0 {
		return false
	}

	return c.Origin.Src.IP() != c.Reply.Dst.IP() ||
		c.Origin.Dst.IP() != c.Reply.Src.IP() ||
		c.Origin.Src.Port() != c.Reply.Dst.Port() ||
		c.Origin.Dst.Port() != c.Reply.Src.Port()
}

func formatIPTranslation(tuple *ConTuple) *network.IPTranslation {
	return &network.IPTranslation{
		ReplSrcIP:   addrFromIP(tuple.Src.IP()),
		ReplDstIP:   addrFromIP(tuple.Dst.IP()),
		ReplSrcPort: tuple.Src.Port(),
		ReplDstPort: tuple.Dst.Port(),
	}
}

func addrFromIP(ip netaddr.IP) util.Address {
	if ip.Is6() && !ip.Is4in6() {
		b := ip.As16()
		return util.V6AddressFromBytes(b[:])
	}
	b := ip.As4()
	return util.V4AddressFromBytes(b[:])
}

func ipFromAddr(a util.Address) netaddr.IP {
	if a.Len() == net.IPv6len {
		return netaddr.IPFrom16(*(*[16]byte)(a.Bytes()))
	}
	return netaddr.IPFrom4(*(*[4]byte)(a.Bytes()))
}

func formatKey(tuple *ConTuple) (k connKey, ok bool) {
	ok = true
	k.src = tuple.Src
	k.dst = tuple.Dst

	proto := tuple.Proto
	switch proto {
	case unix.IPPROTO_TCP:
		k.transport = network.TCP
	case unix.IPPROTO_UDP:
		k.transport = network.UDP
	default:
		ok = false
	}

	return
}
