package telemetry

import (
	"encoding/json"
	"strings"

	"go.uber.org/atomic"
)

// Metric represents a named piece of telemetry
type Metric struct {
	name  string
	tags  []string
	opts  []string
	value *atomic.Int64

	// metrics of type OptSync return this value
	// which is controlled by calling Sync()
	syncValue *atomic.Int64
}

// NewMetric returns a new `Metric` instance
func NewMetric(name string, tagsAndOptions ...string) *Metric {
	m := &Metric{
		name:      name,
		value:     atomic.NewInt64(0),
		syncValue: atomic.NewInt64(0),
	}

	m.tags, m.opts = separateTagsAndOptions(tagsAndOptions)

	r.Lock()
	defer r.Unlock()
	// Ensure we only have one intance per (name, tags). If there is an existing
	// `Metric` instance matching the params we simply return it. For now we're
	// doing a brute-force search here because calls to `NewMetric` are almost
	// always restriced to program initialization
	for _, other := range r.metrics {
		if other.isEqual(m) {
			return other
		}
	}

	r.metrics = append(r.metrics, m)
	return m
}

// Name of the `Metric` (including tags)
func (m *Metric) Name() string {
	return strings.Join(append([]string{m.name}, m.tags...), ",")
}

// Set value atomically
func (m *Metric) Set(v int64) {
	m.value.Store(v)
}

// Add value atomically
func (m *Metric) Add(v int64) {
	m.value.Add(v)
}

// Get value atomically
func (m *Metric) Get() int64 {
	if contains(OptSync, m.opts) {
		return m.syncValue.Load()
	}

	return m.value.Load()
}

// Swap value atomically
func (m *Metric) Swap(v int64) int64 {
	return m.value.Swap(v)
}

// Sync value to be reported
func (m *Metric) Sync() *Metric {
	// this operation is obviously not atomic but we're OK with it
	m.syncValue.Store(m.value.Load())
	return m
}

// MarshalJSON returns a json representation of the current `Metric`. We
// implement our own method so we don't need to export the fields.
// This is mostly inteded for serving a list of the existing
// metrics under /network_tracer/debug/telemetry endpoint
func (m *Metric) MarshalJSON() ([]byte, error) {
	j, err := json.Marshal(struct {
		Name string
		Tags []string `json:",omitempty"`
		Opts []string
	}{
		Name: m.name,
		Tags: m.tags,
		Opts: m.opts,
	})
	if err != nil {
		return nil, err
	}
	return j, nil
}

func (m *Metric) isEqual(other *Metric) bool {
	if m.name != other.name || len(m.tags) != len(other.tags) {
		return false
	}

	// Tags are always sorted
	for i := range m.tags {
		if m.tags[i] != other.tags[i] {
			return false
		}
	}

	return true
}
