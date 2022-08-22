package telemetry

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-go/v5/statsd"
)

const (
	// OptStatsd designates a metric that should be emitted using statsd
	OptStatsd = "_statsd"

	// OptExpvar designates a metric that should be emitted using expvar
	OptExpvar = "_expvar"

	// OptTelemetry designates a metric that should be emitted as agent telemetry
	OptTelemetry = "_telemetry"

	// OptSync means that the client exerts control over which value
	// gets reported by calling Sync(). This is particularly useful for
	// non-monotonic metrics that get peridiocally reset
	OptSync = "_synchronized"

	// OptGauge represents a gauge-type metric
	OptGauge = "_gauge"

	// OptCounter represents a counter-type metric
	OptCounter = "_counter"

	// OptMonotonic designates a metric of monotonic type.
	// In this case the reporters will only emmit the delta
	OptMonotonic = "_monotonic"

	// common prefix used across all statsd metric
	statsdPrefix = "datadog.system_probe.network_tracer."

	// prefix used by options
	optPrefix = "_"
)

var statsdDelta deltaCalculator

// ReportStatsd flushes all metrics tagged with `ReportStatsd`
func ReportStatsd() {
	client := getClient()
	if client == nil {
		return
	}

	metrics := GetMetrics(OptStatsd)
	previousValues := statsdDelta.GetState("")
	for _, metric := range metrics {
		v := previousValues.ValueFor(metric)
		if contains(OptGauge, metric.tags) {
			client.Gauge(statsdPrefix+metric.name, float64(v), metric.tags, 1.0)
		}

		client.Count(statsdPrefix+metric.name, v, metric.tags, 1.0)
	}
}

var telemetryDelta deltaCalculator

// ReportPayloadTelemetry returns a map with all metrics tagged with `OptTelemetry`
// The return format is consistent with what we use in the protobuf messages sent to the backend
func ReportPayloadTelemetry(clientID string) map[string]int64 {
	metrics := GetMetrics(OptTelemetry)
	previousValues := telemetryDelta.GetState(clientID)
	result := make(map[string]int64, len(metrics))
	for _, metric := range metrics {
		result[metric.name] = previousValues.ValueFor(metric)
	}
	return result
}

var expvarDelta deltaCalculator

// ReportExpvar returns a nested map structure with all metrics tagged with `OptExpvar`
func ReportExpvar() map[string]interface{} {
	metrics := GetMetrics(OptExpvar)
	previousValues := expvarDelta.GetState("")
	root := make(map[string]interface{})
	countByName := make(map[string]int)

	for _, m := range metrics {
		if countByName[m.name] == 1 {
			log.Debugf(
				"metric %q has multiple instances with different tag sets which is not suitable for expvar.",
				m.name,
			)
		}

		countByName[m.name]++
		insertNestedValueFor(m.name, previousValues.ValueFor(m), root)
	}

	return root
}

var clientMux sync.Mutex
var client statsd.ClientInterface

// SetStatsdClient used to report data during invocations of `ReportStatsd`
// TODO: should `ReportStatsd` receive a client instance instead?
func SetStatsdClient(c statsd.ClientInterface) {
	clientMux.Lock()
	defer clientMux.Unlock()
	client = c
}

func getClient() statsd.ClientInterface {
	clientMux.Lock()
	defer clientMux.Unlock()
	return client
}
