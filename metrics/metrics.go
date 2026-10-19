package metrics

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// MetricType represents a Prometheus metric category.
type MetricType string

const (
	TypeCounter   MetricType = "counter"
	TypeGauge     MetricType = "gauge"
	TypeHistogram MetricType = "histogram"
)

// Collector interface for all Prometheus metrics.
type Collector interface {
	WritePrometheus(w io.Writer)
}

// Registry stores and renders Prometheus metrics.
type Registry struct {
	collectors []Collector
	mu         sync.RWMutex
}

// NewRegistry creates a fresh metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		collectors: make([]Collector, 0),
	}
}

// DefaultRegistry is the global connector metrics registry.
var DefaultRegistry = NewRegistry()

// Register adds a collector to the registry.
func (r *Registry) Register(c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, c)
}

// WritePrometheus serializes all registered metrics in Prometheus text format (v0.0.4).
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, c := range r.collectors {
		c.WritePrometheus(w)
	}
}

// formatLabels converts a label map to a sorted Prometheus label string: {k1="v1",k2="v2"}.
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(k)
		sb.WriteString("=\"")
		sb.WriteString(labels[k])
		sb.WriteString("\"")
	}
	sb.WriteByte('}')
	return sb.String()
}

// --- Counter ---

// Counter tracks monotonically increasing values.
type Counter struct {
	name       string
	help       string
	labelNames []string
	values     map[string]*atomic.Uint64
	labelMaps  map[string]map[string]string
	mu         sync.RWMutex
}

// NewCounter registers and returns a new Counter.
func NewCounter(name, help string, labelNames ...string) *Counter {
	c := &Counter{
		name:       name,
		help:       help,
		labelNames: labelNames,
		values:     make(map[string]*atomic.Uint64),
		labelMaps:  make(map[string]map[string]string),
	}
	DefaultRegistry.Register(c)
	return c
}

func (c *Counter) key(labelValues []string) string {
	return strings.Join(labelValues, "\x1f")
}

// WithLabelValues retrieves or initializes the counter value for the given label values.
func (c *Counter) WithLabelValues(labelValues ...string) *CounterValue {
	k := c.key(labelValues)

	c.mu.RLock()
	val, exists := c.values[k]
	c.mu.RUnlock()

	if exists {
		return &CounterValue{val: val}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if val, exists := c.values[k]; exists {
		return &CounterValue{val: val}
	}

	val = &atomic.Uint64{}
	c.values[k] = val

	lmap := make(map[string]string, len(c.labelNames))
	for i, name := range c.labelNames {
		if i < len(labelValues) {
			lmap[name] = labelValues[i]
		}
	}
	c.labelMaps[k] = lmap

	return &CounterValue{val: val}
}

// CounterValue wraps the atomic integer for a specific label combination.
type CounterValue struct {
	val *atomic.Uint64
}

// Inc increments counter by 1.
func (cv *CounterValue) Inc() {
	cv.val.Add(1)
}

// Add adds delta to counter.
func (cv *CounterValue) Add(delta uint64) {
	cv.val.Add(delta)
}

// WritePrometheus renders the counter.
func (c *Counter) WritePrometheus(w io.Writer) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.values) == 0 {
		return
	}

	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	for k, val := range c.values {
		labels := formatLabels(c.labelMaps[k])
		fmt.Fprintf(w, "%s%s %d\n", c.name, labels, val.Load())
	}
}

// --- Gauge ---

// Gauge tracks a value that can arbitrarily increase or decrease.
type Gauge struct {
	name       string
	help       string
	labelNames []string
	values     map[string]*atomic.Int64
	labelMaps  map[string]map[string]string
	mu         sync.RWMutex
}

// NewGauge registers and returns a new Gauge.
func NewGauge(name, help string, labelNames ...string) *Gauge {
	g := &Gauge{
		name:       name,
		help:       help,
		labelNames: labelNames,
		values:     make(map[string]*atomic.Int64),
		labelMaps:  make(map[string]map[string]string),
	}
	DefaultRegistry.Register(g)
	return g
}

// WithLabelValues retrieves or initializes the gauge value for labels.
func (g *Gauge) WithLabelValues(labelValues ...string) *GaugeValue {
	k := strings.Join(labelValues, "\x1f")

	g.mu.RLock()
	val, exists := g.values[k]
	g.mu.RUnlock()

	if exists {
		return &GaugeValue{val: val}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if val, exists := g.values[k]; exists {
		return &GaugeValue{val: val}
	}

	val = &atomic.Int64{}
	g.values[k] = val

	lmap := make(map[string]string, len(g.labelNames))
	for i, name := range g.labelNames {
		if i < len(labelValues) {
			lmap[name] = labelValues[i]
		}
	}
	g.labelMaps[k] = lmap

	return &GaugeValue{val: val}
}

// GaugeValue wraps the atomic integer for a specific label combination.
type GaugeValue struct {
	val *atomic.Int64
}

// Set sets gauge to specific value.
func (gv *GaugeValue) Set(v int64) {
	gv.val.Store(v)
}

// Inc increments gauge by 1.
func (gv *GaugeValue) Inc() {
	gv.val.Add(1)
}

// Dec decrements gauge by 1.
func (gv *GaugeValue) Dec() {
	gv.val.Add(-1)
}

// WritePrometheus renders the gauge.
func (g *Gauge) WritePrometheus(w io.Writer) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.values) == 0 {
		return
	}

	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
	for k, val := range g.values {
		labels := formatLabels(g.labelMaps[k])
		fmt.Fprintf(w, "%s%s %d\n", g.name, labels, val.Load())
	}
}

// --- Histogram ---

// Histogram tracks observations across configurable buckets.
type Histogram struct {
	name       string
	help       string
	labelNames []string
	buckets    []float64
	observers  map[string]*histogramObserver
	labelMaps  map[string]map[string]string
	mu         sync.RWMutex
}

type histogramObserver struct {
	bucketCounts []atomic.Uint64
	sumMicros    atomic.Uint64 // stored in microseconds for atomic addition
	count        atomic.Uint64
}

// DefaultDurationBuckets provides standard second buckets from 0.5ms to 10s.
var DefaultDurationBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

// NewHistogram registers and returns a new Histogram.
func NewHistogram(name, help string, buckets []float64, labelNames ...string) *Histogram {
	if len(buckets) == 0 {
		buckets = DefaultDurationBuckets
	}
	h := &Histogram{
		name:       name,
		help:       help,
		labelNames: labelNames,
		buckets:    buckets,
		observers:  make(map[string]*histogramObserver),
		labelMaps:  make(map[string]map[string]string),
	}
	DefaultRegistry.Register(h)
	return h
}

// WithLabelValues retrieves or initializes the histogram observer.
func (h *Histogram) WithLabelValues(labelValues ...string) *HistogramObserver {
	k := strings.Join(labelValues, "\x1f")

	h.mu.RLock()
	obs, exists := h.observers[k]
	h.mu.RUnlock()

	if exists {
		return &HistogramObserver{h: h, obs: obs}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if obs, exists := h.observers[k]; exists {
		return &HistogramObserver{h: h, obs: obs}
	}

	obs = &histogramObserver{
		bucketCounts: make([]atomic.Uint64, len(h.buckets)),
	}
	h.observers[k] = obs

	lmap := make(map[string]string, len(h.labelNames))
	for i, name := range h.labelNames {
		if i < len(labelValues) {
			lmap[name] = labelValues[i]
		}
	}
	h.labelMaps[k] = lmap

	return &HistogramObserver{h: h, obs: obs}
}

// HistogramObserver observes values for a given label set.
type HistogramObserver struct {
	h   *Histogram
	obs *histogramObserver
}

// Observe records a float observation (e.g. latency in seconds).
func (ho *HistogramObserver) Observe(val float64) {
	ho.obs.count.Add(1)
	ho.obs.sumMicros.Add(uint64(val * 1e6))

	for i, b := range ho.h.buckets {
		if val <= b {
			ho.obs.bucketCounts[i].Add(1)
		}
	}
}

// WritePrometheus renders the histogram buckets, sum, and count.
func (h *Histogram) WritePrometheus(w io.Writer) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.observers) == 0 {
		return
	}

	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
	for k, obs := range h.observers {
		baseLabels := h.labelMaps[k]

		var cumulative uint64
		for i, b := range h.buckets {
			cumulative += obs.bucketCounts[i].Load()
			bucketLabels := make(map[string]string, len(baseLabels)+1)
			for k, v := range baseLabels {
				bucketLabels[k] = v
			}
			bucketLabels["le"] = fmt.Sprintf("%g", b)
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, formatLabels(bucketLabels), cumulative)
		}

		// +Inf bucket
		infLabels := make(map[string]string, len(baseLabels)+1)
		for k, v := range baseLabels {
			infLabels[k] = v
		}
		infLabels["le"] = "+Inf"
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, formatLabels(infLabels), obs.count.Load())

		// Sum & Count
		sumSec := float64(obs.sumMicros.Load()) / 1e6
		fmt.Fprintf(w, "%s_sum%s %.6f\n", h.name, formatLabels(baseLabels), sumSec)
		fmt.Fprintf(w, "%s_count%s %d\n", h.name, formatLabels(baseLabels), obs.count.Load())
	}
}

// --- Standard Predefined Metrics ---

var (
	// RequestsTotal tracks all inbound client requests.
	RequestsTotal = NewCounter(
		"anchor_connector_requests_total",
		"Total number of processed AnchorWire and HTTP requests",
		"model", "opcode", "protocol", "status",
	)

	// RequestDuration tracks request latency in seconds.
	RequestDuration = NewHistogram(
		"anchor_connector_request_duration_seconds",
		"Request processing duration in seconds",
		DefaultDurationBuckets,
		"model", "opcode", "protocol",
	)

	// ActiveConnections tracks currently open client connections.
	ActiveConnections = NewGauge(
		"anchor_connector_active_connections",
		"Current active client connections",
		"protocol",
	)

	// PoolConnections tracks backend sockets in pool.
	PoolConnections = NewGauge(
		"anchor_connector_pool_connections",
		"Current persistent connections to backend AnchorDB nodes",
		"backend", "state",
	)

	// PoolInFlightRequests tracks pending requests in multiplexer.
	PoolInFlightRequests = NewGauge(
		"anchor_connector_pool_in_flight_requests",
		"Number of in-flight pipelined requests per backend node",
		"backend",
	)

	// CircuitBreakerState exports 1 if backend breaker is in that state, 0 otherwise.
	CircuitBreakerState = NewGauge(
		"anchor_connector_circuit_breaker_state",
		"Circuit breaker state per backend node (1 if active, 0 otherwise)",
		"backend", "state",
	)

	// FailoversTotal tracks automated failover events.
	FailoversTotal = NewCounter(
		"anchor_connector_failovers_total",
		"Total automated failover elections executed",
		"model", "candidate", "status",
	)

	// ReplicationLagLSN tracks replica lag in LSN count.
	ReplicationLagLSN = NewGauge(
		"anchor_connector_replica_lag_lsn",
		"Replication lag in committed LSN per replica",
		"replica",
	)

	// ReplicationLagMS tracks replica lag in milliseconds.
	ReplicationLagMS = NewGauge(
		"anchor_connector_replica_lag_milliseconds",
		"Replication lag in milliseconds per replica",
		"replica",
	)

	// RingBufferEntries tracks mutations in RAM ring buffer.
	RingBufferEntries = NewGauge(
		"anchor_connector_ring_buffer_entries",
		"Total active mutations retained in RAM hot ring buffer",
	)

	// PrimaryCommitLSN tracks latest committed LSN on primary.
	PrimaryCommitLSN = NewGauge(
		"anchor_connector_primary_commit_lsn",
		"Latest committed transaction LSN on primary",
	)
)

// RenderPrometheusText writes all registered metrics to an in-memory buffer.
func RenderPrometheusText() []byte {
	var buf bytes.Buffer
	DefaultRegistry.WritePrometheus(&buf)
	return buf.Bytes()
}
