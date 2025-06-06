package samurai

import (
	"context"
	"sync"
	"time"
)

// MetricsCollector collects and manages plugin metrics
type MetricsCollector struct {
	mu          sync.RWMutex
	host        HostInterface
	metrics     map[string]interface{}
	counters    map[string]int64
	latencies   map[string][]time.Duration
	initialized bool
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(host HostInterface) *MetricsCollector {
	return &MetricsCollector{
		host:      host,
		metrics:   make(map[string]interface{}),
		counters:  make(map[string]int64),
		latencies: make(map[string][]time.Duration),
	}
}

// Initialize initializes the metrics collector
func (mc *MetricsCollector) Initialize(ctx context.Context) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.initialized = true
	return nil
}

// SetMetric sets a metric value
func (mc *MetricsCollector) SetMetric(ctx context.Context, name string, value interface{}) error {
	mc.mu.Lock()
	mc.metrics[name] = value
	mc.mu.Unlock()

	return mc.host.SetMetric(ctx, name, value)
}

// IncrementCounter increments a counter metric
func (mc *MetricsCollector) IncrementCounter(ctx context.Context, name string) error {
	mc.mu.Lock()
	mc.counters[name]++
	value := mc.counters[name]
	mc.mu.Unlock()

	return mc.host.SetMetric(ctx, name, value)
}

// RecordLatency records a latency metric
func (mc *MetricsCollector) RecordLatency(ctx context.Context, name string, duration time.Duration) error {
	mc.mu.Lock()
	if mc.latencies[name] == nil {
		mc.latencies[name] = []time.Duration{}
	}
	mc.latencies[name] = append(mc.latencies[name], duration)

	// Keep only last 100 measurements
	if len(mc.latencies[name]) > 100 {
		mc.latencies[name] = mc.latencies[name][1:]
	}

	// Calculate average
	var total time.Duration
	for _, d := range mc.latencies[name] {
		total += d
	}
	avg := total / time.Duration(len(mc.latencies[name]))
	mc.mu.Unlock()

	return mc.host.SetMetric(ctx, name+"_avg", avg.Milliseconds())
}

// GetMetrics returns all metrics
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range mc.metrics {
		result[k] = v
	}
	for k, v := range mc.counters {
		result[k] = v
	}

	return result
}

// Shutdown shuts down the metrics collector
func (mc *MetricsCollector) Shutdown(ctx context.Context) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.initialized = false
	return nil
}
