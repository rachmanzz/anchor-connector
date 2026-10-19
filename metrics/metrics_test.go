package metrics

import (
	"strings"
	"sync"
	"testing"
)

func TestMetrics_Counter_ThreadSafety(t *testing.T) {
	c := NewCounter("test_counter", "A test counter", "model", "status")

	concurrency := 20
	iterations := 100
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				c.WithLabelValues("users", "ok").Inc()
			}
		}(i)
	}

	wg.Wait()

	out := RenderPrometheusText()
	text := string(out)

	if !strings.Contains(text, `test_counter{model="users",status="ok"} 2000`) {
		t.Fatalf("expected counter 2000, got:\n%s", text)
	}
}

func TestMetrics_Gauge(t *testing.T) {
	g := NewGauge("test_gauge", "A test gauge", "node")
	g.WithLabelValues("node-1").Set(100)
	g.WithLabelValues("node-1").Inc()
	g.WithLabelValues("node-1").Dec()

	out := RenderPrometheusText()
	text := string(out)

	if !strings.Contains(text, `test_gauge{node="node-1"} 100`) {
		t.Fatalf("expected test_gauge in output, got:\n%s", text)
	}
}

func TestMetrics_Histogram(t *testing.T) {
	h := NewHistogram("test_latency_seconds", "Test latency", []float64{0.005, 0.01, 0.05, 0.1}, "op")
	h.WithLabelValues("ping").Observe(0.002) // falls in <= 0.005
	h.WithLabelValues("ping").Observe(0.008) // falls in <= 0.01
	h.WithLabelValues("ping").Observe(0.08)  // falls in <= 0.1

	out := RenderPrometheusText()
	text := string(out)

	if !strings.Contains(text, `test_latency_seconds_count{op="ping"} 3`) {
		t.Fatalf("expected count 3 in histogram output, got:\n%s", text)
	}
	if !strings.Contains(text, `test_latency_seconds_bucket{le="0.005",op="ping"} 1`) {
		t.Fatalf("expected bucket le=0.005 count 1, got:\n%s", text)
	}
	if !strings.Contains(text, `test_latency_seconds_bucket{le="+Inf",op="ping"} 3`) {
		t.Fatalf("expected +Inf bucket count 3, got:\n%s", text)
	}
}
