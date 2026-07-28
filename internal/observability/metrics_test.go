package observability

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestMetricsPrometheusOutput(t *testing.T) {
	metrics := NewMetrics()
	metrics.ActiveConnections.Store(-1)
	metrics.Connections.Store(3)
	metrics.Pushes.Store(4)
	metrics.NewFunctions.Store(2)
	metrics.Pulls.Store(5)
	metrics.Queried.Store(6)
	metrics.Failures.Store(7)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.RecordVersion(5)
		}()
	}
	metrics.RecordVersion(4)
	wg.Wait()

	var output bytes.Buffer
	metrics.WritePrometheus(&output)
	text := output.String()
	for _, want := range []string{
		"lux_active_connections 0",
		"lux_connections_total 3",
		"lux_pushes_total 4",
		"lux_new_functions_total 2",
		"lux_pulls_total 5",
		"lux_queried_functions_total 6",
		"lux_rpc_failures_total 7",
		`lux_protocol_connections_total{version="5"} 10`,
		`lux_protocol_connections_total{version="4"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q:\n%s", want, text)
		}
	}
}

func TestMax(t *testing.T) {
	if max(-2, 0) != 0 || max(3, 0) != 3 {
		t.Fatal("max returned an unexpected value")
	}
}
