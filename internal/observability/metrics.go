package observability

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

type Metrics struct {
	ActiveConnections atomic.Int64
	Connections       atomic.Uint64
	Pushes            atomic.Uint64
	NewFunctions      atomic.Uint64
	Pulls             atomic.Uint64
	Queried           atomic.Uint64
	Failures          atomic.Uint64

	versionsMu sync.Mutex
	versions   map[uint32]uint64
}

func NewMetrics() *Metrics {
	return &Metrics{versions: make(map[uint32]uint64)}
}

func (m *Metrics) RecordVersion(version uint32) {
	m.versionsMu.Lock()
	m.versions[version]++
	m.versionsMu.Unlock()
}

func (m *Metrics) WritePrometheus(w io.Writer) {
	metrics := []struct {
		name string
		help string
		kind string
		val  uint64
	}{
		{"lux_active_connections", "Active Lumina connections.", "gauge", uint64(max(m.ActiveConnections.Load(), 0))},
		{"lux_connections_total", "Accepted Lumina connections.", "counter", m.Connections.Load()},
		{"lux_pushes_total", "Function metadata pushes.", "counter", m.Pushes.Load()},
		{"lux_new_functions_total", "Previously unknown function metadata pushes.", "counter", m.NewFunctions.Load()},
		{"lux_pulls_total", "Function metadata records returned.", "counter", m.Pulls.Load()},
		{"lux_queried_functions_total", "Function hashes queried.", "counter", m.Queried.Load()},
		{"lux_rpc_failures_total", "RPC failures returned.", "counter", m.Failures.Load()},
	}
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n",
			metric.name, metric.help, metric.name, metric.kind, metric.name, metric.val)
	}
	m.versionsMu.Lock()
	defer m.versionsMu.Unlock()
	_, _ = fmt.Fprintln(w, "# HELP lux_protocol_connections_total Connections by Lumina protocol version.")
	_, _ = fmt.Fprintln(w, "# TYPE lux_protocol_connections_total counter")
	for version, value := range m.versions {
		_, _ = fmt.Fprintf(w, "lux_protocol_connections_total{version=%q} %d\n", fmt.Sprint(version), value)
	}
}

func max(v, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}
