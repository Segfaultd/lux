package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/store"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestManagementUIAndAPI(t *testing.T) {
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := config.Config{
		ServerName: "test-lux", LuminaAddr: ":1234",
		AllowDeletes: true, AdminToken: "secret", HistoryLimit: 50,
	}
	handler := New(cfg, db, observability.NewMetrics(),
		slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Your team’s analysis") {
		t.Fatalf("management UI: status=%d body=%q", response.StatusCode, body)
	}
	if response.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("management UI did not set a content security policy")
	}

	response, err = http.Get(server.URL + "/api/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	var stats store.Stats
	if err := json.NewDecoder(response.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if stats.Functions != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}

	request, _ := http.NewRequest(http.MethodDelete,
		server.URL+"/api/v1/functions/00000000000000000000000000000000", nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("delete without token: got %d", response.StatusCode)
	}
}
