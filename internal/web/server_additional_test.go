package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/store"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestEveryReadOnlyManagementRoute(t *testing.T) {
	db, hash, md5 := populatedWebStore(t)
	cfg := config.Config{
		ServerName: "route-test", LuminaAddr: "127.0.0.1:1234",
		HistoryLimit: 12, TLSCert: "configured.pem",
	}
	server := newWebTestServer(t, cfg, db)
	defer server.Close()

	tests := []struct {
		name       string
		path       string
		status     int
		bodyPieces []string
	}{
		{"index", "/", 200, []string{"Your team’s analysis"}},
		{"stylesheet", "/styles.css", 200, []string{"--acid"}},
		{"script", "/app.js", 200, []string{"loadResults"}},
		{"health", "/healthz", 200, []string{`"status":"ok"`, `"functions":1`}},
		{"metrics", "/metrics", 200, []string{"lux_connections_total"}},
		{"config", "/api/v1/config", 200, []string{`"server_name":"route-test"`, `"tls":true`, `"history_limit":12`}},
		{"stats", "/api/v1/stats", 200, []string{`"functions":1`, `"versions":1`, `"files":1`}},
		{"functions", "/api/v1/functions?q=known&limit=2&offset=0", 200, []string{"known_function", `"limit":2`}},
		{"functions default pagination", "/api/v1/functions?limit=900&offset=-5", 200, []string{`"limit":50`, `"offset":0`}},
		{"function", "/api/v1/functions/" + hash, 200, []string{"known_function", "useful comment"}},
		{"function invalid", "/api/v1/functions/short", 400, []string{"exactly 32"}},
		{"function missing", "/api/v1/functions/99999999999999999999999999999999", 404, []string{"function not found"}},
		{"files", "/api/v1/files?q=sample", 200, []string{"/samples/sample.bin"}},
		{"files empty", "/api/v1/files?q=absent", 200, []string{`"items":[]`}},
		{"file functions", "/api/v1/files/" + md5 + "/functions", 200, []string{"known_function"}},
		{"file invalid", "/api/v1/files/nope/functions", 400, []string{"exactly 32"}},
		{"legacy file", "/api/files/" + md5, 200, []string{`"len":64`, `"name":"known_function"`}},
		{"legacy file invalid", "/api/files/nope", 400, []string{"exactly 32"}},
		{"legacy function", "/api/funcs/" + hash, 200, []string{`"name":"known_function"`, `"Function"`, `"in_files"`}},
		{"legacy function missing", "/api/funcs/99999999999999999999999999999999", 200, []string{"[]"}},
		{"legacy function invalid", "/api/funcs/nope", 400, []string{"exactly 32"}},
		{"not found", "/does-not-exist", 404, []string{"404 page not found"}},
	}
	client := server.Client()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := client.Get(server.URL + test.path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status %d, want %d, body %s", response.StatusCode, test.status, body)
			}
			for _, piece := range test.bodyPieces {
				if !strings.Contains(string(body), piece) {
					t.Errorf("body missing %q: %s", piece, body)
				}
			}
			if response.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Error("security middleware header missing")
			}
		})
	}
}

func TestManagementDeleteAuthorizationAndOutcomes(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		db, hash, _ := populatedWebStore(t)
		server := newWebTestServer(t, config.Config{AllowDeletes: false}, db)
		defer server.Close()
		response := deleteRequest(t, server, hash, "secret")
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", response.StatusCode)
		}
		response.Body.Close()
	})

	t.Run("protected", func(t *testing.T) {
		db, hash, _ := populatedWebStore(t)
		server := newWebTestServer(t, config.Config{AllowDeletes: true, AdminToken: "secret"}, db)
		defer server.Close()
		for _, token := range []string{"", "wrong"} {
			response := deleteRequest(t, server, hash, token)
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("token %q: status %d", token, response.StatusCode)
			}
			if response.Header.Get("WWW-Authenticate") == "" {
				t.Fatal("authentication challenge missing")
			}
			response.Body.Close()
		}
		request, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/functions/"+hash, nil)
		request.Header.Set("Authorization", "Bearersecret")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("malformed bearer status %d", response.StatusCode)
		}
		response.Body.Close()

		response = deleteRequest(t, server, "bad", "secret")
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid hash status %d", response.StatusCode)
		}
		response.Body.Close()
		response = deleteRequest(t, server, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "secret")
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid hex status %d", response.StatusCode)
		}
		response.Body.Close()
		response = deleteRequest(t, server, "99999999999999999999999999999999", "secret")
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("missing hash status %d", response.StatusCode)
		}
		response.Body.Close()

		response = deleteRequest(t, server, hash, "secret")
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"deleted_versions":1`) {
			t.Fatalf("delete status %d, body %s", response.StatusCode, body)
		}
	})

	t.Run("unprotected", func(t *testing.T) {
		db, hash, _ := populatedWebStore(t)
		server := newWebTestServer(t, config.Config{AllowDeletes: true}, db)
		defer server.Close()
		response := deleteRequest(t, server, hash, "")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status %d", response.StatusCode)
		}
		response.Body.Close()
	})
}

func TestManagementDatabaseFailures(t *testing.T) {
	db, hash, md5 := populatedWebStore(t)
	server := newWebTestServer(t, config.Config{}, db)
	defer server.Close()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path   string
		status int
	}{
		{"/healthz", http.StatusServiceUnavailable},
		{"/api/v1/stats", http.StatusInternalServerError},
		{"/api/v1/functions", http.StatusInternalServerError},
		{"/api/v1/functions/" + hash, http.StatusInternalServerError},
		{"/api/v1/files", http.StatusInternalServerError},
		{"/api/v1/files/" + md5 + "/functions", http.StatusInternalServerError},
		{"/api/files/" + md5, http.StatusInternalServerError},
		{"/api/funcs/" + hash, http.StatusInternalServerError},
	}
	for _, test := range tests {
		response, err := server.Client().Get(server.URL + test.path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Errorf("%s: status %d, want %d", test.path, response.StatusCode, test.status)
		}
	}
}

func TestWebHelpers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?limit=4&offset=8", nil)
	if limit, offset := pagination(request); limit != 4 || offset != 8 {
		t.Fatalf("pagination %d/%d", limit, offset)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "bEaReR secret")
	server := &Server{cfg: config.Config{AdminToken: "secret"}}
	if !server.authorized(request) {
		t.Fatal("case-insensitive bearer scheme rejected")
	}
	if isHashError(context.Canceled) {
		t.Fatal("unrelated error classified as hash error")
	}

	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusTeapot, func() {})
	if recorder.Code != http.StatusTeapot || !strings.HasSuffix(recorder.Body.String(), "\n") {
		t.Fatalf("writeJSON error path: %d %q", recorder.Code, recorder.Body.String())
	}
}

func populatedWebStore(t *testing.T) (*store.Store, string, string) {
	t.Helper()
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hashBytes := bytes.Repeat([]byte{0x12}, 16)
	md5Bytes := [16]byte{0x34, 0x56}
	var metadata protocol.Encoder
	metadata.DD(3)
	metadata.Bytes([]byte("useful comment"))
	_, err = db.Push(context.Background(), store.PushIdentity{
		LicenseNumber: []byte{1, 2, 3, 4, 5, 6}, LicenseData: []byte("license"), Hostname: "host",
	}, protocol.PushMetadata{
		IDBPath: "sample.i64", FilePath: "/samples/sample.bin", MD5: md5Bytes, Hostname: "host",
		Funcs: []protocol.PushFunction{{
			Name: "known_function", Length: 64, Hash: hashBytes,
			Metadata: append([]byte(nil), metadata.Payload()...),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, strings.Repeat("12", 16), "34560000000000000000000000000000"
}

func newWebTestServer(t *testing.T, cfg config.Config, db *store.Store) *httptest.Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return httptest.NewServer(New(cfg, db, observability.NewMetrics(), log).Handler())
}

func deleteRequest(t *testing.T, server *httptest.Server, hash, token string) *http.Response {
	t.Helper()
	request, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/functions/"+hash, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
