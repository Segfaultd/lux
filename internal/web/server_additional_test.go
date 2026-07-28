package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/segfaultd/lux/internal/auth"
	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/protocol"
	"github.com/segfaultd/lux/internal/session"
	"github.com/segfaultd/lux/internal/store"
	"github.com/segfaultd/lux/internal/testdb"
)

func TestEveryReadOnlyManagementRoute(t *testing.T) {
	db, hash, md5 := populatedWebStore(t)
	projects, err := db.ListProjects(context.Background(), "", 10, 0)
	if err != nil || len(projects) != 1 {
		t.Fatalf("projects: %#v, %v", projects, err)
	}
	projectID := projects[0].ID
	versions, err := db.Function(context.Background(), hash)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions: %#v, %v", versions, err)
	}
	versionID := versions[0].ID
	pushes, err := db.ListPushes(context.Background(), store.PushFilter{}, 10, 0)
	if err != nil || len(pushes) != 1 {
		t.Fatalf("pushes: %#v, %v", pushes, err)
	}
	changes, err := db.ListHistory(context.Background(), store.HistoryFilter{}, 10, 0)
	if err != nil || len(changes) != 1 {
		t.Fatalf("history: %#v, %v", changes, err)
	}
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
		{"index", "/", 200, []string{"Lux administration", "Per-user statistics", "Active Lumina sessions", "Projects / IDBs", "Push and metadata history", "Functions and metadata"}},
		{"stylesheet", "/styles.css", 200, []string{".topbar", ".version", ".history-filter", ".metadata-chunk", ".metadata-row"}},
		{"script", "/app.js", 200, []string{"loadCollection", "loadSessions", "/api/v1/sessions", "/api/v1/projects", "/api/v1/metadata", "/api/v1/history", "openPush", "openMetadataExplorer", "saveStructuredChunk"}},
		{"health", "/healthz", 200, []string{`"status":"ok"`, `"functions":1`}},
		{"metrics", "/metrics", 200, []string{"lux_connections_total"}},
		{"config", "/api/v1/config", 200, []string{`"server_name":"route-test"`, `"tls":true`, `"account_management":false`, `"history_limit":12`}},
		{"stats", "/api/v1/stats", 200, []string{`"functions":1`, `"versions":1`, `"files":1`}},
		{"user stats", "/api/v1/stats?username=analyst,missing", 200, []string{`"username":"analyst"`, `"functions":1`, `"username":"missing"`}},
		{"user stats empty names", "/api/v1/stats?username=,,,", 400, []string{"1-100"}},
		{"user stats too many names", "/api/v1/stats?username=" + strings.Repeat("x,", 101), 400, []string{"1-100"}},
		{"functions", "/api/v1/functions?q=known&limit=2&offset=0", 200, []string{"known_function", `"limit":2`}},
		{"functions default pagination", "/api/v1/functions?limit=900&offset=-5", 200, []string{`"limit":50`, `"offset":0`}},
		{"function", "/api/v1/functions/" + hash, 200, []string{"known_function", "useful comment"}},
		{"function invalid", "/api/v1/functions/short", 400, []string{"exactly 32"}},
		{"function missing", "/api/v1/functions/99999999999999999999999999999999", 404, []string{"function not found"}},
		{"files", "/api/v1/files?q=sample", 200, []string{"/samples/sample.bin"}},
		{"files empty", "/api/v1/files?q=absent", 200, []string{`"items":[]`}},
		{"file functions", "/api/v1/files/" + md5 + "/functions", 200, []string{"known_function"}},
		{"file invalid", "/api/v1/files/nope/functions", 400, []string{"exactly 32"}},
		{"projects", "/api/v1/projects?q=sample", 200, []string{`"idb_path":"sample.i64"`, `"versions":1`}},
		{"projects empty", "/api/v1/projects?q=absent", 200, []string{`"items":[]`}},
		{"project", "/api/v1/projects/" + strconv.FormatInt(projectID, 10), 200, []string{"sample.i64", `"function_versions"`}},
		{"project invalid", "/api/v1/projects/nope", 400, []string{"positive integer"}},
		{"project missing", "/api/v1/projects/999999", 404, []string{"project not found"}},
		{"metadata", "/api/v1/metadata/" + strconv.FormatInt(versionID, 10), 200, []string{"known_function", `"project_id"`}},
		{"structured metadata", "/api/v1/metadata/" + strconv.FormatInt(versionID, 10) + "/structured", 200, []string{`"key":"function_comment"`, `"text":"useful comment"`, `"known_chunks":1`}},
		{"metadata invalid", "/api/v1/metadata/0", 400, []string{"positive integer"}},
		{"metadata missing", "/api/v1/metadata/999999", 404, []string{"metadata version not found"}},
		{"pushes", "/api/v1/pushes?q=sample&username=&project_id=" + strconv.FormatInt(projectID, 10), 200, []string{`"source":"native"`, `"changed_functions":1`}},
		{"pushes official filters", "/api/v1/pushes?license_id=AB-1234-CDEF-90&chronological=true", 200, []string{`"username":"analyst"`, `"license_email":"analyst@example.test"`}},
		{"push", "/api/v1/pushes/" + strconv.FormatInt(pushes[0].ID, 10), 200, []string{`"changes"`, `"known_function"`}},
		{"push missing", "/api/v1/pushes/999999", 404, []string{"push not found"}},
		{"history", "/api/v1/history?q=known&hash=" + hash, 200, []string{`"operation":"create"`, `"known_function"`}},
		{"history official filters", "/api/v1/history?license_id=AB-1234-CDEF-90&name=known&idb=sample&input=samples&file_md5=" + md5 + "&history_id_from=" + strconv.FormatInt(changes[0].ID, 10) + "&history_id_to=" + strconv.FormatInt(changes[0].ID, 10) + "&push_id_from=" + strconv.FormatInt(pushes[0].ID, 10) + "&push_id_to=" + strconv.FormatInt(pushes[0].ID, 10) + "&chronological=true", 200, []string{`"known_function"`, `"username":"analyst"`}},
		{"history diff", "/api/v1/history/" + strconv.FormatInt(changes[0].ID, 10), 200, []string{`"fields"`, `"field":"name"`, `"metadata_document"`, `"metadata.function_comment"`}},
		{"history missing", "/api/v1/history/999999", 404, []string{"history record not found"}},
		{"history bad hash", "/api/v1/history?hash=bad", 400, []string{"exactly 32"}},
		{"history bad file hash", "/api/v1/history?file_md5=bad", 400, []string{"file_md5"}},
		{"push bad chronological", "/api/v1/pushes?chronological=sometimes", 400, []string{"true or false"}},
		{"push bad project", "/api/v1/pushes?project_id=nope", 400, []string{"positive integer"}},
		{"history bad push", "/api/v1/history?push_id=0", 400, []string{"positive integer"}},
		{"history reversed id range", "/api/v1/history?history_id_from=2&history_id_to=1", 400, []string{"must not exceed"}},
		{"history reversed push range", "/api/v1/history?push_id_from=2&push_id_to=1", 400, []string{"must not exceed"}},
		{"history bad from", "/api/v1/history?from=yesterday", 400, []string{"RFC3339"}},
		{"history reversed range", "/api/v1/history?from=2026-07-28T12%3A00%3A00Z&to=2026-07-27T12%3A00%3A00Z", 400, []string{"must not be later"}},
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

func TestHistoryManagementAPI(t *testing.T) {
	db, hash, _ := populatedWebStore(t)
	changes, err := db.ListHistory(context.Background(), store.HistoryFilter{}, 10, 0)
	if err != nil || len(changes) != 1 {
		t.Fatalf("history: %#v, %v", changes, err)
	}
	pushes, err := db.ListPushes(context.Background(), store.PushFilter{}, 10, 0)
	if err != nil || len(pushes) != 1 {
		t.Fatalf("pushes: %#v, %v", pushes, err)
	}
	changeID := strconv.FormatInt(changes[0].ID, 10)
	pushID := strconv.FormatInt(pushes[0].ID, 10)
	server := newWebTestServer(t, config.Config{AdminToken: "secret", AllowDeletes: true}, db)
	defer server.Close()

	for _, test := range []struct {
		name, method, path, token string
		status                    int
	}{
		{"restore unauthorized", http.MethodPost, "/api/v1/history/" + changeID + "/restore", "", http.StatusUnauthorized},
		{"restore bad id", http.MethodPost, "/api/v1/history/nope/restore", "secret", http.StatusBadRequest},
		{"restore missing", http.MethodPost, "/api/v1/history/999999/restore", "secret", http.StatusNotFound},
		{"delete history unauthorized", http.MethodDelete, "/api/v1/history/" + changeID, "", http.StatusUnauthorized},
		{"delete push unauthorized", http.MethodDelete, "/api/v1/pushes/" + pushID, "", http.StatusUnauthorized},
		{"delete history missing", http.MethodDelete, "/api/v1/history/999999", "secret", http.StatusNotFound},
		{"delete push missing", http.MethodDelete, "/api/v1/pushes/999999", "secret", http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := accountRequest(t, server, test.method, test.path, "", test.token)
			defer response.Body.Close()
			if response.StatusCode != test.status {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status %d, want %d: %s", response.StatusCode, test.status, body)
			}
		})
	}

	response := accountRequest(t, server, http.MethodPost, "/api/v1/history/"+changeID+"/restore", "", "secret")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || !strings.Contains(string(body), `"operation":"restore"`) {
		t.Fatalf("restore status %d: %s", response.StatusCode, body)
	}
	restored := store.HistoryChange{}
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	response = accountRequest(t, server, http.MethodDelete,
		"/api/v1/history/"+strconv.FormatInt(restored.ID, 10), "", "secret")
	if response.StatusCode != http.StatusOK {
		body, _ = io.ReadAll(response.Body)
		t.Fatalf("delete restored history status %d: %s", response.StatusCode, body)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodDelete, "/api/v1/pushes/"+pushID, "", "secret")
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"deleted_changes":1`) {
		t.Fatalf("delete push status %d: %s", response.StatusCode, body)
	}
	versions, err := db.Function(context.Background(), hash)
	if err != nil || len(versions) != 0 {
		t.Fatalf("push deletion left versions %#v, %v", versions, err)
	}
}

func TestStructuredMetadataManagementAPI(t *testing.T) {
	db, hash, _ := populatedWebStore(t)
	versions, err := db.Function(context.Background(), hash)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions: %#v, %v", versions, err)
	}
	versionID := versions[0].ID
	path := "/api/v1/metadata/" + strconv.FormatInt(versionID, 10) + "/structured"
	server := newWebTestServer(t, config.Config{AdminToken: "secret"}, db)
	defer server.Close()

	tests := []struct {
		name, path, body, token string
		status                  int
		piece                   string
	}{
		{"unauthorized", path, `{"mutations":[{"operation":"set","index":0,"text":"x"}]}`, "", http.StatusUnauthorized, "admin token"},
		{"invalid id", "/api/v1/metadata/nope/structured", `{}`, "secret", http.StatusBadRequest, "positive integer"},
		{"missing", "/api/v1/metadata/999999/structured", `{"mutations":[]}`, "secret", http.StatusNotFound, "not found"},
		{"empty patch", path, `{"mutations":[]}`, "secret", http.StatusBadRequest, "at least one"},
		{"invalid patch", path, `{"mutations":[{"operation":"set","index":0,"payload":"xyz"}]}`, "secret", http.StatusBadRequest, "hexadecimal"},
		{"malformed JSON", path, `{`, "secret", http.StatusBadRequest, "valid JSON"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := accountRequest(t, server, http.MethodPatch, test.path, test.body, test.token)
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != test.status || !strings.Contains(string(body), test.piece) {
				t.Fatalf("status %d, want %d, body %s", response.StatusCode, test.status, body)
			}
		})
	}

	response := accountRequest(t, server, http.MethodPatch, path, `{
		"mutations":[
			{"operation":"set","index":0,"text":"structured edit"},
			{"operation":"append","code":99,"payload":"deadbeef"}
		]
	}`, "secret")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		!strings.Contains(string(body), `"text":"structured edit"`) ||
		!strings.Contains(string(body), `"key":"unknown_99"`) ||
		!strings.Contains(string(body), `"payload":"deadbeef"`) {
		t.Fatalf("structured update status %d: %s", response.StatusCode, body)
	}

	version, err := db.FunctionVersion(context.Background(), versionID)
	if err != nil || len(version.Comments) != 1 || version.Comments[0].Text != "structured edit" {
		t.Fatalf("stored structured update = %#v, %v", version, err)
	}
	history, err := db.ListHistory(context.Background(), store.HistoryFilter{}, 10, 0)
	if err != nil || len(history) != 2 {
		t.Fatalf("history after structured update = %#v, %v", history, err)
	}
	diff, err := db.FunctionChangeDiff(context.Background(), history[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	foundSemantic := false
	for _, field := range diff.Fields {
		if field.Field == "metadata.function_comment" &&
			field.Before == "useful comment" && field.After == "structured edit" {
			foundSemantic = true
		}
	}
	if !foundSemantic {
		t.Fatalf("semantic history diff missing: %#v", diff.Fields)
	}
}

func TestProjectAndMetadataManagementAPI(t *testing.T) {
	db, hash, _ := populatedWebStore(t)
	projects, err := db.ListProjects(context.Background(), "", 10, 0)
	if err != nil || len(projects) != 1 {
		t.Fatalf("projects: %#v, %v", projects, err)
	}
	projectID := projects[0].ID
	versions, err := db.Function(context.Background(), hash)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions: %#v, %v", versions, err)
	}
	versionID := versions[0].ID
	server := newWebTestServer(t, config.Config{AdminToken: "secret", AllowDeletes: true}, db)
	defer server.Close()

	projectPath := "/api/v1/projects/" + strconv.FormatInt(projectID, 10)
	versionPath := "/api/v1/metadata/" + strconv.FormatInt(versionID, 10)
	tests := []struct {
		name, method, path, body, token string
		status                          int
	}{
		{"project update unauthorized", http.MethodPatch, projectPath, `{"idb_path":"x.i64"}`, "", http.StatusUnauthorized},
		{"project update empty", http.MethodPatch, projectPath, `{}`, "secret", http.StatusBadRequest},
		{"project update malformed", http.MethodPatch, projectPath, `{`, "secret", http.StatusBadRequest},
		{"project update missing", http.MethodPatch, "/api/v1/projects/999999", `{"idb_path":"x.i64"}`, "secret", http.StatusNotFound},
		{"metadata update unauthorized", http.MethodPatch, versionPath, `{"name":"x"}`, "", http.StatusUnauthorized},
		{"metadata update empty", http.MethodPatch, versionPath, `{}`, "secret", http.StatusBadRequest},
		{"metadata update invalid hex", http.MethodPatch, versionPath, `{"metadata":"xyz"}`, "secret", http.StatusBadRequest},
		{"metadata update missing", http.MethodPatch, "/api/v1/metadata/999999", `{"name":"x"}`, "secret", http.StatusNotFound},
		{"delete project unauthorized", http.MethodDelete, projectPath, "", "", http.StatusUnauthorized},
		{"delete metadata unauthorized", http.MethodDelete, versionPath, "", "", http.StatusUnauthorized},
		{"delete metadata bad id", http.MethodDelete, "/api/v1/metadata/nope", "", "secret", http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := accountRequest(t, server, test.method, test.path, test.body, test.token)
			defer response.Body.Close()
			if response.StatusCode != test.status {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status %d, want %d: %s", response.StatusCode, test.status, body)
			}
		})
	}

	response := accountRequest(t, server, http.MethodPatch, projectPath,
		`{"file_path":"/new/sample.exe","idb_path":"/new/sample.i64"}`, "secret")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"/new/sample.i64"`) {
		t.Fatalf("project update status %d: %s", response.StatusCode, body)
	}
	response = accountRequest(t, server, http.MethodPatch, versionPath,
		`{"name":"managed_name","length":77,"metadata":"00010203"}`, "secret")
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"name":"managed_name"`) ||
		!strings.Contains(string(body), `"metadata":"00010203"`) {
		t.Fatalf("metadata update status %d: %s", response.StatusCode, body)
	}

	response = accountRequest(t, server, http.MethodDelete, versionPath, "", "secret")
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"deleted_versions":1`) {
		t.Fatalf("metadata delete status %d: %s", response.StatusCode, body)
	}
	response = accountRequest(t, server, http.MethodDelete, versionPath, "", "secret")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("missing metadata delete status %d", response.StatusCode)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodDelete, projectPath, "", "secret")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("orphaned project should be gone, status %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestProjectAndMetadataDeletesDisabled(t *testing.T) {
	db, hash, _ := populatedWebStore(t)
	projects, _ := db.ListProjects(context.Background(), "", 10, 0)
	versions, _ := db.Function(context.Background(), hash)
	server := newWebTestServer(t, config.Config{AllowDeletes: false}, db)
	defer server.Close()
	for _, path := range []string{
		"/api/v1/projects/" + strconv.FormatInt(projects[0].ID, 10),
		"/api/v1/metadata/" + strconv.FormatInt(versions[0].ID, 10),
		"/api/v1/pushes/1",
		"/api/v1/history/1",
	} {
		response := accountRequest(t, server, http.MethodDelete, path, "", "")
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status %d", path, response.StatusCode)
		}
		response.Body.Close()
	}
}

func TestAccountManagementAPI(t *testing.T) {
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	authService := auth.New(db)
	if err := authService.Bootstrap(context.Background(), "guest", "guest password"); err != nil {
		t.Fatal(err)
	}

	unprotected := newWebTestServer(t, config.Config{}, db)
	response := accountRequest(t, unprotected, http.MethodGet, "/api/v1/accounts", "", "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unconfigured admin token status %d", response.StatusCode)
	}
	response.Body.Close()
	unprotected.Close()

	server := newWebTestServer(t, config.Config{AdminToken: "secret"}, db)
	defer server.Close()
	response = accountRequest(t, server, http.MethodGet, "/api/v1/accounts", "", "")
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("unprotected account list status %d", response.StatusCode)
	}
	response.Body.Close()

	response = accountRequest(t, server, http.MethodGet, "/api/v1/accounts", "", "secret")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		!strings.Contains(string(body), `"username":"guest"`) ||
		!strings.Contains(string(body), `"is_admin":true`) ||
		!strings.Contains(string(body), `"can_delete_history":true`) {
		t.Fatalf("account list status %d: %s", response.StatusCode, body)
	}

	response = accountRequest(t, server, http.MethodPost, "/api/v1/accounts",
		`{"username":"Analyst","password":"correct horse","email":"analyst@example.test","license_id":"ab-1234-cdef-90","can_delete_history":true}`,
		"secret")
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("create account status %d: %s", response.StatusCode, body)
	}
	response.Body.Close()
	if _, err := authService.Authenticate(context.Background(), "analyst", "correct horse"); err != nil {
		t.Fatalf("new account did not authenticate: %v", err)
	}
	record, err := db.AuthAccountByUsername(context.Background(), "analyst")
	if err != nil || record.IsAdmin || !record.CanDeleteHistory ||
		record.Email != "analyst@example.test" || record.LicenseID != "AB-1234-CDEF-90" {
		t.Fatalf("new account profile %#v: %v", record, err)
	}

	for _, test := range []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{"duplicate", http.MethodPost, "/api/v1/accounts", `{"username":"analyst","password":"another pass"}`, http.StatusConflict},
		{"short password", http.MethodPost, "/api/v1/accounts", `{"username":"short","password":"bad"}`, http.StatusBadRequest},
		{"invalid create email", http.MethodPost, "/api/v1/accounts", `{"username":"owner","password":"valid password","email":"bad\u000amail"}`, http.StatusBadRequest},
		{"invalid create license", http.MethodPost, "/api/v1/accounts", `{"username":"owner","password":"valid password","license_id":"bad"}`, http.StatusBadRequest},
		{"malformed JSON", http.MethodPost, "/api/v1/accounts", `{`, http.StatusBadRequest},
		{"unknown JSON field", http.MethodPost, "/api/v1/accounts", `{"username":"x","password":"valid pass","extra":true}`, http.StatusBadRequest},
		{"multiple JSON values", http.MethodPost, "/api/v1/accounts", `{"username":"x","password":"valid pass"} {}`, http.StatusBadRequest},
		{"missing enabled", http.MethodPatch, "/api/v1/accounts/Analyst", `{}`, http.StatusBadRequest},
		{"missing account enable", http.MethodPatch, "/api/v1/accounts/missing", `{"enabled":true}`, http.StatusNotFound},
		{"invalid profile email", http.MethodPatch, "/api/v1/accounts/Analyst", `{"email":"bad\u000amail"}`, http.StatusBadRequest},
		{"invalid profile license", http.MethodPatch, "/api/v1/accounts/Analyst", `{"license_id":"bad"}`, http.StatusBadRequest},
		{"missing account profile", http.MethodPatch, "/api/v1/accounts/missing", `{"is_admin":true}`, http.StatusNotFound},
		{"malformed password JSON", http.MethodPut, "/api/v1/accounts/Analyst/password", `{`, http.StatusBadRequest},
		{"missing account password", http.MethodPut, "/api/v1/accounts/missing/password", `{"password":"new password"}`, http.StatusNotFound},
		{"missing account delete", http.MethodDelete, "/api/v1/accounts/missing", ``, http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := accountRequest(t, server, test.method, test.path, test.body, "secret")
			defer response.Body.Close()
			if response.StatusCode != test.status {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status %d, want %d: %s", response.StatusCode, test.status, body)
			}
		})
	}

	response = accountRequest(t, server, http.MethodPut, "/api/v1/accounts/Analyst/password", `{"password":"rotated password"}`, "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rotate password status %d", response.StatusCode)
	}
	response.Body.Close()
	if _, err := authService.Authenticate(context.Background(), "Analyst", "rotated password"); err != nil {
		t.Fatalf("rotated account did not authenticate: %v", err)
	}
	response = accountRequest(t, server, http.MethodPatch, "/api/v1/accounts/Analyst",
		`{"email":"new@example.test","is_admin":true,"can_delete_history":false}`, "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("profile update status %d", response.StatusCode)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodPatch, "/api/v1/accounts/Analyst", `{"enabled":false}`, "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disable account status %d", response.StatusCode)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodPatch, "/api/v1/accounts/Analyst", `{"enabled":true}`, "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("enable account status %d", response.StatusCode)
	}
	response.Body.Close()

	response = accountRequest(t, server, http.MethodDelete, "/api/v1/accounts/guest", "", "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete guest status %d", response.StatusCode)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodDelete, "/api/v1/accounts/Analyst", "", "secret")
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("delete last account status %d", response.StatusCode)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodPatch, "/api/v1/accounts/Analyst", `{"enabled":false}`, "secret")
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("disable last account status %d", response.StatusCode)
	}
	response.Body.Close()

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	response = accountRequest(t, server, http.MethodGet, "/api/v1/accounts", "", "secret")
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("closed database account list status %d", response.StatusCode)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodPost, "/api/v1/accounts", `{"username":"closed","password":"valid password"}`, "secret")
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("closed database account create status %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestSessionManagementAPI(t *testing.T) {
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	registry := session.NewRegistry()
	var clients []net.Conn
	for _, identity := range []session.Identity{
		{
			AccountID: 1, Username: "Analyst", CanDeleteHistory: true,
			RemoteAddress: "192.0.2.10:4567", ProtocolVersion: 5,
		},
		{
			AccountID: 2, Username: "regular",
			RemoteAddress: "192.0.2.11:4568", ProtocolVersion: 4,
		},
	} {
		client, peer := net.Pipe()
		clients = append(clients, client)
		registry.Register(identity, session.Track(peer))
	}
	t.Cleanup(func() {
		for _, client := range clients {
			_ = client.Close()
		}
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(NewWithSessions(
		config.Config{AdminToken: "secret"}, db, observability.NewMetrics(), log, registry,
	).Handler())
	defer server.Close()

	response := accountRequest(t, server, http.MethodGet, "/api/v1/sessions", "", "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized list status %d", response.StatusCode)
	}
	response.Body.Close()
	response = accountRequest(t, server, http.MethodGet, "/api/v1/sessions", "", "secret")
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		!strings.Contains(string(body), `"count":2`) ||
		!strings.Contains(string(body), `"username":"Analyst"`) ||
		!strings.Contains(string(body), `"remote_address":"192.0.2.10:4567"`) {
		t.Fatalf("session list status %d: %s", response.StatusCode, body)
	}

	for _, test := range []struct {
		name, path string
		status     int
	}{
		{"invalid", "/api/v1/sessions/nope", http.StatusBadRequest},
		{"zero", "/api/v1/sessions/0", http.StatusBadRequest},
		{"missing", "/api/v1/sessions/999", http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := accountRequest(t, server, http.MethodDelete, test.path, "", "secret")
			defer response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status %d, want %d", response.StatusCode, test.status)
			}
		})
	}

	response = accountRequest(t, server, http.MethodDelete, "/api/v1/sessions/1", "", "secret")
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		!strings.Contains(string(body), `"username":"Analyst"`) {
		t.Fatalf("terminate status %d: %s", response.StatusCode, body)
	}
	if _, err := clients[0].Write([]byte("closed")); err == nil {
		t.Fatal("terminated client remained connected")
	}

	response = accountRequest(t, server, http.MethodDelete, "/api/v1/accounts/REGULAR/sessions", "", "secret")
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"terminated":1`) {
		t.Fatalf("account termination status %d: %s", response.StatusCode, body)
	}
	if _, err := clients[1].Write([]byte("closed")); err == nil {
		t.Fatal("account-terminated client remained connected")
	}

	response = accountRequest(t, server, http.MethodGet, "/api/v1/sessions", "", "secret")
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"count":0`) {
		t.Fatalf("empty session list status %d: %s", response.StatusCode, body)
	}
}

func TestAccountSecurityChangesRevokeSessions(t *testing.T) {
	db, err := store.Open(testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	authService := auth.New(db)
	if err := authService.Bootstrap(context.Background(), "guest", "guest password"); err != nil {
		t.Fatal(err)
	}
	analyst, err := authService.Create(context.Background(), "analyst", "analyst password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authService.Create(context.Background(), "backup", "backup password"); err != nil {
		t.Fatal(err)
	}
	registry := session.NewRegistry()
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	server := httptest.NewServer(NewWithSessions(
		config.Config{AdminToken: "secret"}, db, observability.NewMetrics(), log, registry,
	).Handler())
	defer server.Close()

	register := func() net.Conn {
		client, peer := net.Pipe()
		registry.Register(session.Identity{
			AccountID: analyst.ID, Username: analyst.Username,
			IsAdmin: analyst.IsAdmin, CanDeleteHistory: analyst.CanDeleteHistory,
		}, session.Track(peer))
		return client
	}
	assertRevoked := func(client net.Conn) {
		t.Helper()
		defer client.Close()
		if _, err := client.Write([]byte("closed")); err == nil {
			t.Fatal("security change left the client connected")
		}
		if active := registry.List(); len(active) != 0 {
			t.Fatalf("revoked session remains registered: %#v", active)
		}
	}

	client := register()
	response := accountRequest(t, server, http.MethodPatch,
		"/api/v1/accounts/analyst", `{"can_delete_history":true}`, "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("privilege change status %d", response.StatusCode)
	}
	response.Body.Close()
	assertRevoked(client)

	client = register()
	response = accountRequest(t, server, http.MethodPut,
		"/api/v1/accounts/analyst/password", `{"password":"rotated password"}`, "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("password change status %d", response.StatusCode)
	}
	response.Body.Close()
	assertRevoked(client)

	client = register()
	response = accountRequest(t, server, http.MethodPatch,
		"/api/v1/accounts/analyst", `{"enabled":false}`, "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disable status %d", response.StatusCode)
	}
	response.Body.Close()
	assertRevoked(client)
	response = accountRequest(t, server, http.MethodPatch,
		"/api/v1/accounts/analyst", `{"enabled":true}`, "secret")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("enable status %d", response.StatusCode)
	}

	client = register()
	response = accountRequest(t, server, http.MethodDelete,
		"/api/v1/accounts/analyst", "", "secret")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d", response.StatusCode)
	}
	response.Body.Close()
	assertRevoked(client)

	response = accountRequest(t, server, http.MethodPost, "/api/v1/accounts",
		`{"username":"operator","password":"operator password","is_admin":true}`, "secret")
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status %d", response.StatusCode)
	}
	for _, piece := range []string{
		"authentication account created",
		"authentication account password changed",
		"authentication account updated",
		"authentication account deleted",
		"terminated_sessions=1",
	} {
		if !strings.Contains(logs.String(), piece) {
			t.Errorf("audit log missing %q: %s", piece, logs.String())
		}
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
	projects, _ := db.ListProjects(context.Background(), "", 10, 0)
	versions, _ := db.Function(context.Background(), hash)
	pushes, _ := db.ListPushes(context.Background(), store.PushFilter{}, 10, 0)
	changes, _ := db.ListHistory(context.Background(), store.HistoryFilter{}, 10, 0)
	projectID := strconv.FormatInt(projects[0].ID, 10)
	versionID := strconv.FormatInt(versions[0].ID, 10)
	pushID := strconv.FormatInt(pushes[0].ID, 10)
	changeID := strconv.FormatInt(changes[0].ID, 10)
	server := newWebTestServer(t, config.Config{AllowDeletes: true}, db)
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
		{"/api/v1/stats?username=analyst", http.StatusInternalServerError},
		{"/api/v1/functions", http.StatusInternalServerError},
		{"/api/v1/functions/" + hash, http.StatusInternalServerError},
		{"/api/v1/files", http.StatusInternalServerError},
		{"/api/v1/files/" + md5 + "/functions", http.StatusInternalServerError},
		{"/api/v1/projects", http.StatusInternalServerError},
		{"/api/v1/projects/" + projectID, http.StatusInternalServerError},
		{"/api/v1/metadata/" + versionID, http.StatusInternalServerError},
		{"/api/v1/pushes", http.StatusInternalServerError},
		{"/api/v1/pushes/" + pushID, http.StatusInternalServerError},
		{"/api/v1/history", http.StatusInternalServerError},
		{"/api/v1/history/" + changeID, http.StatusInternalServerError},
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
	for _, test := range []struct {
		method, path, body string
	}{
		{http.MethodPatch, "/api/v1/projects/" + projectID, `{"idb_path":"x"}`},
		{http.MethodDelete, "/api/v1/projects/" + projectID, ""},
		{http.MethodPatch, "/api/v1/metadata/" + versionID, `{"name":"x"}`},
		{http.MethodDelete, "/api/v1/metadata/" + versionID, ""},
		{http.MethodPost, "/api/v1/history/" + changeID + "/restore", ""},
		{http.MethodDelete, "/api/v1/history/" + changeID, ""},
		{http.MethodDelete, "/api/v1/pushes/" + pushID, ""},
	} {
		response := accountRequest(t, server, test.method, test.path, test.body, "")
		if response.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s: status %d", test.method, test.path, response.StatusCode)
		}
		response.Body.Close()
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
		LicenseNumber: []byte{1, 2, 3, 4, 5, 6}, LicenseData: []byte("license"),
		Hostname: "host", Username: "analyst",
		AccountLicenseID: "AB-1234-CDEF-90", AccountEmail: "analyst@example.test",
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

func accountRequest(t *testing.T, server *httptest.Server, method, path, body, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
