package web

import (
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/segfaultd/lux/internal/access"
	authn "github.com/segfaultd/lux/internal/auth"
	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/metadata"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/store"
)

//go:embed static/*
var assets embed.FS

type Server struct {
	cfg     config.Config
	store   *store.Store
	auth    *authn.Service
	metrics *observability.Metrics
	log     *slog.Logger
	handler http.Handler
}

func New(cfg config.Config, store *store.Store, metrics *observability.Metrics, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: store, auth: authn.New(store), metrics: metrics, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /metrics", s.prometheus)
	mux.HandleFunc("GET /api/v1/config", s.getConfig)
	mux.HandleFunc("GET /api/v1/stats", s.getStats)
	mux.HandleFunc("GET /api/v1/functions", s.listFunctions)
	mux.HandleFunc("GET /api/v1/functions/{hash}", s.getFunction)
	mux.HandleFunc("DELETE /api/v1/functions/{hash}", s.deleteFunction)
	mux.HandleFunc("GET /api/v1/files", s.listFiles)
	mux.HandleFunc("GET /api/v1/files/{md5}/functions", s.getFileFunctions)
	mux.HandleFunc("GET /api/v1/projects", s.listProjects)
	mux.HandleFunc("GET /api/v1/projects/{id}", s.getProject)
	mux.HandleFunc("PATCH /api/v1/projects/{id}", s.updateProject)
	mux.HandleFunc("DELETE /api/v1/projects/{id}", s.deleteProject)
	mux.HandleFunc("GET /api/v1/metadata/{id}", s.getMetadata)
	mux.HandleFunc("PATCH /api/v1/metadata/{id}", s.updateMetadata)
	mux.HandleFunc("DELETE /api/v1/metadata/{id}", s.deleteMetadata)
	mux.HandleFunc("GET /api/v1/metadata/{id}/structured", s.getStructuredMetadata)
	mux.HandleFunc("PATCH /api/v1/metadata/{id}/structured", s.updateStructuredMetadata)
	mux.HandleFunc("GET /api/v1/pushes", s.listPushes)
	mux.HandleFunc("GET /api/v1/pushes/{id}", s.getPush)
	mux.HandleFunc("DELETE /api/v1/pushes/{id}", s.deletePush)
	mux.HandleFunc("GET /api/v1/history", s.listHistory)
	mux.HandleFunc("GET /api/v1/history/{id}", s.getHistory)
	mux.HandleFunc("POST /api/v1/history/{id}/restore", s.restoreHistory)
	mux.HandleFunc("DELETE /api/v1/history/{id}", s.deleteHistory)
	mux.HandleFunc("GET /api/v1/accounts", s.listAccounts)
	mux.HandleFunc("POST /api/v1/accounts", s.createAccount)
	mux.HandleFunc("PUT /api/v1/accounts/{username}/password", s.setAccountPassword)
	mux.HandleFunc("PATCH /api/v1/accounts/{username}", s.setAccountEnabled)
	mux.HandleFunc("DELETE /api/v1/accounts/{username}", s.deleteAccount)
	// Lumen-compatible read-only HTTP routes.
	mux.HandleFunc("GET /api/files/{md5}", s.legacyFile)
	mux.HandleFunc("GET /api/funcs/{hash}", s.legacyFunction)
	static, _ := fs.Sub(assets, "static")
	mux.Handle("/", http.FileServerFS(static))
	s.handler = s.middleware(mux)
	return s
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
		s.log.Debug("HTTP request", "method", r.Method, "path", r.URL.Path, "elapsed", time.Since(start))
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "functions": stats.Functions})
}

func (s *Server) prometheus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.WritePrometheus(w)
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"server_name":        s.cfg.ServerName,
		"lumina_addr":        s.cfg.LuminaAddr,
		"tls":                s.cfg.TLSCert != "",
		"allow_deletes":      s.cfg.AllowDeletes,
		"admin_protected":    s.cfg.AdminToken != "",
		"account_management": s.cfg.AdminToken != "",
		"history_limit":      s.cfg.HistoryLimit,
	})
}

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccountAdmin(w, r) {
		return
	}
	accounts, err := s.auth.List(r.Context())
	if err != nil {
		s.internalError(w, "list authentication accounts", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": accounts})
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccountAdmin(w, r) {
		return
	}
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	role := access.RoleContributor
	if request.Role != "" {
		role = access.Role(request.Role)
	}
	account, err := s.auth.CreateWithRole(r.Context(), request.Username, request.Password, role)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, account)
}

func (s *Server) setAccountPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccountAdmin(w, r) {
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	account, err := s.auth.SetPassword(r.Context(), r.PathValue("username"), request.Password)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, account)
}

func (s *Server) setAccountEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccountAdmin(w, r) {
		return
	}
	var request struct {
		Enabled *bool   `json:"enabled"`
		Role    *string `json:"role"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if (request.Enabled == nil) == (request.Role == nil) {
		writeError(w, http.StatusBadRequest, "exactly one of enabled or role is required")
		return
	}
	var account store.AuthAccount
	var err error
	if request.Role != nil {
		account, err = s.auth.SetRole(r.Context(), r.PathValue("username"), access.Role(*request.Role))
	} else {
		account, err = s.auth.SetEnabled(r.Context(), r.PathValue("username"), *request.Enabled)
	}
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, account)
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if !s.requireAccountAdmin(w, r) {
		return
	}
	account, err := s.auth.Delete(r.Context(), r.PathValue("username"))
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, account)
}

func (s *Server) requireAccountAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		writeError(w, http.StatusForbidden, "configure an admin token to manage authentication accounts")
		return false
	}
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="lux management"`)
		writeError(w, http.StatusUnauthorized, "valid admin token required")
		return false
	}
	return true
}

func (s *Server) writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authn.ErrInvalidUsername), errors.Is(err, authn.ErrInvalidPassword),
		errors.Is(err, access.ErrInvalidRole):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, store.ErrAuthAccountExists), errors.Is(err, store.ErrLastAuthAccount):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrAuthAccountNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		s.internalError(w, "manage authentication account", err)
	}
}

func (s *Server) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		s.internalError(w, "load stats", err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) listFunctions(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	functions, err := s.store.ListFunctions(r.Context(), r.URL.Query().Get("q"), limit, offset)
	if err != nil {
		s.internalError(w, "list functions", err)
		return
	}
	if functions == nil {
		functions = []store.FunctionSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": functions, "limit": limit, "offset": offset})
}

func (s *Server) getFunction(w http.ResponseWriter, r *http.Request) {
	versions, err := s.store.Function(r.Context(), r.PathValue("hash"))
	if err != nil {
		if isHashError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			s.internalError(w, "get function", err)
		}
		return
	}
	if len(versions) == 0 {
		writeError(w, http.StatusNotFound, "function not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hash": strings.ToUpper(r.PathValue("hash")), "versions": versions})
}

func (s *Server) deleteFunction(w http.ResponseWriter, r *http.Request) {
	if !s.requireDeletion(w, r) {
		return
	}
	hash := r.PathValue("hash")
	if len(hash) != 32 {
		writeError(w, http.StatusBadRequest, "hash must contain exactly 32 hexadecimal characters")
		return
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(hash[i*2:i*2+2], 16, 8)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid hexadecimal hash")
			return
		}
		raw[i] = byte(v)
	}
	deleted, err := s.store.DeleteHashes(r.Context(), [][]byte{raw})
	if err != nil {
		s.internalError(w, "delete function", err)
		return
	}
	if deleted == 0 {
		writeError(w, http.StatusNotFound, "function not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted_versions": deleted})
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	projects, err := s.store.ListProjects(r.Context(), r.URL.Query().Get("q"), limit, offset)
	if err != nil {
		s.internalError(w, "list projects", err)
		return
	}
	if projects == nil {
		projects = []store.ProjectSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": projects, "limit": limit, "offset": offset})
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	project, err := s.store.Project(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.internalError(w, "get project", err)
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var request struct {
		FilePath *string `json:"file_path"`
		IDBPath  *string `json:"idb_path"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.FilePath == nil && request.IDBPath == nil {
		writeError(w, http.StatusBadRequest, "file_path or idb_path is required")
		return
	}
	current, err := s.store.Project(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		s.internalError(w, "get project for update", err)
		return
	}
	filePath, idbPath := current.FilePath, current.IDBPath
	if request.FilePath != nil {
		filePath = *request.FilePath
	}
	if request.IDBPath != nil {
		idbPath = *request.IDBPath
	}
	project, err := s.store.UpdateProject(r.Context(), id, filePath, idbPath)
	if err != nil {
		s.internalError(w, "update project", err)
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	if !s.requireDeletion(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	result, err := s.store.DeleteProject(r.Context(), id)
	if err != nil {
		s.internalError(w, "delete project", err)
		return
	}
	if !result.Found {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getMetadata(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	version, err := s.store.FunctionVersion(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "metadata version not found")
		return
	}
	if err != nil {
		s.internalError(w, "get metadata version", err)
		return
	}
	writeJSON(w, http.StatusOK, version)
}

func (s *Server) getStructuredMetadata(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	version, err := s.store.FunctionVersion(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "metadata version not found")
		return
	}
	if err != nil {
		s.internalError(w, "get structured metadata", err)
		return
	}
	rawMetadata, err := hex.DecodeString(version.Metadata)
	if err != nil {
		s.internalError(w, "decode stored metadata", err)
		return
	}
	writeStructuredMetadata(w, version, rawMetadata)
}

func (s *Server) updateStructuredMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var request metadata.PatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	current, err := s.store.FunctionVersion(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "metadata version not found")
		return
	}
	if err != nil {
		s.internalError(w, "get metadata version for structured update", err)
		return
	}
	rawMetadata, err := hex.DecodeString(current.Metadata)
	if err != nil {
		s.internalError(w, "decode stored metadata", err)
		return
	}
	patched, err := metadata.ApplyPatch(rawMetadata, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	version, err := s.store.UpdateFunctionVersion(
		r.Context(), id, current.Name, current.Length, patched)
	if err != nil {
		s.internalError(w, "update structured metadata", err)
		return
	}
	writeStructuredMetadata(w, version, patched)
}

func writeStructuredMetadata(w http.ResponseWriter, version store.FunctionVersion, rawMetadata []byte) {
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       version.ID,
		"hash":     version.Hash,
		"name":     version.Name,
		"length":   version.Length,
		"score":    version.Score,
		"document": metadata.Inspect(rawMetadata),
	})
}

func (s *Server) updateMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var request struct {
		Name     *string `json:"name"`
		Length   *uint32 `json:"length"`
		Metadata *string `json:"metadata"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Name == nil && request.Length == nil && request.Metadata == nil {
		writeError(w, http.StatusBadRequest, "name, length, or metadata is required")
		return
	}
	current, err := s.store.FunctionVersion(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "metadata version not found")
		return
	}
	if err != nil {
		s.internalError(w, "get metadata version for update", err)
		return
	}
	name, length := current.Name, current.Length
	rawMetadata, err := hex.DecodeString(current.Metadata)
	if err != nil {
		s.internalError(w, "decode stored metadata", err)
		return
	}
	if request.Name != nil {
		name = *request.Name
	}
	if request.Length != nil {
		length = *request.Length
	}
	if request.Metadata != nil {
		rawMetadata, err = hex.DecodeString(strings.TrimSpace(*request.Metadata))
		if err != nil {
			writeError(w, http.StatusBadRequest, "metadata must be hexadecimal")
			return
		}
	}
	version, err := s.store.UpdateFunctionVersion(r.Context(), id, name, length, rawMetadata)
	if err != nil {
		s.internalError(w, "update metadata version", err)
		return
	}
	writeJSON(w, http.StatusOK, version)
}

func (s *Server) deleteMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.requireDeletion(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	result, err := s.store.DeleteFunctionVersion(r.Context(), id)
	if err != nil {
		s.internalError(w, "delete metadata version", err)
		return
	}
	if !result.Found {
		writeError(w, http.StatusNotFound, "metadata version not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listPushes(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	from, to, ok := timeRange(w, r)
	if !ok {
		return
	}
	projectID, ok := optionalQueryID(w, r, "project_id")
	if !ok {
		return
	}
	pushes, err := s.store.ListPushes(r.Context(), store.PushFilter{
		Search: r.URL.Query().Get("q"), Username: r.URL.Query().Get("username"),
		ProjectID: projectID, From: from, To: to,
	}, limit, offset)
	if err != nil {
		s.internalError(w, "list pushes", err)
		return
	}
	if pushes == nil {
		pushes = []store.PushSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": pushes, "limit": limit, "offset": offset})
}

func (s *Server) getPush(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	push, err := s.store.PushRecord(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "push not found")
		return
	}
	if err != nil {
		s.internalError(w, "get push", err)
		return
	}
	writeJSON(w, http.StatusOK, push)
}

func (s *Server) deletePush(w http.ResponseWriter, r *http.Request) {
	if !s.requireDeletion(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	result, err := s.store.DeletePush(r.Context(), id)
	if err != nil {
		s.internalError(w, "delete push", err)
		return
	}
	if !result.Found {
		writeError(w, http.StatusNotFound, "push not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listHistory(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	from, to, ok := timeRange(w, r)
	if !ok {
		return
	}
	projectID, ok := optionalQueryID(w, r, "project_id")
	if !ok {
		return
	}
	pushID, ok := optionalQueryID(w, r, "push_id")
	if !ok {
		return
	}
	hash := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("hash")))
	if hash != "" {
		raw, err := hex.DecodeString(hash)
		if err != nil || len(raw) != 16 {
			writeError(w, http.StatusBadRequest, "hash must contain exactly 32 hexadecimal characters")
			return
		}
	}
	changes, err := s.store.ListHistory(r.Context(), store.HistoryFilter{
		Search: r.URL.Query().Get("q"), Username: r.URL.Query().Get("username"), Hash: hash,
		ProjectID: projectID, PushID: pushID, From: from, To: to,
	}, limit, offset)
	if err != nil {
		s.internalError(w, "list history", err)
		return
	}
	if changes == nil {
		changes = []store.HistoryChange{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": changes, "limit": limit, "offset": offset})
}

func (s *Server) getHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	diff, err := s.store.FunctionChangeDiff(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "history record not found")
		return
	}
	if err != nil {
		s.internalError(w, "get history record", err)
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

func (s *Server) restoreHistory(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	change, err := s.store.RestoreFunctionChange(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "history record not found")
		return
	}
	if err != nil {
		s.internalError(w, "restore history record", err)
		return
	}
	writeJSON(w, http.StatusCreated, change)
}

func (s *Server) deleteHistory(w http.ResponseWriter, r *http.Request) {
	if !s.requireDeletion(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	result, err := s.store.DeleteFunctionChange(r.Context(), id)
	if err != nil {
		s.internalError(w, "delete history record", err)
		return
	}
	if !result.Found {
		writeError(w, http.StatusNotFound, "history record not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	files, err := s.store.ListFiles(r.Context(), r.URL.Query().Get("q"), limit, offset)
	if err != nil {
		s.internalError(w, "list files", err)
		return
	}
	if files == nil {
		files = []store.FileSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": files, "limit": limit, "offset": offset})
}

func (s *Server) getFileFunctions(w http.ResponseWriter, r *http.Request) {
	functions, err := s.store.FileFunctions(r.Context(), r.PathValue("md5"))
	if err != nil {
		if isHashError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			s.internalError(w, "get file functions", err)
		}
		return
	}
	if functions == nil {
		functions = []store.FunctionSummary{}
	}
	writeJSON(w, http.StatusOK, functions)
}

func (s *Server) legacyFile(w http.ResponseWriter, r *http.Request) {
	functions, err := s.store.FileFunctions(r.Context(), r.PathValue("md5"))
	if err != nil {
		if isHashError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			s.internalError(w, "get legacy file", err)
		}
		return
	}
	type legacyFunction struct {
		Hash string `json:"hash"`
		Len  uint32 `json:"len"`
		Name string `json:"name"`
	}
	out := make([]legacyFunction, len(functions))
	for i, f := range functions {
		out[i] = legacyFunction{Hash: f.Hash, Len: f.Length, Name: f.Name}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) legacyFunction(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	versions, err := s.store.Function(r.Context(), hash)
	if err != nil {
		if isHashError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			s.internalError(w, "get legacy function", err)
		}
		return
	}
	if len(versions) == 0 {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	files, err := s.store.FilesWithFunction(r.Context(), hash)
	if err != nil {
		s.internalError(w, "find function files", err)
		return
	}
	type legacyComment struct {
		Offset  *uint32 `json:"offset,omitempty"`
		Type    any     `json:"type"`
		Comment string  `json:"comment"`
	}
	comments := make([]legacyComment, 0, len(versions[0].Comments))
	for _, comment := range versions[0].Comments {
		if comment.Type == "parse-error" {
			continue
		}
		var kind any
		switch comment.Type {
		case "anterior":
			kind = "Anterior"
		case "posterior":
			kind = "Posterior"
		case "function":
			kind = map[string]any{"Function": map[string]bool{"repeatable": comment.Repeatable}}
		default:
			kind = map[string]any{"Byte": map[string]bool{"repeatable": comment.Repeatable}}
		}
		comments = append(comments, legacyComment{Offset: comment.Offset, Type: kind, Comment: comment.Text})
	}
	type legacyInfo struct {
		Name     string          `json:"name"`
		Comments []legacyComment `json:"comments"`
		Length   uint32          `json:"length"`
		InFiles  []string        `json:"in_files"`
	}
	writeJSON(w, http.StatusOK, []legacyInfo{{
		Name: versions[0].Name, Comments: comments, Length: versions[0].Length, InFiles: files,
	}})
}

func (s *Server) authorized(r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		return true
	}
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	value = strings.TrimSpace(value)
	return subtle.ConstantTimeCompare([]byte(value), []byte(s.cfg.AdminToken)) == 1
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.authorized(r) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="lux management"`)
	writeError(w, http.StatusUnauthorized, "valid admin token required")
	return false
}

func (s *Server) requireDeletion(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.AllowDeletes {
		writeError(w, http.StatusForbidden, "deletions are disabled")
		return false
	}
	return s.requireAdmin(w, r)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "id must be a positive integer")
		return 0, false
	}
	return id, true
}

func isHashError(err error) bool {
	return strings.Contains(err.Error(), "hash") || strings.Contains(err.Error(), "hexadecimal")
}

func (s *Server) internalError(w http.ResponseWriter, operation string, err error) {
	s.log.Error(operation, "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}

func pagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit < 1 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func optionalQueryID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, name+" must be a positive integer")
		return 0, false
	}
	return id, true
}

func timeRange(w http.ResponseWriter, r *http.Request) (*time.Time, *time.Time, bool) {
	parse := func(name string) (*time.Time, bool) {
		value := strings.TrimSpace(r.URL.Query().Get(name))
		if value == "" {
			return nil, true
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, name+" must be an RFC3339 timestamp")
			return nil, false
		}
		return &parsed, true
	}
	from, ok := parse("from")
	if !ok {
		return nil, nil, false
	}
	to, ok := parse("to")
	if !ok {
		return nil, nil, false
	}
	if from != nil && to != nil && from.After(*to) {
		writeError(w, http.StatusBadRequest, "from must not be later than to")
		return nil, nil, false
	}
	return from, to, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		_, _ = fmt.Fprintln(w)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "request must contain one JSON object")
		return false
	}
	return true
}
