package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/segfaultd/lux/internal/config"
	"github.com/segfaultd/lux/internal/observability"
	"github.com/segfaultd/lux/internal/store"
)

//go:embed static/*
var assets embed.FS

type Server struct {
	cfg     config.Config
	store   *store.Store
	metrics *observability.Metrics
	log     *slog.Logger
	handler http.Handler
}

func New(cfg config.Config, store *store.Store, metrics *observability.Metrics, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: store, metrics: metrics, log: log}
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
		"server_name":     s.cfg.ServerName,
		"lumina_addr":     s.cfg.LuminaAddr,
		"tls":             s.cfg.TLSCert != "",
		"allow_deletes":   s.cfg.AllowDeletes,
		"admin_protected": s.cfg.AdminToken != "",
		"history_limit":   s.cfg.HistoryLimit,
	})
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
	if !s.cfg.AllowDeletes {
		writeError(w, http.StatusForbidden, "deletions are disabled")
		return
	}
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="lux management"`)
		writeError(w, http.StatusUnauthorized, "valid admin token required")
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
