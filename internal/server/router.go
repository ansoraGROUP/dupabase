package server

import (
	"encoding/json"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	apiAuth "github.com/ansoraGROUP/dupabase/internal/api/auth"
	apiRest "github.com/ansoraGROUP/dupabase/internal/api/rest"
	"github.com/ansoraGROUP/dupabase/internal/database"
	"github.com/ansoraGROUP/dupabase/internal/middleware"
	"github.com/ansoraGROUP/dupabase/internal/platform"
)

type Server struct {
	mux             *http.ServeMux
	authService     *platform.AuthService
	projectService  *platform.ProjectService
	credService     *platform.CredentialService
	auditService    *platform.AuditService
	backupService   *platform.BackupService
	importService   *platform.ImportService
	adminService    *platform.AdminService
	platformAuth    *middleware.PlatformAuth
	projectRouter   *middleware.ProjectRouter
	supabaseAuth    *apiAuth.Handler
	supabaseRest    *apiRest.Handler
	authLimiter     *middleware.RateLimiter // 5 req/s, burst 10 for auth endpoints
	apiLimiter      *middleware.RateLimiter // 30 req/s, burst 60 for API endpoints
	platformDB      *pgxpool.Pool
	importMaxBytes  int64
	importTempDir   string
	dashboardProxy  http.Handler
}

func New(
	authService *platform.AuthService,
	projectService *platform.ProjectService,
	credService *platform.CredentialService,
	auditService *platform.AuditService,
	backupService *platform.BackupService,
	importService *platform.ImportService,
	adminService *platform.AdminService,
	poolManager *database.PoolManager,
	platformDB *pgxpool.Pool,
	importMaxSizeMB int,
	importTempDir string,
) *Server {
	s := &Server{
		mux:            http.NewServeMux(),
		authService:    authService,
		projectService: projectService,
		credService:    credService,
		auditService:   auditService,
		backupService:  backupService,
		importService:  importService,
		adminService:   adminService,
		platformAuth:   middleware.NewPlatformAuth(authService),
		projectRouter:  middleware.NewProjectRouter(poolManager),
		supabaseAuth:   apiAuth.NewHandler(),
		supabaseRest:   apiRest.NewHandler(),
		authLimiter:    middleware.NewRateLimiter(5, 10),  // 5 req/s, burst 10
		apiLimiter:     middleware.NewRateLimiter(30, 60), // 30 req/s, burst 60
		platformDB:     platformDB,
		importMaxBytes: int64(importMaxSizeMB) * 1024 * 1024,
		importTempDir:  importTempDir,
	}

	// Set up dashboard reverse proxy if DASHBOARD_URL is configured
	// In Docker, Next.js standalone runs on port 3000 internally
	if dashURL := os.Getenv("DASHBOARD_URL"); dashURL != "" {
		target, err := url.Parse(dashURL)
		if err == nil {
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				slog.Warn("Dashboard proxy error", "error", err, "path", r.URL.Path)
				http.Error(w, "Dashboard unavailable", http.StatusBadGateway)
			}
			s.dashboardProxy = proxy
			slog.Info("Dashboard proxy enabled", "target", dashURL)
		}
	}

	s.registerRoutes()
	return s
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(cors(s.mux))
}

// securityHeaders adds security headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// Use strict CSP for API routes, relaxed CSP for dashboard
		if isAPIRoute(r.URL.Path) {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		}

		// HSTS — enable in production behind TLS
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// isAPIRoute returns true for API/platform/auth/rest routes.
func isAPIRoute(path string) bool {
	return strings.HasPrefix(path, "/platform/") ||
		strings.HasPrefix(path, "/auth/v1/") ||
		strings.HasPrefix(path, "/rest/v1/") ||
		path == "/health"
}

// maxBody limits request body size to prevent DoS via large payloads.
func maxBody(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	// Health check with DB ping
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if err := s.platformDB.Ping(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "error": "database unreachable"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Platform auth (no auth required, rate-limited)
	s.mux.Handle("POST /platform/auth/register", s.authLimiter.Middleware(maxBody(http.HandlerFunc(s.handlePlatformRegister), 1<<20)))
	s.mux.Handle("POST /platform/auth/login", s.authLimiter.Middleware(maxBody(http.HandlerFunc(s.handlePlatformLogin), 1<<20)))

	// Platform endpoints (require platform JWT)
	s.mux.Handle("GET /platform/auth/me", s.platformAuth.Middleware(http.HandlerFunc(s.handlePlatformMe)))
	s.mux.Handle("GET /platform/projects", s.platformAuth.Middleware(http.HandlerFunc(s.handleListProjects)))
	s.mux.Handle("POST /platform/projects", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleCreateProject), 1<<20)))
	s.mux.Handle("DELETE /platform/projects/{id}", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleDeleteProject), 1<<20)))
	s.mux.Handle("PUT /platform/auth/password", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleChangePassword), 1<<20)))
	s.mux.Handle("PATCH /platform/projects/{id}/settings", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleUpdateProjectSettings), 1<<20)))
	s.mux.Handle("POST /platform/credentials/reveal", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleRevealCredentials), 1<<20)))
	s.mux.Handle("POST /platform/projects/{id}/rotate-keys", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleRotateAPIKeys), 1<<20)))

	// Import endpoints (require platform JWT)
	s.mux.Handle("POST /platform/projects/{id}/import", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleStartImport), s.importMaxBytes)))
	s.mux.Handle("GET /platform/projects/{id}/import/{taskId}", s.platformAuth.Middleware(http.HandlerFunc(s.handleImportStatus)))
	s.mux.Handle("GET /platform/projects/{id}/import/history", s.platformAuth.Middleware(http.HandlerFunc(s.handleImportHistory)))
	s.mux.Handle("POST /platform/projects/{id}/import/{taskId}/cancel", s.platformAuth.Middleware(http.HandlerFunc(s.handleCancelImport)))

	// Backup endpoints (require platform JWT)
	s.mux.Handle("POST /platform/backups/settings", s.platformAuth.Middleware(maxBody(http.HandlerFunc(s.handleSaveBackupSettings), 1<<20)))
	s.mux.Handle("GET /platform/backups/settings", s.platformAuth.Middleware(http.HandlerFunc(s.handleGetBackupSettings)))
	s.mux.Handle("GET /platform/backups/history", s.platformAuth.Middleware(http.HandlerFunc(s.handleGetBackupHistory)))
	s.mux.Handle("POST /platform/backups/run", s.platformAuth.Middleware(http.HandlerFunc(s.handleRunBackupNow)))

	// Public: registration mode (for frontend to check)
	s.mux.HandleFunc("GET /platform/auth/registration-mode", s.handleRegistrationMode)

	// Admin endpoints (require platform JWT + is_admin)
	s.mux.Handle("GET /platform/admin/users", s.platformAuth.Middleware(s.adminOnly(http.HandlerFunc(s.handleAdminListUsers))))
	s.mux.Handle("DELETE /platform/admin/users/{id}", s.platformAuth.Middleware(s.adminOnly(http.HandlerFunc(s.handleAdminDeleteUser))))
	s.mux.Handle("GET /platform/admin/settings", s.platformAuth.Middleware(s.adminOnly(http.HandlerFunc(s.handleAdminGetSettings))))
	s.mux.Handle("PUT /platform/admin/settings", s.platformAuth.Middleware(s.adminOnly(maxBody(http.HandlerFunc(s.handleAdminUpdateSettings), 1<<20))))
	s.mux.Handle("GET /platform/admin/invites", s.platformAuth.Middleware(s.adminOnly(http.HandlerFunc(s.handleAdminListInvites))))
	s.mux.Handle("POST /platform/admin/invites", s.platformAuth.Middleware(s.adminOnly(maxBody(http.HandlerFunc(s.handleAdminCreateInvite), 1<<20))))
	s.mux.Handle("DELETE /platform/admin/invites/{id}", s.platformAuth.Middleware(s.adminOnly(http.HandlerFunc(s.handleAdminDeleteInvite))))

	// Supabase-compatible API (routed per-project via apikey JWT, rate-limited)
	s.mux.Handle("POST /auth/v1/signup", s.authLimiter.Middleware(maxBody(s.projectRouter.Middleware(http.HandlerFunc(s.supabaseAuth.Signup)), 1<<20)))
	s.mux.Handle("POST /auth/v1/token", s.authLimiter.Middleware(maxBody(s.projectRouter.Middleware(http.HandlerFunc(s.supabaseAuth.Token)), 1<<20)))
	s.mux.Handle("GET /auth/v1/user", s.apiLimiter.Middleware(s.projectRouter.Middleware(http.HandlerFunc(s.supabaseAuth.GetUser))))
	s.mux.Handle("PUT /auth/v1/user", s.apiLimiter.Middleware(maxBody(s.projectRouter.Middleware(http.HandlerFunc(s.supabaseAuth.UpdateUser)), 1<<20)))
	s.mux.Handle("POST /auth/v1/logout", s.apiLimiter.Middleware(maxBody(s.projectRouter.Middleware(http.HandlerFunc(s.supabaseAuth.Logout)), 1<<20)))

	// PostgREST-compatible REST API (rate-limited, body limit for mutating requests)
	s.mux.Handle("/rest/v1/rpc/", s.apiLimiter.Middleware(maxBody(s.projectRouter.Middleware(http.HandlerFunc(s.supabaseRest.HandleRPC)), 1<<20)))
	s.mux.Handle("/rest/v1/", s.apiLimiter.Middleware(maxBody(s.projectRouter.Middleware(http.HandlerFunc(s.supabaseRest.HandleTable)), 1<<20)))

	// Dashboard proxy: forward all non-API requests to the Next.js server
	if s.dashboardProxy != nil {
		s.mux.Handle("/", s.dashboardProxy)
	}
}

// ---------- Platform handlers ----------

func (s *Server) handlePlatformRegister(w http.ResponseWriter, r *http.Request) {
	var req platform.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, status, err := s.authService.Register(r.Context(), req)
	if err != nil {
		s.auditService.Log(r.Context(), nil, "register_failed", "user", "", r, map[string]interface{}{"email": req.Email})
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &resp.User.ID, "register", "user", resp.User.ID, r, nil)
	writeJSON(w, status, resp)
}

func (s *Server) handlePlatformLogin(w http.ResponseWriter, r *http.Request) {
	var req platform.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, status, err := s.authService.Login(r.Context(), req)
	if err != nil {
		s.auditService.Log(r.Context(), nil, "login_failed", "user", "", r, map[string]interface{}{"email": req.Email})
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &resp.User.ID, "login", "user", resp.User.ID, r, nil)
	writeJSON(w, status, resp)
}

func (s *Server) handlePlatformMe(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	user, err := s.authService.GetUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	projects, err := s.projectService.ListProjects(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	var req platform.CreateProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, status, err := s.projectService.CreateProject(r.Context(), userID, req)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "create_project", "project", resp.ID, r, map[string]interface{}{"name": req.Name})
	writeJSON(w, status, resp)
}

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	projectID := r.PathValue("id")

	status, err := s.projectService.DeleteProject(r.Context(), userID, projectID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "delete_project", "project", projectID, r, nil)
	writeJSON(w, status, map[string]string{"status": "deleted"})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	var req platform.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	status, err := s.authService.ChangePassword(r.Context(), userID, req)
	if err != nil {
		s.auditService.Log(r.Context(), &userID, "password_change_failed", "user", userID, r, nil)
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "password_changed", "user", userID, r, nil)
	writeJSON(w, status, map[string]string{"message": "password changed successfully"})
}

func (s *Server) handleUpdateProjectSettings(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	projectID := r.PathValue("id")
	var req platform.UpdateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, status, err := s.projectService.UpdateProjectSettings(r.Context(), userID, projectID, req)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, status, resp)
}

func (s *Server) handleRotateAPIKeys(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	projectID := r.PathValue("id")

	resp, status, err := s.projectService.RotateAPIKeys(r.Context(), userID, projectID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "rotate_api_keys", "project", projectID, r, nil)
	writeJSON(w, status, resp)
}

func (s *Server) handleRevealCredentials(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	var req platform.RevealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, status, err := s.credService.RevealCredentials(r.Context(), userID, req)
	if err != nil {
		s.auditService.Log(r.Context(), &userID, "reveal_credentials_failed", "credentials", "", r, nil)
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "reveal_credentials", "credentials", "", r, nil)
	writeJSON(w, status, resp)
}

// ---------- Backup handlers ----------

func (s *Server) handleSaveBackupSettings(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	var req platform.SaveBackupSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, status, err := s.backupService.SaveSettings(r.Context(), userID, req)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "save_backup_settings", "backup", "", r, nil)
	writeJSON(w, status, resp)
}

func (s *Server) handleGetBackupSettings(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	resp, status, err := s.backupService.GetSettings(r.Context(), userID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, status, resp)
}

func (s *Server) handleGetBackupHistory(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	resp, status, err := s.backupService.GetHistory(r.Context(), userID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, status, resp)
}

func (s *Server) handleRunBackupNow(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	status, err := s.backupService.RunBackupForUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "run_backup_now", "backup", "", r, nil)
	writeJSON(w, status, map[string]string{"status": "backup started"})
}

// ---------- Import handlers ----------

func (s *Server) handleStartImport(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	projectID := r.PathValue("id")

	// Parse multipart form
	if err := r.ParseMultipartForm(s.importMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too large or invalid multipart form"})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file field is required"})
		return
	}
	defer file.Close()

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowed := map[string]bool{".sql": true, ".dump": true, ".backup": true, ".tar": true}
	if !allowed[ext] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported file type, use .sql, .dump, .backup, or .tar"})
		return
	}

	// Parse import options from form fields
	opts := platform.ImportOptions{
		CleanImport:     r.FormValue("clean_import") == "true",
		SkipAuthSchema:  r.FormValue("skip_auth_schema") != "false", // default true
		DisableTriggers: r.FormValue("disable_triggers") != "false", // default true
	}

	// Save file to temp directory
	dir := filepath.Join(s.importTempDir, projectID)
	if err := os.MkdirAll(dir, 0750); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create temp directory"})
		return
	}

	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	destName := fmt.Sprintf("%s_%s", hex.EncodeToString(randBytes), header.Filename)
	destPath := filepath.Join(dir, destName)

	dest, err := os.Create(destPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save file"})
		return
	}

	written, err := io.Copy(dest, file)
	dest.Close()
	if err != nil {
		os.Remove(destPath)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save file"})
		return
	}

	// Start import
	task, status, err := s.importService.StartImport(r.Context(), userID, projectID, destPath, header.Filename, written, opts)
	if err != nil {
		os.Remove(destPath)
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "start_import", "import", fmt.Sprintf("%d", task.ID), r, map[string]interface{}{
		"file_name": header.Filename,
		"file_size": written,
	})
	writeJSON(w, status, task)
}

func (s *Server) handleImportStatus(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	projectID := r.PathValue("id")
	taskIDStr := r.PathValue("taskId")

	taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid task ID"})
		return
	}

	task, status, err := s.importService.GetImportStatus(r.Context(), userID, projectID, taskID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, status, task)
}

func (s *Server) handleImportHistory(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	projectID := r.PathValue("id")

	tasks, status, err := s.importService.GetImportHistory(r.Context(), userID, projectID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, status, tasks)
}

func (s *Server) handleCancelImport(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	taskIDStr := r.PathValue("taskId")

	taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid task ID"})
		return
	}

	status, err := s.importService.CancelImport(r.Context(), userID, taskID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &userID, "cancel_import", "import", taskIDStr, r, nil)
	writeJSON(w, status, map[string]string{"status": "cancelled"})
}

// ---------- Admin middleware ----------

func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := middleware.GetUserID(r)
		if !s.authService.IsAdmin(r.Context(), userID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Registration mode (public) ----------

func (s *Server) handleRegistrationMode(w http.ResponseWriter, r *http.Request) {
	mode := s.authService.GetRegistrationMode(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"registration_mode": mode})
}

// ---------- Admin handlers ----------

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}

	result, status, err := s.adminService.ListUsers(r.Context(), page, perPage)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, status, result)
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	callerID := middleware.GetUserID(r)
	targetID := r.PathValue("id")

	status, err := s.adminService.DeleteUser(r.Context(), callerID, targetID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &callerID, "admin_delete_user", "user", targetID, r, nil)
	writeJSON(w, status, map[string]string{"status": "deleted"})
}

func (s *Server) handleAdminGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, status, err := s.adminService.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, status, settings)
}

func (s *Server) handleAdminUpdateSettings(w http.ResponseWriter, r *http.Request) {
	callerID := middleware.GetUserID(r)
	var req platform.PlatformSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	status, err := s.adminService.UpdateSettings(r.Context(), req)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &callerID, "admin_update_settings", "settings", "", r, map[string]interface{}{"registration_mode": req.RegistrationMode})
	writeJSON(w, status, map[string]string{"status": "updated"})
}

func (s *Server) handleAdminListInvites(w http.ResponseWriter, r *http.Request) {
	invites, status, err := s.adminService.ListInvites(r.Context())
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, status, invites)
}

func (s *Server) handleAdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	callerID := middleware.GetUserID(r)
	var req platform.CreateInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	invite, status, err := s.adminService.CreateInvite(r.Context(), callerID, req)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &callerID, "admin_create_invite", "invite", invite.ID, r, nil)
	writeJSON(w, status, invite)
}

func (s *Server) handleAdminDeleteInvite(w http.ResponseWriter, r *http.Request) {
	callerID := middleware.GetUserID(r)
	inviteID := r.PathValue("id")

	status, err := s.adminService.DeleteInvite(r.Context(), inviteID)
	if err != nil {
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	s.auditService.Log(r.Context(), &callerID, "admin_delete_invite", "invite", inviteID, r, nil)
	writeJSON(w, status, map[string]string{"status": "deleted"})
}

// ---------- Helpers ----------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// allowedOrigins returns the list of origins permitted for CORS.
// In production, set ALLOWED_ORIGINS env var to a comma-separated list.
func allowedOrigins() map[string]bool {
	originsStr := os.Getenv("ALLOWED_ORIGINS")
	origins := map[string]bool{
		"http://localhost:3000": true,
		"http://localhost:3001": true,
		"http://localhost:3002": true,
		"http://localhost:3333": true,
	}
	if originsStr != "" {
		for _, o := range strings.Split(originsStr, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				origins[o] = true
			}
		}
	}
	return origins
}

var corsOrigins = allowedOrigins()

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Only allow whitelisted origins with credentials
		if origin != "" && corsOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else if origin == "" {
			// No Origin header (same-origin or non-browser) — allow without credentials
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			// Unknown origin — allow without credentials (no cookies sent)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// Deliberately NOT setting Allow-Credentials for unknown origins
		}

		w.Header().Set("Vary", "Origin")

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", strings.Join([]string{
			"Authorization", "Content-Type", "apikey", "X-Client-Info",
			"Accept", "Accept-Profile", "Content-Profile", "Prefer", "Range",
		}, ", "))
		w.Header().Set("Access-Control-Expose-Headers", "Content-Range, X-Total-Count")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
