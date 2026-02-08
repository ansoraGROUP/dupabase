package platform

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ImportService handles database import operations.
type ImportService struct {
	db          *pgxpool.Pool
	databaseURL string

	mu        sync.Mutex
	processes map[int64]*exec.Cmd // taskID -> running process for cancellation
}

// NewImportService creates a new ImportService.
func NewImportService(db *pgxpool.Pool, databaseURL string) *ImportService {
	return &ImportService{
		db:          db,
		databaseURL: databaseURL,
		processes:   make(map[int64]*exec.Cmd),
	}
}

// ImportOptions controls import behavior.
type ImportOptions struct {
	CleanImport     bool `json:"clean_import"`
	SkipAuthSchema  bool `json:"skip_auth_schema"`
	DisableTriggers bool `json:"disable_triggers"`
}

// ImportTaskResponse is the public-facing import task record.
type ImportTaskResponse struct {
	ID             int64      `json:"id"`
	ProjectID      string     `json:"project_id"`
	DBName         string     `json:"db_name"`
	FileName       string     `json:"file_name"`
	FileSize       int64      `json:"file_size"`
	Format         string     `json:"format"`
	Status         string     `json:"status"`
	ErrorMessage   *string    `json:"error_message"`
	TablesImported *int       `json:"tables_imported"`
	StartedAt      time.Time  `json:"started_at"`
	CompletedAt    *time.Time `json:"completed_at"`
}

// Regex patterns for filtering Supabase-specific SQL statements
var sqlFilterPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*CREATE\s+SCHEMA\s+(IF\s+NOT\s+EXISTS\s+)?(auth|extensions|supabase_functions|graphql|graphql_public|realtime|_realtime|storage|vault|pgsodium)\b`),
	regexp.MustCompile(`(?i)^\s*ALTER\s+SCHEMA\s+(auth|extensions|supabase_functions|graphql|graphql_public|realtime|_realtime|storage|vault|pgsodium)\b`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?auth\.`),
	regexp.MustCompile(`(?i)^\s*ALTER\s+TABLE\s+(ONLY\s+)?auth\.`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+(UNIQUE\s+)?INDEX\s+.+\bON\s+auth\.`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?extensions\.`),
	regexp.MustCompile(`(?i)^\s*ALTER\s+TABLE\s+(ONLY\s+)?extensions\.`),
	regexp.MustCompile(`(?i)^\s*COPY\s+auth\.`),
	regexp.MustCompile(`(?i)^\s*INSERT\s+INTO\s+auth\.`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+ROLE\b`),
	regexp.MustCompile(`(?i)^\s*ALTER\s+ROLE\b`),
	regexp.MustCompile(`(?i)^\s*DROP\s+ROLE\b`),
	regexp.MustCompile(`(?i)^\s*GRANT\s+.*\bTO\s+(supabase_admin|supabase_auth_admin|supabase_storage_admin|authenticator|dashboard_user|pgbouncer|pgsodium_keyholder|pgsodium_keyiduser|pgsodium_keymaker|service_role|anon|authenticated)\b`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+auth\.`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+TRIGGER\s+.*\bON\s+auth\.`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+POLICY\s+.*\bON\s+auth\.`),
	regexp.MustCompile(`(?i)^\s*(ALTER\s+TABLE.*)?ENABLE\s+ROW\s+LEVEL\s+SECURITY`),
	regexp.MustCompile(`(?i)^\s*CREATE\s+EXTENSION\b`),
	regexp.MustCompile(`(?i)^\s*COMMENT\s+ON\s+EXTENSION\b`),
	regexp.MustCompile(`(?i)^\s*SET\s+.*search_path\s*=.*\bauth\b`),
}

// TOC filter patterns for custom dump format
var tocFilterPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bauth\b`),
	regexp.MustCompile(`(?i)\bextensions\b`),
	regexp.MustCompile(`(?i)\bsupabase_`),
	regexp.MustCompile(`(?i)\bCREATE ROLE\b`),
	regexp.MustCompile(`(?i)\bALTER ROLE\b`),
	regexp.MustCompile(`(?i)\bCREATE EXTENSION\b`),
}

// StartImport validates ownership, saves metadata, and launches async import.
func (s *ImportService) StartImport(ctx context.Context, userID, projectID, filePath, fileName string, fileSize int64, opts ImportOptions) (*ImportTaskResponse, int, error) {
	// Validate project ownership
	var dbName string
	err := s.db.QueryRow(ctx, `
		SELECT db_name FROM platform.projects
		WHERE id = $1 AND user_id = $2 AND status = 'active'
	`, projectID, userID).Scan(&dbName)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("project not found or not active")
	}

	// Detect format
	format := detectFormat(filePath)

	// Insert task record
	var taskID int64
	err = s.db.QueryRow(ctx, `
		INSERT INTO platform.import_tasks (user_id, project_id, db_name, file_name, file_size, format, options, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'running')
		RETURNING id
	`, userID, projectID, dbName, fileName, fileSize, format,
		fmt.Sprintf(`{"clean_import":%t,"skip_auth_schema":%t,"disable_triggers":%t}`,
			opts.CleanImport, opts.SkipAuthSchema, opts.DisableTriggers),
	).Scan(&taskID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("create import task: %w", err)
	}

	// Launch async import
	go s.executeImport(taskID, dbName, filePath, format, opts)

	task := &ImportTaskResponse{
		ID:        taskID,
		ProjectID: projectID,
		DBName:    dbName,
		FileName:  fileName,
		FileSize:  fileSize,
		Format:    format,
		Status:    "running",
		StartedAt: time.Now(),
	}

	return task, http.StatusAccepted, nil
}

// GetImportStatus returns the latest import task for a project.
func (s *ImportService) GetImportStatus(ctx context.Context, userID, projectID string, taskID int64) (*ImportTaskResponse, int, error) {
	var t ImportTaskResponse
	err := s.db.QueryRow(ctx, `
		SELECT id, project_id, db_name, file_name, file_size, format,
			status, error_message, tables_imported, started_at, completed_at
		FROM platform.import_tasks
		WHERE id = $1 AND project_id = $2 AND user_id = $3
	`, taskID, projectID, userID).Scan(
		&t.ID, &t.ProjectID, &t.DBName, &t.FileName, &t.FileSize, &t.Format,
		&t.Status, &t.ErrorMessage, &t.TablesImported, &t.StartedAt, &t.CompletedAt,
	)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("import task not found")
	}
	return &t, http.StatusOK, nil
}

// GetImportHistory returns all import tasks for a project.
func (s *ImportService) GetImportHistory(ctx context.Context, userID, projectID string) ([]ImportTaskResponse, int, error) {
	// Verify ownership
	var exists bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM platform.projects WHERE id = $1 AND user_id = $2)
	`, projectID, userID).Scan(&exists)
	if err != nil || !exists {
		return nil, http.StatusNotFound, fmt.Errorf("project not found")
	}

	rows, err := s.db.Query(ctx, `
		SELECT id, project_id, db_name, file_name, file_size, format,
			status, error_message, tables_imported, started_at, completed_at
		FROM platform.import_tasks
		WHERE project_id = $1 AND user_id = $2
		ORDER BY started_at DESC
		LIMIT 50
	`, projectID, userID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query import history: %w", err)
	}
	defer rows.Close()

	var tasks []ImportTaskResponse
	for rows.Next() {
		var t ImportTaskResponse
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.DBName, &t.FileName, &t.FileSize, &t.Format,
			&t.Status, &t.ErrorMessage, &t.TablesImported, &t.StartedAt, &t.CompletedAt); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("scan import task: %w", err)
		}
		tasks = append(tasks, t)
	}
	if tasks == nil {
		tasks = []ImportTaskResponse{}
	}
	return tasks, http.StatusOK, nil
}

// CancelImport cancels a running import.
func (s *ImportService) CancelImport(ctx context.Context, userID string, taskID int64) (int, error) {
	// Verify ownership and running status
	var status string
	err := s.db.QueryRow(ctx, `
		SELECT status FROM platform.import_tasks
		WHERE id = $1 AND user_id = $2
	`, taskID, userID).Scan(&status)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("import task not found")
	}
	if status != "running" {
		return http.StatusBadRequest, fmt.Errorf("import is not running (status: %s)", status)
	}

	// Kill process if exists
	s.mu.Lock()
	cmd, ok := s.processes[taskID]
	s.mu.Unlock()

	if ok && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}

	s.db.Exec(ctx, `
		UPDATE platform.import_tasks
		SET status = 'cancelled', completed_at = NOW()
		WHERE id = $1
	`, taskID)

	return http.StatusOK, nil
}

// --- Internal ---

// executeImport runs the actual import in a goroutine.
func (s *ImportService) executeImport(taskID int64, dbName, filePath, format string, opts ImportOptions) {
	ctx := context.Background()

	defer func() {
		// Clean up process reference
		s.mu.Lock()
		delete(s.processes, taskID)
		s.mu.Unlock()
	}()

	// Build target database URL
	dbURL, err := s.buildDBURL(dbName)
	if err != nil {
		s.markImportFailed(ctx, taskID, fmt.Sprintf("build DB URL: %v", err))
		return
	}

	// Pre-import: handle clean import and disable triggers
	if opts.CleanImport || opts.DisableTriggers {
		if err := s.preImport(ctx, dbURL, opts); err != nil {
			s.markImportFailed(ctx, taskID, fmt.Sprintf("pre-import: %v", err))
			return
		}
	}

	var importErr error
	var tableCount int

	if format == "custom" {
		tableCount, importErr = s.importCustomDump(ctx, taskID, dbURL, filePath, opts)
	} else {
		tableCount, importErr = s.importPlainSQL(ctx, taskID, dbURL, filePath, opts)
	}

	// Post-import: re-enable triggers
	if opts.DisableTriggers {
		s.postImport(ctx, dbURL)
	}

	if importErr != nil {
		s.markImportFailed(ctx, taskID, importErr.Error())
		return
	}

	// Mark completed
	s.db.Exec(ctx, `
		UPDATE platform.import_tasks
		SET status = 'completed', tables_imported = $1, completed_at = NOW()
		WHERE id = $2
	`, tableCount, taskID)

	// Clean up temp file on success
	os.Remove(filePath)

	slog.Info("Import completed", "task_id", taskID, "db", dbName, "tables", tableCount)
}

func (s *ImportService) buildDBURL(dbName string) (string, error) {
	u, err := url.Parse(s.databaseURL)
	if err != nil {
		return "", fmt.Errorf("parse database URL: %w", err)
	}
	u.Path = "/" + dbName
	return u.String(), nil
}

func (s *ImportService) preImport(ctx context.Context, dbURL string, opts ImportOptions) error {
	var stmts []string

	if opts.DisableTriggers {
		stmts = append(stmts, "SET session_replication_role = 'replica';")
	}

	if opts.CleanImport {
		stmts = append(stmts,
			"DO $$ DECLARE r RECORD; BEGIN FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP EXECUTE 'DROP TABLE IF EXISTS public.' || quote_ident(r.tablename) || ' CASCADE'; END LOOP; END $$;",
		)
	}

	if len(stmts) == 0 {
		return nil
	}

	sql := strings.Join(stmts, "\n")
	cmd := exec.CommandContext(ctx, "psql", dbURL, "-c", sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pre-import SQL: %s: %w", string(out), err)
	}
	return nil
}

func (s *ImportService) postImport(ctx context.Context, dbURL string) {
	cmd := exec.CommandContext(ctx, "psql", dbURL, "-c", "SET session_replication_role = 'origin';")
	cmd.CombinedOutput()
}

// importCustomDump handles pg_restore for custom format dumps.
func (s *ImportService) importCustomDump(ctx context.Context, taskID int64, dbURL, filePath string, opts ImportOptions) (int, error) {
	cancelCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	if opts.SkipAuthSchema {
		// Use pg_restore --list to get TOC, filter it, then use --use-list
		return s.importCustomDumpFiltered(cancelCtx, taskID, dbURL, filePath)
	}

	// Direct restore (--clean --if-exists drops before creating)
	cmd := exec.CommandContext(cancelCtx, "pg_restore",
		"--no-owner",
		"--no-acl",
		"--role=stech",
		"--clean",
		"--if-exists",
		"--dbname="+dbURL,
		filePath,
	)

	s.mu.Lock()
	s.processes[taskID] = cmd
	s.mu.Unlock()

	out, err := cmd.CombinedOutput()
	if err != nil {
		// pg_restore returns exit code 1 for warnings too, check output
		outStr := string(out)
		if isOnlyWarnings(outStr) {
			slog.Warn("pg_restore completed with warnings", "task_id", taskID, "output", outStr)
		} else {
			return 0, fmt.Errorf("pg_restore: %s", outStr)
		}
	}

	tableCount := countRestoredTables(ctx, dbURL)
	return tableCount, nil
}

// importCustomDumpFiltered does TOC-based filtering for custom dumps.
func (s *ImportService) importCustomDumpFiltered(ctx context.Context, taskID int64, dbURL, filePath string) (int, error) {
	// Step 1: Get TOC listing
	listCmd := exec.CommandContext(ctx, "pg_restore", "--list", filePath)
	tocOutput, err := listCmd.Output()
	if err != nil {
		return 0, fmt.Errorf("pg_restore --list: %w", err)
	}

	// Step 2: Filter TOC
	filteredTOC := filterTOC(string(tocOutput))

	// Step 3: Write filtered TOC to temp file
	tocFile, err := os.CreateTemp("", "import-toc-*.list")
	if err != nil {
		return 0, fmt.Errorf("create TOC temp file: %w", err)
	}
	defer os.Remove(tocFile.Name())

	if _, err := tocFile.WriteString(filteredTOC); err != nil {
		tocFile.Close()
		return 0, fmt.Errorf("write TOC: %w", err)
	}
	tocFile.Close()

	// Step 4: Restore with filtered TOC (--clean --if-exists drops before creating)
	cmd := exec.CommandContext(ctx, "pg_restore",
		"--no-owner",
		"--no-acl",
		"--role=stech",
		"--clean",
		"--if-exists",
		"--use-list="+tocFile.Name(),
		"--dbname="+dbURL,
		filePath,
	)

	s.mu.Lock()
	s.processes[taskID] = cmd
	s.mu.Unlock()

	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		if isOnlyWarnings(outStr) {
			slog.Warn("pg_restore (filtered) completed with warnings", "task_id", taskID, "output", outStr)
		} else {
			return 0, fmt.Errorf("pg_restore: %s", outStr)
		}
	}

	tableCount := countRestoredTables(ctx, dbURL)
	return tableCount, nil
}

// importPlainSQL handles plain SQL file import.
func (s *ImportService) importPlainSQL(ctx context.Context, taskID int64, dbURL, filePath string, opts ImportOptions) (int, error) {
	cancelCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	importFile := filePath

	if opts.SkipAuthSchema {
		// Filter the SQL file
		filtered, err := filterSQLFile(filePath)
		if err != nil {
			return 0, fmt.Errorf("filter SQL: %w", err)
		}
		importFile = filtered
		defer os.Remove(filtered)
	}

	cmd := exec.CommandContext(cancelCtx, "psql",
		dbURL,
		"-f", importFile,
	)

	s.mu.Lock()
	s.processes[taskID] = cmd
	s.mu.Unlock()

	out, err := cmd.CombinedOutput()
	outStr := string(out)
	if err != nil {
		// psql can return errors for non-critical things (duplicate keys, etc.)
		// Check if we got at least some tables imported
		tableCount := countRestoredTables(cancelCtx, dbURL)
		if tableCount > 0 {
			slog.Warn("psql import completed with errors", "task_id", taskID, "tables", tableCount)
			return tableCount, nil
		}
		return 0, fmt.Errorf("psql import: %s", outStr)
	}

	tableCount := countRestoredTables(cancelCtx, dbURL)
	return tableCount, nil
}

func (s *ImportService) markImportFailed(ctx context.Context, taskID int64, errMsg string) {
	slog.Error("Import failed", "task_id", taskID, "error", errMsg)
	s.db.Exec(ctx, `
		UPDATE platform.import_tasks
		SET status = 'failed', error_message = $1, completed_at = NOW()
		WHERE id = $2
	`, errMsg, taskID)
}

// --- Helpers ---

// detectFormat checks file magic bytes to determine if it's a custom pg_dump or plain SQL.
func detectFormat(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return "sql"
	}
	defer f.Close()

	header := make([]byte, 5)
	n, err := f.Read(header)
	if err != nil || n < 5 {
		return "sql"
	}

	// Custom pg_dump format starts with "PGDMP"
	if string(header) == "PGDMP" {
		return "custom"
	}

	return "sql"
}

// filterTOC filters a pg_restore TOC listing, removing auth/extensions entries.
func filterTOC(toc string) string {
	var filtered strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(toc))

	for scanner.Scan() {
		line := scanner.Text()

		// Always keep comment lines (starting with ;)
		if strings.HasPrefix(line, ";") {
			filtered.WriteString(line)
			filtered.WriteString("\n")
			continue
		}

		skip := false
		for _, pattern := range tocFilterPatterns {
			if pattern.MatchString(line) {
				skip = true
				break
			}
		}

		if !skip {
			filtered.WriteString(line)
			filtered.WriteString("\n")
		}
	}

	return filtered.String()
}

// filterSQLFile creates a filtered copy of a SQL file, removing auth schema statements.
// Handles multi-line CREATE FUNCTION with $$-quoted bodies and COPY blocks.
func filterSQLFile(inputPath string) (string, error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return "", fmt.Errorf("open input: %w", err)
	}
	defer input.Close()

	output, err := os.CreateTemp("", "import-filtered-*.sql")
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}

	writer := bufio.NewWriter(output)
	scanner := bufio.NewScanner(input)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	// State machine for filtering
	type skipState int
	const (
		stateNormal  skipState = iota
		stateCopy              // skipping COPY block until \.
		stateDollar            // skipping $$-quoted body until $$;
		stateMulti             // skipping multi-line statement until ;
		stateMultiDQ           // skipping multi-line that entered a $$ block
	)

	state := stateNormal

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		switch state {
		case stateCopy:
			if line == "\\." {
				state = stateNormal
			}
			continue

		case stateDollar:
			if strings.Contains(line, "$$") {
				state = stateNormal
			}
			continue

		case stateMulti:
			// Inside a multi-line filtered statement
			if strings.Contains(line, "$$") && !strings.Contains(line, "$$;") {
				// Entered a dollar-quoted body inside the filtered statement
				state = stateMultiDQ
			} else if strings.HasSuffix(trimmed, ";") || strings.HasSuffix(trimmed, "$$;") {
				state = stateNormal
			}
			continue

		case stateMultiDQ:
			// Inside dollar-quoted body of a filtered multi-line statement
			if strings.Contains(line, "$$") {
				// End of dollar-quote — but statement may continue
				if strings.HasSuffix(trimmed, ";") {
					state = stateNormal
				} else {
					state = stateMulti
				}
			}
			continue
		}

		// stateNormal: check if line should be filtered

		// Skip psql meta-commands
		if strings.HasPrefix(trimmed, "\\restrict") || strings.HasPrefix(trimmed, "\\unrestrict") || strings.HasPrefix(trimmed, "\\connect") {
			continue
		}

		upper := strings.ToUpper(trimmed)

		// COPY auth/extensions block → skip until \.
		if strings.HasPrefix(upper, "COPY AUTH.") || strings.HasPrefix(upper, "COPY EXTENSIONS.") {
			state = stateCopy
			continue
		}

		// Check filter patterns
		skip := false
		for _, pattern := range sqlFilterPatterns {
			if pattern.MatchString(line) {
				skip = true
				break
			}
		}

		if skip {
			if strings.Contains(line, "$$") && !strings.Contains(line, "$$;") {
				// Opens a $$-quoted body (e.g., CREATE FUNCTION auth.jwt() ... AS $$)
				state = stateDollar
			} else if strings.HasSuffix(trimmed, ";") || strings.HasSuffix(trimmed, "$$;") {
				// Single-line statement, already skipped
				state = stateNormal
			} else if trimmed != "" {
				// Multi-line statement (CREATE TABLE auth.xxx (\n  ...
				state = stateMulti
			}
			continue
		}

		writer.WriteString(line)
		writer.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		output.Close()
		os.Remove(output.Name())
		return "", fmt.Errorf("scan input: %w", err)
	}

	writer.Flush()
	output.Close()
	return output.Name(), nil
}

// isOnlyWarnings checks if pg_restore output contains only non-fatal warnings.
func isOnlyWarnings(output string) bool {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// pg_restore warnings start with "pg_restore: warning:" or "WARNING:"
		if strings.HasPrefix(line, "pg_restore: warning:") ||
			strings.HasPrefix(line, "WARNING:") ||
			strings.HasPrefix(line, "DETAIL:") ||
			strings.HasPrefix(line, "HINT:") {
			continue
		}
		// Error lines
		if strings.Contains(line, "ERROR") || strings.Contains(line, "FATAL") {
			return false
		}
	}
	return true
}

// countRestoredTables counts public tables in the target database.
func countRestoredTables(ctx context.Context, dbURL string) int {
	cmd := exec.CommandContext(ctx, "psql", dbURL, "-tAc",
		"SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	var count int
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
	return count
}

// readOutput reads all output from a reader and returns it as a string.
func readOutput(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}
