package platform

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestFilterTOC(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantLines  int // expected number of non-empty output lines
		wantAbsent []string
	}{
		{
			"keeps public schema",
			"123; 0 0 TABLE public users postgres\n",
			1,
			nil,
		},
		{
			"filters auth schema",
			"123; 0 0 TABLE auth users postgres\n",
			0,
			[]string{"auth"},
		},
		{
			"filters extensions schema",
			"123; 0 0 TABLE extensions ext1 postgres\n",
			0,
			[]string{"extensions"},
		},
		{
			"keeps comment lines and filters auth",
			"; This is a comment\n123; 0 0 TABLE auth users postgres\n",
			0, // comment is kept but is not a non-comment line; auth line is filtered
			nil,
		},
		{
			"filters supabase_ prefixed entries",
			"123; 0 0 TABLE supabase_functions fn1 postgres\n",
			0,
			[]string{"supabase_"},
		},
		{
			"filters CREATE ROLE entries",
			"123; 0 0 CREATE ROLE myuser postgres\n",
			0,
			[]string{"CREATE ROLE"},
		},
		{
			"filters ALTER ROLE entries",
			"123; 0 0 ALTER ROLE myuser postgres\n",
			0,
			[]string{"ALTER ROLE"},
		},
		{
			"filters CREATE EXTENSION entries",
			"123; 0 0 CREATE EXTENSION pgcrypto postgres\n",
			0,
			[]string{"CREATE EXTENSION"},
		},
		{
			"mixed input keeps only public",
			"123; 0 0 TABLE public products postgres\n124; 0 0 TABLE auth users postgres\n125; 0 0 TABLE public orders postgres\n",
			2,
			[]string{"auth"},
		},
		{
			"empty input",
			"",
			0,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterTOC(tt.input)

			// Count non-empty, non-comment lines
			var lines int
			for _, line := range strings.Split(result, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, ";") {
					lines++
				}
			}

			if lines != tt.wantLines {
				t.Errorf("expected %d non-comment lines, got %d.\nInput:\n%s\nOutput:\n%s", tt.wantLines, lines, tt.input, result)
			}

			for _, absent := range tt.wantAbsent {
				// Check that filtered entries don't appear in non-comment lines
				for _, line := range strings.Split(result, "\n") {
					if !strings.HasPrefix(strings.TrimSpace(line), ";") && strings.Contains(line, absent) {
						t.Errorf("expected output NOT to contain %q in non-comment lines, got:\n%s", absent, result)
					}
				}
			}
		})
	}
}

func TestIsOnlyWarnings(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"empty string", "", true},
		{"warning only", "pg_restore: warning: something happened\n", true},
		{"WARNING prefix", "WARNING: some warning\n", true},
		{"DETAIL line", "DETAIL: some detail\n", true},
		{"HINT line", "HINT: some hint\n", true},
		{"multiple warnings", "pg_restore: warning: one\nWARNING: two\nDETAIL: three\n", true},
		// pg_restore uses lowercase "error:" prefix — now correctly detected.
		{"lowercase error line caught", "pg_restore: error: something failed\n", false},
		{"uppercase ERROR line", "pg_restore: [archiver] ERROR: something failed\n", false},
		{"ERROR keyword", "ERROR: something broke\n", false},
		{"FATAL keyword", "FATAL: connection refused\n", false},
		{"mixed warning and error", "pg_restore: warning: ok\nERROR: bad\n", false},
		{"whitespace only lines", "  \n  \n", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOnlyWarnings(tt.input); got != tt.expect {
				t.Errorf("isOnlyWarnings(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestFilterSQLFile(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantContains    []string
		wantNotContains []string
	}{
		{
			"passes public CREATE TABLE",
			"CREATE TABLE public.products (id int);\n",
			[]string{"CREATE TABLE public.products"},
			nil,
		},
		{
			"filters auth CREATE TABLE single line",
			"CREATE TABLE auth.users (id uuid);\n",
			nil,
			[]string{"CREATE TABLE auth.users"},
		},
		{
			"filters auth CREATE TABLE multi-line",
			"CREATE TABLE auth.users (\n  id uuid,\n  email text\n);\n",
			nil,
			[]string{"CREATE TABLE auth.users", "id uuid", "email text"},
		},
		{
			"filters COPY auth data block",
			"COPY auth.users (id, email) FROM stdin;\ndata1\tvalue1\ndata2\tvalue2\n\\.\nSELECT 1;\n",
			[]string{"SELECT 1"},
			[]string{"COPY auth.users", "data1", "data2"},
		},
		{
			"passes normal INSERT",
			"INSERT INTO public.products VALUES (1, 'test');\n",
			[]string{"INSERT INTO public.products"},
			nil,
		},
		{
			"filters auth INSERT",
			"INSERT INTO auth.users VALUES ('uuid', 'email');\n",
			nil,
			[]string{"INSERT INTO auth.users"},
		},
		{
			"filters CREATE ROLE",
			"CREATE ROLE supabase_admin;\n",
			nil,
			[]string{"CREATE ROLE"},
		},
		{
			"filters ALTER ROLE",
			"ALTER ROLE authenticator SET search_path TO public;\n",
			nil,
			[]string{"ALTER ROLE"},
		},
		{
			"filters CREATE EXTENSION",
			"CREATE EXTENSION IF NOT EXISTS pgcrypto;\n",
			nil,
			[]string{"CREATE EXTENSION"},
		},
		{
			"filters CREATE SCHEMA auth",
			"CREATE SCHEMA IF NOT EXISTS auth;\n",
			nil,
			[]string{"CREATE SCHEMA"},
		},
		{
			"passes public schema content",
			"CREATE TABLE public.orders (id serial PRIMARY KEY);\nINSERT INTO public.orders VALUES (1);\n",
			[]string{"CREATE TABLE public.orders", "INSERT INTO public.orders"},
			nil,
		},
		{
			"filters COPY extensions data block",
			"COPY extensions.something (id) FROM stdin;\nrow1\n\\.\n",
			nil,
			[]string{"COPY extensions.something", "row1"},
		},
		{
			"filters dollar-quoted function body",
			"CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb AS $$\nBEGIN\n  RETURN '{}'::jsonb;\nEND;\n$$;\n",
			nil,
			[]string{"CREATE OR REPLACE FUNCTION auth.jwt", "RETURN", "END"},
		},
		{
			"filters GRANT to supabase roles",
			"GRANT ALL ON TABLE public.users TO supabase_admin;\n",
			nil,
			[]string{"GRANT"},
		},
		{
			"filters psql meta-commands",
			"\\connect mydb\nSELECT 1;\n",
			[]string{"SELECT 1"},
			[]string{"\\connect"},
		},
		{
			"filters ALTER TABLE auth",
			"ALTER TABLE ONLY auth.users ADD CONSTRAINT pk PRIMARY KEY (id);\n",
			nil,
			[]string{"ALTER TABLE"},
		},
		{
			"filters CREATE INDEX ON auth",
			"CREATE UNIQUE INDEX users_email_idx ON auth.users (email);\n",
			nil,
			[]string{"CREATE UNIQUE INDEX"},
		},
		{
			"empty file",
			"",
			nil,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp input file
			tmpIn, err := os.CreateTemp("", "test-filter-*.sql")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpIn.Name())

			if _, err := tmpIn.WriteString(tt.input); err != nil {
				t.Fatal(err)
			}
			tmpIn.Close()

			outPath, err := filterSQLFile(tmpIn.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(outPath)

			output, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}

			for _, s := range tt.wantContains {
				if !strings.Contains(string(output), s) {
					t.Errorf("expected output to contain %q, got:\n%s", s, output)
				}
			}
			for _, s := range tt.wantNotContains {
				if strings.Contains(string(output), s) {
					t.Errorf("expected output NOT to contain %q, got:\n%s", s, output)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseCopyColumns
// ---------------------------------------------------------------------------

func TestParseCopyColumns(t *testing.T) {
	tests := []struct {
		name    string
		stmt    string
		wantLen int
		want    []string
	}{
		{
			"valid_copy_statement",
			"COPY auth.users (id, email, encrypted_password, created_at) FROM stdin;",
			4,
			[]string{"id", "email", "encrypted_password", "created_at"},
		},
		{
			"single_column",
			"COPY auth.users (id) FROM stdin;",
			1,
			[]string{"id"},
		},
		{
			"no_parens",
			"COPY auth.users FROM stdin;",
			0,
			nil,
		},
		{
			"empty_parens",
			"COPY auth.users () FROM stdin;",
			1, // splits "" into one empty string
			nil,
		},
		{
			"many_columns",
			"COPY auth.users (id, email, encrypted_password, phone, email_confirmed_at, phone_confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_anonymous, banned_until, created_at, updated_at) FROM stdin;",
			13,
			[]string{"id", "email", "encrypted_password", "phone"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cols := parseCopyColumns(tt.stmt)
			if len(cols) != tt.wantLen {
				t.Fatalf("expected %d columns, got %d: %v", tt.wantLen, len(cols), cols)
			}
			for i, expected := range tt.want {
				if i < len(cols) && cols[i] != expected {
					t.Errorf("column[%d]: got %q, want %q", i, cols[i], expected)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseCopyRow
// ---------------------------------------------------------------------------

func TestParseCopyRow(t *testing.T) {
	columns := []string{"id", "email", "encrypted_password", "created_at"}

	t.Run("valid_row", func(t *testing.T) {
		line := "uuid-123\tuser@test.com\t$2a$12$hash\t2026-01-01 00:00:00"
		user := parseCopyRow(line, columns)
		if user == nil {
			t.Fatal("expected non-nil user")
		}
		if user.id != "uuid-123" {
			t.Errorf("expected id 'uuid-123', got %q", user.id)
		}
		if user.email != "user@test.com" {
			t.Errorf("expected email 'user@test.com', got %q", user.email)
		}
		if user.encryptedPassword != "$2a$12$hash" {
			t.Errorf("expected encryptedPassword '$2a$12$hash', got %q", user.encryptedPassword)
		}
		if user.createdAt != "2026-01-01 00:00:00" {
			t.Errorf("expected createdAt '2026-01-01 00:00:00', got %q", user.createdAt)
		}
	})

	t.Run("row_with_null_values", func(t *testing.T) {
		// \N in PostgreSQL COPY means NULL
		line := "uuid-456\tuser2@test.com\t\\N\t2026-01-01 00:00:00"
		user := parseCopyRow(line, columns)
		if user == nil {
			t.Fatal("expected non-nil user")
		}
		if user.encryptedPassword != "" {
			t.Errorf("expected empty encryptedPassword for \\N, got %q", user.encryptedPassword)
		}
	})

	t.Run("too_few_fields", func(t *testing.T) {
		line := "uuid-789\tuser3@test.com"
		user := parseCopyRow(line, columns)
		if user != nil {
			t.Error("expected nil user for too few fields")
		}
	})

	t.Run("extra_fields_ok", func(t *testing.T) {
		// More fields than columns is fine -- extras are ignored
		line := "uuid-abc\tuser4@test.com\t$2a$12$hash\t2026-01-01\textra_field"
		user := parseCopyRow(line, columns)
		if user == nil {
			t.Fatal("expected non-nil user")
		}
		if user.id != "uuid-abc" {
			t.Errorf("expected id 'uuid-abc', got %q", user.id)
		}
	})

	t.Run("empty_columns_list", func(t *testing.T) {
		line := "uuid-123\tuser@test.com"
		user := parseCopyRow(line, []string{})
		if user == nil {
			t.Fatal("expected non-nil user (empty columns produces empty colMap)")
		}
		// All fields should be empty since no columns map
		if user.id != "" {
			t.Errorf("expected empty id with no columns, got %q", user.id)
		}
	})
}

// ---------------------------------------------------------------------------
// sqlQuote
// ---------------------------------------------------------------------------

func TestSqlQuote(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple_string", "hello", "'hello'"},
		{"empty_string", "", "''"},
		{"with_single_quote", "O'Brien", "'O''Brien'"},
		{"with_multiple_quotes", "it's a 'test'", "'it''s a ''test'''"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", "'550e8400-e29b-41d4-a716-446655440000'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sqlQuote(tt.input)
			if got != tt.expected {
				t.Errorf("sqlQuote(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sqlQuoteNullable
// ---------------------------------------------------------------------------

func TestSqlQuoteNullable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty_returns_null", "", "NULL"},
		{"non_empty", "value", "'value'"},
		{"with_quote", "it's", "'it''s'"},
		{"timestamp", "2026-01-01 00:00:00", "'2026-01-01 00:00:00'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sqlQuoteNullable(tt.input)
			if got != tt.expected {
				t.Errorf("sqlQuoteNullable(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sqlQuoteJSON
// ---------------------------------------------------------------------------

func TestSqlQuoteJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty_returns_empty_jsonb", "", "'{}'::jsonb"},
		{"backslash_n_returns_empty_jsonb", "\\N", "'{}'::jsonb"},
		{"valid_json", `{"role":"admin"}`, `'{"role":"admin"}'::jsonb`},
		{"json_with_single_quote", `{"name":"O'Brien"}`, `'{"name":"O''Brien"}'::jsonb`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sqlQuoteJSON(tt.input)
			if got != tt.expected {
				t.Errorf("sqlQuoteJSON(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sqlQuoteBool
// ---------------------------------------------------------------------------

func TestSqlQuoteBool(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"true_string", "true", "true"},
		{"t_string", "t", "true"},
		{"false_string", "false", "false"},
		{"f_string", "f", "false"},
		{"empty_string", "", "false"},
		{"random_string", "yes", "false"},
		{"uppercase_true", "TRUE", "false"}, // not handled, returns false
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sqlQuoteBool(tt.input)
			if got != tt.expected {
				t.Errorf("sqlQuoteBool(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sqlQuoteTimestamp
// ---------------------------------------------------------------------------

func TestSqlQuoteTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty_returns_now", "", "NOW()"},
		{"valid_timestamp", "2026-01-01 00:00:00+00", "'2026-01-01 00:00:00+00'"},
		{"timestamp_with_quote", "2026-01-01'", "'2026-01-01'''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sqlQuoteTimestamp(tt.input)
			if got != tt.expected {
				t.Errorf("sqlQuoteTimestamp(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DumpAnalysis type construction
// ---------------------------------------------------------------------------

func TestDumpAnalysis_ZeroValue(t *testing.T) {
	var da DumpAnalysis
	if da.IsSupabaseDump {
		t.Error("expected IsSupabaseDump false")
	}
	if da.Format != "" {
		t.Errorf("expected empty Format, got %q", da.Format)
	}
	if da.HasAuthUsers {
		t.Error("expected HasAuthUsers false")
	}
	if da.HasMigrations {
		t.Error("expected HasMigrations false")
	}
	if da.SupabaseSchemas != nil {
		t.Error("expected nil SupabaseSchemas")
	}
	if da.DetectedSignals != nil {
		t.Error("expected nil DetectedSignals")
	}
	if da.RecommendedAction != "" {
		t.Errorf("expected empty RecommendedAction, got %q", da.RecommendedAction)
	}
}

func TestDumpAnalysis_Populated(t *testing.T) {
	da := DumpAnalysis{
		IsSupabaseDump:    true,
		Format:            "sql",
		HasAuthUsers:      true,
		HasMigrations:     true,
		SupabaseSchemas:   []string{"auth", "extensions"},
		DetectedSignals:   []string{"auth schema creation", "auth.users table"},
		RecommendedAction: "Import with 'Skip Auth Schema' enabled",
	}
	if !da.IsSupabaseDump {
		t.Error("expected IsSupabaseDump true")
	}
	if da.Format != "sql" {
		t.Errorf("expected Format 'sql', got %q", da.Format)
	}
	if len(da.SupabaseSchemas) != 2 {
		t.Errorf("expected 2 SupabaseSchemas, got %d", len(da.SupabaseSchemas))
	}
	if len(da.DetectedSignals) != 2 {
		t.Errorf("expected 2 DetectedSignals, got %d", len(da.DetectedSignals))
	}
}

// ---------------------------------------------------------------------------
// splitDBURL
// ---------------------------------------------------------------------------

func TestSplitDBURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		host     string
		port     string
		user     string
		password string
		dbName   string
		wantErr  bool
	}{
		{
			"standard_url",
			"postgresql://user:pass@localhost:5432/mydb",
			"localhost", "5432", "user", "pass", "mydb", false,
		},
		{
			"default_port",
			"postgresql://user:pass@localhost/mydb",
			"localhost", "5432", "user", "pass", "mydb", false,
		},
		{
			"with_ip",
			"postgresql://admin:secret@192.168.1.1:5433/proddb",
			"192.168.1.1", "5433", "admin", "secret", "proddb", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, user, password, dbName, err := splitDBURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.host {
				t.Errorf("host: got %q, want %q", host, tt.host)
			}
			if port != tt.port {
				t.Errorf("port: got %q, want %q", port, tt.port)
			}
			if user != tt.user {
				t.Errorf("user: got %q, want %q", user, tt.user)
			}
			if password != tt.password {
				t.Errorf("password: got %q, want %q", password, tt.password)
			}
			if dbName != tt.dbName {
				t.Errorf("dbName: got %q, want %q", dbName, tt.dbName)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewImportService constructor
// ---------------------------------------------------------------------------

func TestNewImportService_ReturnsNonNil(t *testing.T) {
	svc := NewImportService(nil, "postgresql://localhost/test")
	if svc == nil {
		t.Fatal("NewImportService returned nil")
	}
	if svc.processes == nil {
		t.Error("expected non-nil processes map")
	}
}

// ---------------------------------------------------------------------------
// ImportOptions type
// ---------------------------------------------------------------------------

func TestImportOptions_ZeroValue(t *testing.T) {
	var opts ImportOptions
	if opts.CleanImport {
		t.Error("expected CleanImport false")
	}
	if opts.SkipAuthSchema {
		t.Error("expected SkipAuthSchema false")
	}
	if opts.DisableTriggers {
		t.Error("expected DisableTriggers false")
	}
	if opts.MigrateAuthUsers {
		t.Error("expected MigrateAuthUsers false")
	}
}

// ---------------------------------------------------------------------------
// ImportTaskResponse type
// ---------------------------------------------------------------------------

func TestImportTaskResponse_Fields(t *testing.T) {
	now := time.Now()
	errMsg := "something went wrong"
	tables := 5
	resp := ImportTaskResponse{
		ID:             1,
		ProjectID:      "proj-123",
		DBName:         "proj_db",
		FileName:       "dump.sql",
		FileSize:       1024,
		Format:         "sql",
		Status:         "completed",
		ErrorMessage:   &errMsg,
		TablesImported: &tables,
		StartedAt:      now,
		CompletedAt:    &now,
	}

	if resp.ID != 1 {
		t.Errorf("expected ID 1, got %d", resp.ID)
	}
	if resp.ProjectID != "proj-123" {
		t.Errorf("expected ProjectID 'proj-123', got %q", resp.ProjectID)
	}
	if *resp.ErrorMessage != "something went wrong" {
		t.Errorf("expected ErrorMessage 'something went wrong', got %q", *resp.ErrorMessage)
	}
	if *resp.TablesImported != 5 {
		t.Errorf("expected TablesImported 5, got %d", *resp.TablesImported)
	}
}

// ---------------------------------------------------------------------------
// detectFormat
// ---------------------------------------------------------------------------

func TestDetectFormat(t *testing.T) {
	t.Run("sql_file", func(t *testing.T) {
		f, err := os.CreateTemp("", "test-detect-*.sql")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.WriteString("CREATE TABLE test (id int);\n")
		f.Close()

		format := detectFormat(f.Name())
		if format != "sql" {
			t.Errorf("expected format 'sql', got %q", format)
		}
	})

	t.Run("custom_format", func(t *testing.T) {
		f, err := os.CreateTemp("", "test-detect-*.dump")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.Write([]byte("PGDMP"))
		f.Close()

		format := detectFormat(f.Name())
		if format != "custom" {
			t.Errorf("expected format 'custom', got %q", format)
		}
	})

	t.Run("nonexistent_file", func(t *testing.T) {
		format := detectFormat("/nonexistent/file")
		if format != "sql" {
			t.Errorf("expected format 'sql' for nonexistent file, got %q", format)
		}
	})

	t.Run("short_file", func(t *testing.T) {
		f, err := os.CreateTemp("", "test-detect-*.dat")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.WriteString("PG")
		f.Close()

		format := detectFormat(f.Name())
		if format != "sql" {
			t.Errorf("expected format 'sql' for short file, got %q", format)
		}
	})
}

// ---------------------------------------------------------------------------
// supabaseAuthUser type
// ---------------------------------------------------------------------------

func TestSupabaseAuthUser_Fields(t *testing.T) {
	u := supabaseAuthUser{
		id:                "uuid-123",
		email:             "user@test.com",
		encryptedPassword: "$2a$12$hash",
		emailConfirmedAt:  "2026-01-01",
		phone:             "+1234567890",
		rawAppMetaData:    `{"role":"admin"}`,
		rawUserMetaData:   `{"name":"Test"}`,
		isAnonymous:       "false",
		createdAt:         "2026-01-01 00:00:00",
		updatedAt:         "2026-01-01 00:00:00",
	}

	if u.id != "uuid-123" {
		t.Errorf("expected id 'uuid-123', got %q", u.id)
	}
	if u.email != "user@test.com" {
		t.Errorf("expected email 'user@test.com', got %q", u.email)
	}
	if u.rawAppMetaData != `{"role":"admin"}` {
		t.Errorf("unexpected rawAppMetaData: %q", u.rawAppMetaData)
	}
}
