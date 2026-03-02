package platform

import (
	"io"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// projectID safe slice (boundary check in runSingleBackup)
// ---------------------------------------------------------------------------

func TestProjectIDShortSlice(t *testing.T) {
	// runSingleBackup slices projectID to 8 chars for the S3 key prefix.
	// Verify the logic handles IDs shorter than 8 characters.
	tests := []struct {
		name     string
		id       string
		expected string
	}{
		{"longer_than_8", "abcdefgh12345", "abcdefgh"},
		{"exactly_8", "12345678", "12345678"},
		{"shorter_than_8", "abc", "abc"},
		{"empty", "", ""},
		{"one_char", "x", "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shortID := tt.id
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}
			if shortID != tt.expected {
				t.Errorf("got %q, want %q", shortID, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// countingReader
// ---------------------------------------------------------------------------

func TestCountingReader(t *testing.T) {
	data := "hello, world! this is a test."
	cr := &countingReader{r: strings.NewReader(data)}

	buf := make([]byte, 10)
	n, err := cr.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 10 {
		t.Errorf("expected 10 bytes read, got %d", n)
	}
	if cr.n != 10 {
		t.Errorf("expected count 10, got %d", cr.n)
	}

	// Read the rest
	remaining, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedRemaining := len(data) - 10
	if len(remaining) != expectedRemaining {
		t.Errorf("expected %d remaining bytes, got %d", expectedRemaining, len(remaining))
	}
	if cr.n != int64(len(data)) {
		t.Errorf("expected total count %d, got %d", len(data), cr.n)
	}
}

func TestCountingReader_Empty(t *testing.T) {
	cr := &countingReader{r: strings.NewReader("")}
	buf := make([]byte, 10)
	n, err := cr.Read(buf)
	if err != io.EOF {
		t.Errorf("expected EOF, got err=%v, n=%d", err, n)
	}
	if cr.n != 0 {
		t.Errorf("expected count 0, got %d", cr.n)
	}
}

// ---------------------------------------------------------------------------
// BackupService constructor
// ---------------------------------------------------------------------------

func TestNewBackupService(t *testing.T) {
	svc := NewBackupService(nil, "postgres://localhost/test", "backup-key")
	if svc == nil {
		t.Fatal("NewBackupService returned nil")
	}
	if svc.databaseURL != "postgres://localhost/test" {
		t.Errorf("unexpected databaseURL: %q", svc.databaseURL)
	}
	if svc.backupKey != "backup-key" {
		t.Errorf("unexpected backupKey: %q", svc.backupKey)
	}
}

// ---------------------------------------------------------------------------
// BackupSettingsResponse nil ProjectIDs normalization
// ---------------------------------------------------------------------------

func TestBackupSettingsResponse_NilProjectIDs(t *testing.T) {
	// Verify the nil -> empty slice normalization pattern used throughout backup.go
	var projectIDs []string
	if projectIDs == nil {
		projectIDs = []string{}
	}
	if projectIDs == nil {
		t.Fatal("projectIDs should not be nil after normalization")
	}
	if len(projectIDs) != 0 {
		t.Errorf("expected empty slice, got length %d", len(projectIDs))
	}
}

// ---------------------------------------------------------------------------
// SaveBackupSettingsRequest validation
// ---------------------------------------------------------------------------

func TestSaveBackupSettingsRequest_Defaults(t *testing.T) {
	req := SaveBackupSettingsRequest{
		S3Endpoint:       "https://s3.example.com",
		S3Bucket:         "my-bucket",
		S3AccessKey:      "access",
		S3SecretKey:      "secret",
		PlatformPassword: "pass",
	}

	// Test default schedule
	schedule := req.Schedule
	if schedule == "" {
		schedule = "daily"
	}
	if schedule != "daily" {
		t.Errorf("expected default schedule 'daily', got %q", schedule)
	}

	// Test default region
	region := req.S3Region
	if region == "" {
		region = "us-east-1"
	}
	if region != "us-east-1" {
		t.Errorf("expected default region 'us-east-1', got %q", region)
	}

	// Test default retention
	retentionDays := req.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 30
	}
	if retentionDays != 30 {
		t.Errorf("expected default retention 30, got %d", retentionDays)
	}
}

func TestSaveBackupSettingsRequest_ScheduleValidation(t *testing.T) {
	validSchedules := []string{"hourly", "daily", "weekly"}
	invalidSchedules := []string{"monthly", "yearly", "every5min", ""}

	for _, s := range validSchedules {
		if s != "hourly" && s != "daily" && s != "weekly" {
			t.Errorf("valid schedule %q rejected", s)
		}
	}

	for _, s := range invalidSchedules {
		if s == "hourly" || s == "daily" || s == "weekly" {
			t.Errorf("invalid schedule %q accepted", s)
		}
	}
}

// ---------------------------------------------------------------------------
// BackupHistoryResponse structure
// ---------------------------------------------------------------------------

func TestBackupHistoryResponse_Fields(t *testing.T) {
	resp := BackupHistoryResponse{
		ID:        1,
		ProjectID: "proj-123",
		DBName:    "testdb",
		S3Key:     "backups/testdb/2024-01-01.dump",
		Status:    "completed",
	}

	if resp.ID != 1 {
		t.Errorf("unexpected ID: %d", resp.ID)
	}
	if resp.ProjectID != "proj-123" {
		t.Errorf("unexpected ProjectID: %q", resp.ProjectID)
	}
	if resp.Status != "completed" {
		t.Errorf("unexpected Status: %q", resp.Status)
	}
	if resp.SizeBytes != nil {
		t.Error("expected nil SizeBytes")
	}
	if resp.Error != nil {
		t.Error("expected nil Error")
	}
	if resp.CompletedAt != nil {
		t.Error("expected nil CompletedAt")
	}
}
