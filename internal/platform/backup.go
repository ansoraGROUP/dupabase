package platform

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// BackupService handles S3 backup operations for project databases.
type BackupService struct {
	db          *pgxpool.Pool
	databaseURL string
	backupKey   string // server-level encryption key for S3 credentials
}

// NewBackupService creates a new BackupService.
func NewBackupService(db *pgxpool.Pool, databaseURL string, backupKey string) *BackupService {
	return &BackupService{
		db:          db,
		databaseURL: databaseURL,
		backupKey:   backupKey,
	}
}

// --- Request/Response types ---

// SaveBackupSettingsRequest is the request body for saving S3 backup settings.
type SaveBackupSettingsRequest struct {
	S3Endpoint       string   `json:"s3_endpoint"`
	S3Region         string   `json:"s3_region"`
	S3Bucket         string   `json:"s3_bucket"`
	S3AccessKey      string   `json:"s3_access_key"`
	S3SecretKey      string   `json:"s3_secret_key"`
	S3PathPrefix     string   `json:"s3_path_prefix,omitempty"`
	Schedule         string   `json:"schedule,omitempty"` // "daily", "weekly", "hourly"
	RetentionDays    int      `json:"retention_days,omitempty"`
	ProjectIDs       []string `json:"project_ids,omitempty"` // empty = all projects
	PlatformPassword string   `json:"platform_password"`
}

// BackupSettingsResponse is the public-facing backup settings (no decrypted keys).
type BackupSettingsResponse struct {
	ID            string   `json:"id"`
	S3Endpoint    string   `json:"s3_endpoint"`
	S3Region      string   `json:"s3_region"`
	S3Bucket      string   `json:"s3_bucket"`
	S3PathPrefix  string   `json:"s3_path_prefix"`
	Schedule      string   `json:"schedule"`
	RetentionDays int      `json:"retention_days"`
	ProjectIDs    []string `json:"project_ids"`
	Enabled       bool     `json:"enabled"`
}

// BackupHistoryResponse is a single backup history record.
type BackupHistoryResponse struct {
	ID          int64      `json:"id"`
	ProjectID   string     `json:"project_id"`
	DBName      string     `json:"db_name"`
	S3Key       string     `json:"s3_key"`
	SizeBytes   *int64     `json:"size_bytes"`
	Status      string     `json:"status"`
	Error       *string    `json:"error_message"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

// backupSettingsInternal holds the full row including encrypted credentials.
type backupSettingsInternal struct {
	ID                   string
	UserID               string
	S3Endpoint           string
	S3Region             string
	S3Bucket             string
	S3AccessKeyEncrypted string
	S3SecretKeyEncrypted string
	S3PathPrefix         string
	Schedule             string
	RetentionDays        int
	ProjectIDs           []string
	Enabled              bool
}

// --- Public methods ---

// SaveSettings validates the user's platform password, encrypts S3 keys with the
// server-level backup encryption key, and upserts backup settings.
func (s *BackupService) SaveSettings(ctx context.Context, userID string, req SaveBackupSettingsRequest) (*BackupSettingsResponse, int, error) {
	if req.PlatformPassword == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("platform_password is required")
	}
	if req.S3Endpoint == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("s3_endpoint is required")
	}
	if req.S3Bucket == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("s3_bucket is required")
	}
	if req.S3AccessKey == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("s3_access_key is required")
	}
	if req.S3SecretKey == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("s3_secret_key is required")
	}

	// Verify the user's platform password via bcrypt
	var passwordHash string
	err := s.db.QueryRow(ctx, `SELECT password_hash FROM platform.users WHERE id = $1`, userID).Scan(&passwordHash)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.PlatformPassword)); err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid password")
	}

	// Defaults
	region := req.S3Region
	if region == "" {
		region = "us-east-1"
	}
	schedule := req.Schedule
	if schedule == "" {
		schedule = "daily"
	}
	if schedule != "hourly" && schedule != "daily" && schedule != "weekly" {
		return nil, http.StatusBadRequest, fmt.Errorf("schedule must be one of: hourly, daily, weekly")
	}
	retentionDays := req.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 30
	}

	// Encrypt S3 keys with the server-level backup encryption key
	accessKeyEnc, err := EncryptPgPassword(req.S3AccessKey, s.backupKey)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("encrypt access key: %w", err)
	}
	secretKeyEnc, err := EncryptPgPassword(req.S3SecretKey, s.backupKey)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("encrypt secret key: %w", err)
	}

	// Normalize project_ids (nil → empty)
	projectIDs := req.ProjectIDs
	if projectIDs == nil {
		projectIDs = []string{}
	}

	// UPSERT
	var id string
	err = s.db.QueryRow(ctx, `
		INSERT INTO platform.backup_settings (
			user_id, s3_endpoint, s3_region, s3_bucket,
			s3_access_key_encrypted, s3_secret_key_encrypted,
			s3_path_prefix, schedule, retention_days, project_ids, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE)
		ON CONFLICT (user_id) DO UPDATE SET
			s3_endpoint = EXCLUDED.s3_endpoint,
			s3_region = EXCLUDED.s3_region,
			s3_bucket = EXCLUDED.s3_bucket,
			s3_access_key_encrypted = EXCLUDED.s3_access_key_encrypted,
			s3_secret_key_encrypted = EXCLUDED.s3_secret_key_encrypted,
			s3_path_prefix = EXCLUDED.s3_path_prefix,
			schedule = EXCLUDED.schedule,
			retention_days = EXCLUDED.retention_days,
			project_ids = EXCLUDED.project_ids,
			enabled = TRUE,
			updated_at = NOW()
		RETURNING id
	`, userID, req.S3Endpoint, region, req.S3Bucket,
		accessKeyEnc, secretKeyEnc,
		req.S3PathPrefix, schedule, retentionDays, projectIDs,
	).Scan(&id)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("upsert backup settings: %w", err)
	}

	return &BackupSettingsResponse{
		ID:            id,
		S3Endpoint:    req.S3Endpoint,
		S3Region:      region,
		S3Bucket:      req.S3Bucket,
		S3PathPrefix:  req.S3PathPrefix,
		Schedule:      schedule,
		RetentionDays: retentionDays,
		ProjectIDs:    projectIDs,
		Enabled:       true,
	}, http.StatusOK, nil
}

// GetSettings returns the user's backup settings (without decrypted keys).
func (s *BackupService) GetSettings(ctx context.Context, userID string) (*BackupSettingsResponse, int, error) {
	var resp BackupSettingsResponse
	err := s.db.QueryRow(ctx, `
		SELECT id, s3_endpoint, s3_region, s3_bucket, s3_path_prefix,
			schedule, retention_days, project_ids, enabled
		FROM platform.backup_settings
		WHERE user_id = $1
	`, userID).Scan(
		&resp.ID, &resp.S3Endpoint, &resp.S3Region, &resp.S3Bucket,
		&resp.S3PathPrefix, &resp.Schedule, &resp.RetentionDays, &resp.ProjectIDs, &resp.Enabled,
	)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("backup settings not found")
	}
	if resp.ProjectIDs == nil {
		resp.ProjectIDs = []string{}
	}
	return &resp, http.StatusOK, nil
}

// GetHistory returns the backup history for a user.
func (s *BackupService) GetHistory(ctx context.Context, userID string) ([]BackupHistoryResponse, int, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, project_id, db_name, s3_key, size_bytes,
			status, error_message, started_at, completed_at
		FROM platform.backup_history
		WHERE user_id = $1
		ORDER BY started_at DESC
		LIMIT 100
	`, userID)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("query backup history: %w", err)
	}
	defer rows.Close()

	var history []BackupHistoryResponse
	for rows.Next() {
		var h BackupHistoryResponse
		if err := rows.Scan(&h.ID, &h.ProjectID, &h.DBName, &h.S3Key,
			&h.SizeBytes, &h.Status, &h.Error, &h.StartedAt, &h.CompletedAt); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("scan backup history: %w", err)
		}
		history = append(history, h)
	}
	if history == nil {
		history = []BackupHistoryResponse{}
	}
	return history, http.StatusOK, nil
}

// RunBackupForUser runs backups for all active projects of a specific user.
// This is called from the manual "run now" endpoint.
func (s *BackupService) RunBackupForUser(ctx context.Context, userID string) (int, error) {
	settings, err := s.getSettingsInternal(ctx, userID)
	if err != nil {
		return http.StatusNotFound, fmt.Errorf("backup settings not found")
	}
	if !settings.Enabled {
		return http.StatusBadRequest, fmt.Errorf("backups are disabled")
	}

	projects, err := s.getActiveProjects(ctx, userID, settings.ProjectIDs)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("get projects: %w", err)
	}
	if len(projects) == 0 {
		return http.StatusOK, nil
	}

	for _, proj := range projects {
		s.runSingleBackup(ctx, userID, proj.id, proj.dbName, settings)
	}
	return http.StatusOK, nil
}

// RunBackupsForAllUsers is the cron entry point that runs backups for all enabled users.
func (s *BackupService) RunBackupsForAllUsers(ctx context.Context) error {
	rows, err := s.db.Query(ctx, `
		SELECT id, user_id, s3_endpoint, s3_region, s3_bucket,
			s3_access_key_encrypted, s3_secret_key_encrypted,
			s3_path_prefix, schedule, retention_days, project_ids, enabled
		FROM platform.backup_settings
		WHERE enabled = TRUE
	`)
	if err != nil {
		return fmt.Errorf("query backup settings: %w", err)
	}
	defer rows.Close()

	var allSettings []backupSettingsInternal
	for rows.Next() {
		var bs backupSettingsInternal
		if err := rows.Scan(&bs.ID, &bs.UserID, &bs.S3Endpoint, &bs.S3Region,
			&bs.S3Bucket, &bs.S3AccessKeyEncrypted, &bs.S3SecretKeyEncrypted,
			&bs.S3PathPrefix, &bs.Schedule, &bs.RetentionDays, &bs.ProjectIDs, &bs.Enabled); err != nil {
			return fmt.Errorf("scan backup settings: %w", err)
		}
		if bs.ProjectIDs == nil {
			bs.ProjectIDs = []string{}
		}
		allSettings = append(allSettings, bs)
	}

	now := time.Now().UTC()
	for _, settings := range allSettings {
		projects, err := s.getActiveProjects(ctx, settings.UserID, settings.ProjectIDs)
		if err != nil {
			slog.Error("Backup: failed to get projects", "user_id", settings.UserID, "error", err)
			continue
		}

		for _, proj := range projects {
			if !s.isDue(ctx, settings.Schedule, proj.id, now) {
				continue
			}
			s.runSingleBackup(ctx, settings.UserID, proj.id, proj.dbName, &settings)
		}
	}
	return nil
}

// --- Internal helpers ---

type projectInfo struct {
	id     string
	dbName string
}

func (s *BackupService) getSettingsInternal(ctx context.Context, userID string) (*backupSettingsInternal, error) {
	var bs backupSettingsInternal
	err := s.db.QueryRow(ctx, `
		SELECT id, user_id, s3_endpoint, s3_region, s3_bucket,
			s3_access_key_encrypted, s3_secret_key_encrypted,
			s3_path_prefix, schedule, retention_days, project_ids, enabled
		FROM platform.backup_settings
		WHERE user_id = $1
	`, userID).Scan(&bs.ID, &bs.UserID, &bs.S3Endpoint, &bs.S3Region,
		&bs.S3Bucket, &bs.S3AccessKeyEncrypted, &bs.S3SecretKeyEncrypted,
		&bs.S3PathPrefix, &bs.Schedule, &bs.RetentionDays, &bs.ProjectIDs, &bs.Enabled)
	if err != nil {
		return nil, err
	}
	if bs.ProjectIDs == nil {
		bs.ProjectIDs = []string{}
	}
	return &bs, nil
}

func (s *BackupService) getActiveProjects(ctx context.Context, userID string, filterIDs []string) ([]projectInfo, error) {
	var query string
	var args []interface{}

	if len(filterIDs) > 0 {
		query = `SELECT id, db_name FROM platform.projects
			WHERE user_id = $1 AND status = 'active' AND id::text = ANY($2)`
		args = []interface{}{userID, filterIDs}
	} else {
		query = `SELECT id, db_name FROM platform.projects
			WHERE user_id = $1 AND status = 'active'`
		args = []interface{}{userID}
	}

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []projectInfo
	for rows.Next() {
		var p projectInfo
		if err := rows.Scan(&p.id, &p.dbName); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

// isDue checks whether a backup should run for a specific project based on the schedule.
// It looks at the most recent completed backup for that project to decide.
func (s *BackupService) isDue(ctx context.Context, schedule, projectID string, now time.Time) bool {
	var lastCompleted time.Time
	err := s.db.QueryRow(ctx, `
		SELECT COALESCE(MAX(completed_at), '1970-01-01'::timestamptz)
		FROM platform.backup_history
		WHERE project_id = $1 AND status = 'completed'
	`, projectID).Scan(&lastCompleted)
	if err != nil {
		return true // if we can't tell, run anyway
	}

	switch schedule {
	case "hourly":
		return now.Sub(lastCompleted) >= 1*time.Hour
	case "daily":
		return now.Sub(lastCompleted) >= 24*time.Hour
	case "weekly":
		return now.Sub(lastCompleted) >= 7*24*time.Hour
	default:
		return now.Sub(lastCompleted) >= 24*time.Hour
	}
}

// runSingleBackup performs pg_dump and uploads the result to S3 for one project.
func (s *BackupService) runSingleBackup(ctx context.Context, userID, projectID, dbName string, settings *backupSettingsInternal) {
	now := time.Now().UTC()
	shortID := projectID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	s3Key := fmt.Sprintf("%s%s/%s_%s.dump",
		settings.S3PathPrefix,
		dbName,
		now.Format("2006-01-02T15-04-05Z"),
		shortID,
	)

	// Insert running record
	var historyID int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO platform.backup_history (user_id, project_id, db_name, s3_key, status)
		VALUES ($1, $2, $3, $4, 'running')
		RETURNING id
	`, userID, projectID, dbName, s3Key).Scan(&historyID)
	if err != nil {
		slog.Error("Backup: failed to insert history", "db_name", dbName, "error", err)
		return
	}

	// Run pg_dump
	reader, err := s.dumpDatabase(ctx, dbName)
	if err != nil {
		if ctx.Err() != nil {
			s.markBackupCancelled(ctx, historyID)
			return
		}
		s.markBackupFailed(ctx, historyID, fmt.Sprintf("pg_dump failed: %v", err))
		return
	}
	defer reader.Close()

	// Upload to S3
	sizeBytes, err := s.uploadToS3(ctx, settings, s3Key, reader)
	if err != nil {
		if ctx.Err() != nil {
			// Try to clean up partial upload with a fresh context
			s.deleteS3Object(context.Background(), settings, s3Key)
			s.markBackupCancelled(context.Background(), historyID)
			return
		}
		s.markBackupFailed(ctx, historyID, fmt.Sprintf("S3 upload failed: %v", err))
		return
	}

	// Mark completed
	if _, err := s.db.Exec(ctx, `
		UPDATE platform.backup_history
		SET status = 'completed', size_bytes = $1, completed_at = NOW()
		WHERE id = $2
	`, sizeBytes, historyID); err != nil {
		slog.Error("failed to update backup history", "error", err)
	}

	slog.Info("Backup completed", "db_name", dbName, "s3_key", s3Key, "size_bytes", sizeBytes)

	// Enforce retention policy
	prefix := settings.S3PathPrefix + dbName + "/"
	s.enforceRetention(ctx, settings, prefix)
}

func (s *BackupService) markBackupFailed(ctx context.Context, historyID int64, errMsg string) {
	slog.Error("Backup failed", "history_id", historyID, "error", errMsg)
	if _, err := s.db.Exec(ctx, `
		UPDATE platform.backup_history
		SET status = 'failed', error_message = $1, completed_at = NOW()
		WHERE id = $2
	`, errMsg, historyID); err != nil {
		slog.Error("failed to update backup history", "error", err)
	}
}

func (s *BackupService) markBackupCancelled(ctx context.Context, historyID int64) {
	slog.Info("Backup cancelled", "history_id", historyID)
	if _, err := s.db.Exec(ctx, `
		UPDATE platform.backup_history
		SET status = 'cancelled', completed_at = NOW()
		WHERE id = $1
	`, historyID); err != nil {
		slog.Error("failed to update backup history", "error", err)
	}
}

// deleteS3Object attempts to remove a partial S3 upload after cancellation.
func (s *BackupService) deleteS3Object(ctx context.Context, settings *backupSettingsInternal, key string) {
	client, err := s.getS3Client(ctx, settings)
	if err != nil {
		slog.Error("failed to create S3 client for cleanup", "error", err)
		return
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(settings.S3Bucket),
		Key:    aws.String(key),
	}); err != nil {
		slog.Error("failed to delete partial S3 backup", "key", key, "error", err)
	}
}

// dumpDatabase runs pg_dump for a specific database and returns a reader of the output.
func (s *BackupService) dumpDatabase(ctx context.Context, dbName string) (io.ReadCloser, error) {
	u, err := url.Parse(s.databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	u.Path = "/" + dbName

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	user := u.User.Username()
	password, _ := u.User.Password()

	cmd := exec.CommandContext(ctx, "pg_dump",
		"--format=custom",
		"--no-owner",
		"--no-acl",
		"--host="+host, "--port="+port, "--username="+user, "--dbname="+dbName,
	)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+password)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start pg_dump: %w", err)
	}

	return &dumpReader{cmd: cmd, ReadCloser: stdout}, nil
}

// dumpReader wraps the stdout pipe and waits for the command to finish on Close.
type dumpReader struct {
	cmd *exec.Cmd
	io.ReadCloser
}

func (r *dumpReader) Close() error {
	err := r.ReadCloser.Close()
	cmdErr := r.cmd.Wait()
	if err != nil {
		return err
	}
	return cmdErr
}

// uploadToS3 decrypts S3 credentials and uploads the dump to S3.
func (s *BackupService) uploadToS3(ctx context.Context, settings *backupSettingsInternal, key string, body io.Reader) (int64, error) {
	client, err := s.getS3Client(ctx, settings)
	if err != nil {
		return 0, fmt.Errorf("create S3 client: %w", err)
	}

	// We need to buffer to know the size; use a countingReader to track bytes.
	cr := &countingReader{r: body}
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(settings.S3Bucket),
		Key:    aws.String(key),
		Body:   cr,
	})
	if err != nil {
		return 0, fmt.Errorf("PutObject: %w", err)
	}

	return cr.n, nil
}

// countingReader counts the number of bytes read.
type countingReader struct {
	r io.Reader
	n int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

// getS3Client creates an S3 client from backup settings.
func (s *BackupService) getS3Client(ctx context.Context, settings *backupSettingsInternal) (*s3.Client, error) {
	accessKey, err := DecryptPgPassword(settings.S3AccessKeyEncrypted, s.backupKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt access key: %w", err)
	}
	secretKey, err := DecryptPgPassword(settings.S3SecretKeyEncrypted, s.backupKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret key: %w", err)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(settings.S3Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if settings.S3Endpoint != "" {
			o.BaseEndpoint = aws.String(settings.S3Endpoint)
			o.UsePathStyle = true
		}
	})
	return client, nil
}

// enforceRetention deletes backups older than the retention period from S3.
func (s *BackupService) enforceRetention(ctx context.Context, settings *backupSettingsInternal, prefix string) {
	if settings.RetentionDays <= 0 {
		return
	}

	client, err := s.getS3Client(ctx, settings)
	if err != nil {
		slog.Warn("failed to create S3 client for retention cleanup", "error", err)
		return
	}

	cutoff := time.Now().AddDate(0, 0, -settings.RetentionDays)

	var continuationToken *string
	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            &settings.S3Bucket,
			Prefix:            &prefix,
			ContinuationToken: continuationToken,
		}

		output, err := client.ListObjectsV2(ctx, input)
		if err != nil {
			slog.Warn("failed to list S3 objects for retention", "error", err)
			return
		}

		for _, obj := range output.Contents {
			if obj.LastModified != nil && obj.LastModified.Before(cutoff) {
				_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: &settings.S3Bucket,
					Key:    obj.Key,
				})
				if err != nil {
					slog.Warn("failed to delete old backup", "key", *obj.Key, "error", err)
				} else {
					slog.Info("deleted old backup", "key", *obj.Key, "age_days", int(time.Since(*obj.LastModified).Hours()/24))
				}
			}
		}

		if output.IsTruncated == nil || !*output.IsTruncated {
			break
		}
		continuationToken = output.NextContinuationToken
	}
}
