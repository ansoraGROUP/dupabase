package platform

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"
)

// BackupScheduler periodically checks for and runs due backups.
type BackupScheduler struct {
	service      *BackupService
	stopCh       chan struct{}
	stopOnce     sync.Once
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	startupDelay time.Duration
}

// NewBackupScheduler creates a new BackupScheduler.
func NewBackupScheduler(service *BackupService) *BackupScheduler {
	delay := 30 * time.Second
	if d := os.Getenv("BACKUP_SCHEDULER_STARTUP_DELAY"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			delay = parsed
		}
	}
	return &BackupScheduler{
		service:      service,
		stopCh:       make(chan struct{}),
		startupDelay: delay,
	}
}

// Start begins the scheduler loop in a goroutine.
func (bs *BackupScheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	bs.cancel = cancel
	bs.wg.Add(1)
	go bs.run(ctx)
}

// Stop signals the scheduler to shut down and waits for it to finish.
// It is safe to call Stop multiple times.
func (bs *BackupScheduler) Stop() {
	bs.stopOnce.Do(func() {
		close(bs.stopCh)
		if bs.cancel != nil {
			bs.cancel()
		}
	})
	bs.wg.Wait()
}

func (bs *BackupScheduler) run(ctx context.Context) {
	defer bs.wg.Done()

	// Check every hour for backups that need to run
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Run once on startup after a short delay
	select {
	case <-time.After(bs.startupDelay):
		bs.runDueBackups(ctx)
	case <-bs.stopCh:
		return
	}

	for {
		select {
		case <-ticker.C:
			bs.runDueBackups(ctx)
		case <-bs.stopCh:
			return
		}
	}
}

func (bs *BackupScheduler) runDueBackups(ctx context.Context) {
	if err := bs.service.RunBackupsForAllUsers(ctx); err != nil {
		slog.Error("Backup scheduler error", "error", err)
	}
}
