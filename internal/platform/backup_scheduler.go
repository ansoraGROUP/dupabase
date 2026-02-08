package platform

import (
	"context"
	"fmt"
	"time"
)

// BackupScheduler periodically checks for and runs due backups.
type BackupScheduler struct {
	service *BackupService
	stopCh  chan struct{}
}

// NewBackupScheduler creates a new BackupScheduler.
func NewBackupScheduler(service *BackupService) *BackupScheduler {
	return &BackupScheduler{
		service: service,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the scheduler loop in a goroutine.
func (bs *BackupScheduler) Start() {
	go bs.run()
}

// Stop signals the scheduler to shut down.
func (bs *BackupScheduler) Stop() {
	close(bs.stopCh)
}

func (bs *BackupScheduler) run() {
	// Check every hour for backups that need to run
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Run once on startup after a short delay
	select {
	case <-time.After(30 * time.Second):
		bs.runDueBackups()
	case <-bs.stopCh:
		return
	}

	for {
		select {
		case <-ticker.C:
			bs.runDueBackups()
		case <-bs.stopCh:
			return
		}
	}
}

func (bs *BackupScheduler) runDueBackups() {
	ctx := context.Background()
	if err := bs.service.RunBackupsForAllUsers(ctx); err != nil {
		fmt.Printf("Backup scheduler error: %v\n", err)
	}
}
