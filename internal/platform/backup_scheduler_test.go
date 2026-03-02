package platform

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BackupScheduler Stop() cancellation
// ---------------------------------------------------------------------------

func TestBackupScheduler_StopCancelsCleanly(t *testing.T) {
	// Create a scheduler with a nil service (we won't actually run backups)
	svc := &BackupService{}
	scheduler := &BackupScheduler{
		service:      svc,
		stopCh:       make(chan struct{}),
		startupDelay: 1 * time.Hour, // long delay so run() blocks on startup
	}

	scheduler.Start()

	// Stop should return without hanging
	done := make(chan struct{})
	go func() {
		scheduler.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success — Stop returned cleanly
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5 seconds — possible goroutine leak")
	}
}

func TestBackupScheduler_DoubleStopSafe(t *testing.T) {
	// Double Stop() should be safe thanks to sync.Once guarding the channel close.
	svc := &BackupService{}
	scheduler := &BackupScheduler{
		service:      svc,
		stopCh:       make(chan struct{}),
		startupDelay: 1 * time.Hour,
	}

	scheduler.Start()
	scheduler.Stop()

	// Second Stop should NOT panic
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		scheduler.Stop()
	}()

	if panicked {
		t.Error("second Stop() should not panic (sync.Once protects channel close)")
	}
}

func TestNewBackupScheduler(t *testing.T) {
	svc := &BackupService{}
	scheduler := NewBackupScheduler(svc)
	if scheduler == nil {
		t.Fatal("NewBackupScheduler returned nil")
	}
	if scheduler.service != svc {
		t.Error("unexpected service reference")
	}
	if scheduler.stopCh == nil {
		t.Error("stopCh should not be nil")
	}
	// Default startup delay is 30s
	if scheduler.startupDelay != 30*time.Second {
		t.Errorf("expected default startup delay 30s, got %v", scheduler.startupDelay)
	}
}

func TestNewBackupScheduler_CustomDelay(t *testing.T) {
	t.Setenv("BACKUP_SCHEDULER_STARTUP_DELAY", "5s")
	svc := &BackupService{}
	scheduler := NewBackupScheduler(svc)
	if scheduler.startupDelay != 5*time.Second {
		t.Errorf("expected custom startup delay 5s, got %v", scheduler.startupDelay)
	}
}

func TestNewBackupScheduler_InvalidDelay(t *testing.T) {
	t.Setenv("BACKUP_SCHEDULER_STARTUP_DELAY", "notaduration")
	svc := &BackupService{}
	scheduler := NewBackupScheduler(svc)
	// Invalid duration should fall back to default 30s
	if scheduler.startupDelay != 30*time.Second {
		t.Errorf("expected default 30s for invalid delay, got %v", scheduler.startupDelay)
	}
}
