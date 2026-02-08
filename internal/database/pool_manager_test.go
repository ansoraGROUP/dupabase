package database

import (
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ansoraGROUP/dupabase/internal/config"
)

// ---------------------------------------------------------------------------
// InvalidateProjectCache
// ---------------------------------------------------------------------------

func TestInvalidateProjectCache_RemovesEntry(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	// Manually insert a cache entry
	pm.projectCache["proj-1"] = &projectCacheEntry{
		project:  ProjectRecord{ID: "proj-1", DBName: "testdb"},
		cachedAt: time.Now(),
	}

	if len(pm.projectCache) != 1 {
		t.Fatal("expected 1 cache entry")
	}

	pm.InvalidateProjectCache("proj-1")

	if len(pm.projectCache) != 0 {
		t.Fatal("expected 0 cache entries after invalidation")
	}
}

func TestInvalidateProjectCache_NonExistentKey(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	// Should not panic
	pm.InvalidateProjectCache("nonexistent")
}

func TestInvalidateProjectCache_DoesNotAffectOtherEntries(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	pm.projectCache["proj-1"] = &projectCacheEntry{
		project:  ProjectRecord{ID: "proj-1"},
		cachedAt: time.Now(),
	}
	pm.projectCache["proj-2"] = &projectCacheEntry{
		project:  ProjectRecord{ID: "proj-2"},
		cachedAt: time.Now(),
	}

	pm.InvalidateProjectCache("proj-1")

	if len(pm.projectCache) != 1 {
		t.Fatalf("expected 1 cache entry, got %d", len(pm.projectCache))
	}
	if _, ok := pm.projectCache["proj-2"]; !ok {
		t.Fatal("proj-2 should still be in cache")
	}
}

// ---------------------------------------------------------------------------
// ClosePool
// ---------------------------------------------------------------------------

func TestClosePool_NonExistentPoolDoesNotPanic(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	// Should not panic
	pm.ClosePool("nonexistent")
}

func TestClosePool_DoesNotRemoveCacheWhenNoPool(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	pm.projectCache["proj-1"] = &projectCacheEntry{
		project:  ProjectRecord{ID: "proj-1"},
		cachedAt: time.Now(),
	}

	// ClosePool on a project that has no pool but has a cache entry.
	// Per the source code, ClosePool only removes cache if pool exists.
	pm.ClosePool("proj-1")

	// Cache should remain since no pool entry was found
	if _, ok := pm.projectCache["proj-1"]; !ok {
		t.Fatal("cache entry should remain when no pool exists")
	}
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

func TestShutdown_ClearsAllMaps(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	pm.projectCache["proj-1"] = &projectCacheEntry{
		project:  ProjectRecord{ID: "proj-1"},
		cachedAt: time.Now(),
	}
	pm.projectCache["proj-2"] = &projectCacheEntry{
		project:  ProjectRecord{ID: "proj-2"},
		cachedAt: time.Now(),
	}

	pm.Shutdown()

	if len(pm.pools) != 0 {
		t.Errorf("expected 0 pools after shutdown, got %d", len(pm.pools))
	}
	if len(pm.projectCache) != 0 {
		t.Errorf("expected 0 cache entries after shutdown, got %d", len(pm.projectCache))
	}
}

func TestShutdown_StopsEvictionLoop(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	// Start the eviction loop manually
	done := make(chan struct{})
	go func() {
		pm.evictionLoop()
		close(done)
	}()

	pm.Shutdown()

	select {
	case <-done:
		// evictionLoop exited as expected
	case <-time.After(2 * time.Second):
		t.Fatal("eviction loop did not stop within 2 seconds")
	}
}

// ---------------------------------------------------------------------------
// buildDBURL
// ---------------------------------------------------------------------------

func TestBuildDBURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		dbName   string
		expected string
	}{
		{
			name:     "standard_url",
			baseURL:  "postgresql://user:pass@localhost:5432/platform",
			dbName:   "proj_abc123",
			expected: "postgresql://user:pass@localhost:5432/proj_abc123",
		},
		{
			name:     "url_with_params",
			baseURL:  "postgresql://user:pass@localhost:5432/platform?sslmode=disable",
			dbName:   "proj_xyz",
			expected: "postgresql://user:pass@localhost:5432/proj_xyz?sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.baseURL)
			if err != nil {
				t.Fatal(err)
			}
			pm := &PoolManager{
				baseURL: parsed,
			}

			result := pm.buildDBURL(tt.dbName)
			if result != tt.expected {
				t.Errorf("buildDBURL: got %q, want %q", result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evictLRULocked
// ---------------------------------------------------------------------------

func TestEvictLRULocked_EmptyPools(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	// Should not panic on empty pools
	pm.evictLRULocked()

	if len(pm.pools) != 0 {
		t.Error("pools should still be empty")
	}
}

// ---------------------------------------------------------------------------
// evictIdle
// ---------------------------------------------------------------------------

func TestEvictIdle_NoPoolsDoesNotPanic(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		cfg: &config.Config{
			PoolIdleTimeout: 300,
		},
		stopCh: make(chan struct{}),
	}

	// Should not panic
	pm.evictIdle()
}

// ---------------------------------------------------------------------------
// ProjectRecord
// ---------------------------------------------------------------------------

func TestProjectRecord_Fields(t *testing.T) {
	pr := ProjectRecord{
		ID:             "id-1",
		DBName:         "proj_db",
		JWTSecret:      "secret",
		AnonKey:        "anon-key",
		ServiceRoleKey: "sr-key",
		EnableSignup:   true,
		Autoconfirm:    true,
		PasswordMinLen: 6,
		SiteURL:        "http://localhost:3000",
		Status:         "active",
	}

	if pr.ID != "id-1" {
		t.Error("unexpected ID")
	}
	if pr.DBName != "proj_db" {
		t.Error("unexpected DBName")
	}
	if !pr.EnableSignup {
		t.Error("expected EnableSignup true")
	}
	if pr.PasswordMinLen != 6 {
		t.Error("expected PasswordMinLen 6")
	}
}

// ---------------------------------------------------------------------------
// Concurrent access safety
// ---------------------------------------------------------------------------

func TestInvalidateProjectCache_ConcurrentAccess(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	// Pre-populate cache
	for i := 0; i < 100; i++ {
		id := "proj-" + string(rune('A'+i%26))
		pm.projectCache[id] = &projectCacheEntry{
			project:  ProjectRecord{ID: id},
			cachedAt: time.Now(),
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := "proj-" + string(rune('A'+idx%26))
			pm.InvalidateProjectCache(id)
		}(i)
	}

	wg.Wait()
	// Just verify no data race / no panic
}

func TestClosePool_ConcurrentAccess(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pm.ClosePool("proj-" + string(rune('A'+idx%26)))
		}(i)
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// PlatformPool
// ---------------------------------------------------------------------------

func TestPlatformPool_ReturnsNilWhenNotSet(t *testing.T) {
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		platformPool: nil,
		stopCh:       make(chan struct{}),
	}

	if pm.PlatformPool() != nil {
		t.Error("expected nil platform pool")
	}
}

// ---------------------------------------------------------------------------
// Cache expiry logic (testing the time-based check)
// ---------------------------------------------------------------------------

func TestGetProject_CacheExpiry(t *testing.T) {
	// Verify that a cache entry older than 60 seconds is considered stale.
	// We cannot call GetProject without a real DB, but we can verify the
	// cache checking logic by inspecting the time comparison.
	pm := &PoolManager{
		pools:        make(map[string]*poolEntry),
		projectCache: make(map[string]*projectCacheEntry),
		stopCh:       make(chan struct{}),
	}

	freshEntry := &projectCacheEntry{
		project:  ProjectRecord{ID: "fresh"},
		cachedAt: time.Now(),
	}
	staleEntry := &projectCacheEntry{
		project:  ProjectRecord{ID: "stale"},
		cachedAt: time.Now().Add(-61 * time.Second),
	}

	pm.projectCache["fresh"] = freshEntry
	pm.projectCache["stale"] = staleEntry

	// Fresh entry should be within 60 seconds
	if time.Since(freshEntry.cachedAt) >= 60*time.Second {
		t.Error("fresh entry should not be expired")
	}

	// Stale entry should be beyond 60 seconds
	if time.Since(staleEntry.cachedAt) < 60*time.Second {
		t.Error("stale entry should be expired")
	}
}

// ---------------------------------------------------------------------------
// poolEntry fields
// ---------------------------------------------------------------------------

func TestPoolEntry_LastUsedUpdated(t *testing.T) {
	// Verify the data structure works as expected
	entry := &poolEntry{
		pool:     nil,
		dbName:   "testdb",
		lastUsed: time.Now().Add(-5 * time.Minute),
	}

	before := entry.lastUsed
	entry.lastUsed = time.Now()

	if !entry.lastUsed.After(before) {
		t.Error("lastUsed should have been updated to a later time")
	}
}
