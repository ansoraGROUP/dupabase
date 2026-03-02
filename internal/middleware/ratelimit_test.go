package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(10, 5, false)
	defer rl.Stop()

	// First request from a new IP should always be allowed
	if !rl.Allow("192.168.1.1") {
		t.Error("expected first request to be allowed")
	}
}

func TestRateLimiter_BurstExhaustion(t *testing.T) {
	burst := 5
	rl := NewRateLimiter(1, burst, false)
	defer rl.Stop()

	// Exhaust the burst for one IP
	for i := 0; i < burst; i++ {
		if !rl.Allow("10.0.0.1") {
			t.Errorf("request %d should be allowed within burst", i+1)
		}
	}

	// Next request should be denied (burst exhausted, not enough time for refill)
	if rl.Allow("10.0.0.1") {
		t.Error("expected request to be denied after burst exhaustion")
	}
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := NewRateLimiter(1, 2, false)
	defer rl.Stop()

	// Exhaust burst for IP A
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")

	// IP B should still be allowed (independent bucket)
	if !rl.Allow("10.0.0.2") {
		t.Error("different IP should have independent bucket")
	}
}

func TestRateLimiter_ConcurrentSameIP(t *testing.T) {
	rl := NewRateLimiter(10, 20, false)
	defer rl.Stop()

	var wg sync.WaitGroup
	var allowed atomic.Int64
	var denied atomic.Int64

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("192.168.1.1") {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	if allowed.Load() == 0 {
		t.Error("expected some requests to be allowed")
	}
	if denied.Load() == 0 {
		t.Error("expected some requests to be denied with burst 20 and 100 concurrent")
	}
	t.Logf("allowed=%d denied=%d", allowed.Load(), denied.Load())
}

func TestRateLimiter_ConcurrentDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(10, 20, false)
	defer rl.Stop()

	var wg sync.WaitGroup
	errors := make(chan string, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		ip := fmt.Sprintf("10.0.0.%d", i)
		go func(ip string) {
			defer wg.Done()
			// Each unique IP should be allowed (fresh bucket)
			if !rl.Allow(ip) {
				errors <- fmt.Sprintf("expected %s to be allowed (fresh bucket)", ip)
			}
		}(ip)
	}
	wg.Wait()
	close(errors)

	for msg := range errors {
		t.Error(msg)
	}
}

func TestRateLimiter_Middleware(t *testing.T) {
	rl := NewRateLimiter(1, 2, false)
	defer rl.Stop()

	innerCalled := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled++
		w.WriteHeader(http.StatusOK)
	})
	handler := rl.Middleware(inner)

	// First two requests should pass (burst=2)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// Third request should be rate-limited
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "1" {
		t.Errorf("expected Retry-After: 1, got %q", rec.Header().Get("Retry-After"))
	}
}

func TestRateLimiter_MiddlewareDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(1, 1, false)
	defer rl.Stop()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rl.Middleware(inner)

	// First IP exhausts its bucket
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:12345"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	// Second IP should still be allowed
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "5.6.7.8:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected different IP to be allowed, got %d", rec2.Code)
	}
}

func TestRateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter(10, 20, false)
	rl.Stop()
	// Verify Allow still works after Stop (graceful degradation)
	if !rl.Allow("10.0.0.1") {
		t.Error("expected Allow to still work after Stop")
	}
}
