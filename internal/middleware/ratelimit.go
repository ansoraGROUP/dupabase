package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/ansoraGROUP/dupabase/internal/httputil"
)

// RateLimiter implements a per-IP token bucket rate limiter.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	rate       float64 // tokens per second
	burst      int     // max tokens
	trustProxy bool
	stopCh     chan struct{}
}

type bucket struct {
	tokens   float64
	lastTime time.Time
}

// NewRateLimiter creates a rate limiter. rate = requests/second, burst = max burst size.
func NewRateLimiter(rate float64, burst int, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		burst:      burst,
		trustProxy: trustProxy,
		stopCh:     make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop shuts down the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	now := time.Now()

	if !ok {
		rl.buckets[ip] = &bucket{tokens: float64(rl.burst) - 1, lastTime: now}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastTime = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.extractIP(r)
		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded","error_description":"too many requests, please try again later"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware returns an HTTP middleware that rate-limits requests.
func (rl *RateLimiter) extractIP(r *http.Request) string {
	return httputil.ExtractClientIP(r, rl.trustProxy)
}

// cleanup removes stale entries every 5 minutes.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			stale := time.Now().Add(-10 * time.Minute)
			for ip, b := range rl.buckets {
				if b.lastTime.Before(stale) {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}
