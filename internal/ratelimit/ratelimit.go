package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	rate    float64                 // tokens per second
	burst   int                     // maximum burst size
	buckets map[string]*TokenBucket // buckets per client key
	mu      sync.RWMutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:    rate,
		burst:   burst,
		buckets: make(map[string]*TokenBucket),
	}
}

// createBucket creates a new token bucket for a key
func (rl *RateLimiter) createBucket() *TokenBucket {
	return &TokenBucket{
		tokens:     float64(rl.burst),
		lastRefill: time.Now(),
	}
}

// getBucket gets or creates a bucket for the given key
func (rl *RateLimiter) getBucket(key string) *TokenBucket {
	rl.mu.RLock()
	bucket, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		if bucket, exists = rl.buckets[key]; !exists {
			bucket = rl.createBucket()
			rl.buckets[key] = bucket
		}
		rl.mu.Unlock()
	}

	return bucket
}

// refillBucket refills a bucket with tokens based on elapsed time
func (rl *RateLimiter) refillBucket(bucket *TokenBucket) {
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	tokensToAdd := elapsed * rl.rate

	bucket.tokens = min(bucket.tokens+tokensToAdd, float64(rl.burst))
	bucket.lastRefill = now
}

// CheckRateLimit checks if a request is within rate limits
func (rl *RateLimiter) CheckRateLimit(key string, tokens int) (allowed bool, retryAfter float64) {
	bucket := rl.getBucket(key)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	rl.refillBucket(bucket)

	tokensNeeded := float64(tokens)
	if bucket.tokens >= tokensNeeded {
		// Request is allowed, consume tokens
		bucket.tokens -= tokensNeeded
		return true, 0.0
	}

	// Request exceeds rate limit
	// Calculate how long until enough tokens are available
	missingTokens := tokensNeeded - bucket.tokens
	retryAfter = missingTokens / rl.rate

	return false, retryAfter
}

// GetStats returns statistics about the rate limiter
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := map[string]interface{}{
		"rate":        rl.rate,
		"burst":       rl.burst,
		"active_keys": len(rl.buckets),
	}

	// Add per-key statistics
	keyStats := make(map[string]interface{})
	for key, bucket := range rl.buckets {
		bucket.mu.Lock()
		rl.refillBucket(bucket) // Update tokens before reporting
		keyStats[key] = map[string]interface{}{
			"tokens":      bucket.tokens,
			"last_refill": bucket.lastRefill,
		}
		bucket.mu.Unlock()
	}
	stats["keys"] = keyStats

	return stats
}

// CleanupStaleKeys removes buckets that haven't been used recently
func (rl *RateLimiter) CleanupStaleKeys(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, bucket := range rl.buckets {
		bucket.mu.Lock()
		if now.Sub(bucket.lastRefill) > maxAge {
			delete(rl.buckets, key)
		}
		bucket.mu.Unlock()
	}
}

// StartCleanupRoutine starts a goroutine that periodically cleans up stale keys
func (rl *RateLimiter) StartCleanupRoutine(interval, maxAge time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			rl.CleanupStaleKeys(maxAge)
		}
	}()
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
