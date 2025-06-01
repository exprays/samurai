package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RateLimiter represents a token bucket rate limiter
type RateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	mutex      sync.Mutex
}

// RateLimiterStore stores rate limiters per IP/user
type RateLimiterStore struct {
	limiters map[string]*RateLimiter
	mutex    sync.RWMutex
	logger   *zap.SugaredLogger
}

// NewRateLimiterStore creates a new rate limiter store
func NewRateLimiterStore(logger *zap.SugaredLogger) *RateLimiterStore {
	store := &RateLimiterStore{
		limiters: make(map[string]*RateLimiter),
		logger:   logger,
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

// GetLimiter gets or creates a rate limiter for a key
func (s *RateLimiterStore) GetLimiter(key string, maxTokens int, refillRate time.Duration) *RateLimiter {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	limiter, exists := s.limiters[key]
	if !exists {
		limiter = &RateLimiter{
			tokens:     maxTokens,
			maxTokens:  maxTokens,
			refillRate: refillRate,
			lastRefill: time.Now(),
		}
		s.limiters[key] = limiter
	}

	return limiter
}

// cleanup removes old rate limiters
func (s *RateLimiterStore) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mutex.Lock()
		for key, limiter := range s.limiters {
			limiter.mutex.Lock()
			if time.Since(limiter.lastRefill) > time.Hour {
				delete(s.limiters, key)
			}
			limiter.mutex.Unlock()
		}
		s.mutex.Unlock()
	}
}

// Allow checks if the request is allowed
func (r *RateLimiter) Allow() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill)

	// Refill tokens based on elapsed time
	tokensToAdd := int(elapsed / r.refillRate)
	if tokensToAdd > 0 {
		r.tokens += tokensToAdd
		if r.tokens > r.maxTokens {
			r.tokens = r.maxTokens
		}
		r.lastRefill = now
	}

	if r.tokens > 0 {
		r.tokens--
		return true
	}

	return false
}

// Global rate limiter store
var globalRateLimiterStore *RateLimiterStore

// InitRateLimiter initializes the global rate limiter store
func InitRateLimiter(logger *zap.SugaredLogger) {
	globalRateLimiterStore = NewRateLimiterStore(logger)
}

// RateLimit middleware for general API rate limiting
func RateLimit(maxRequests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if globalRateLimiterStore == nil {
			c.Next()
			return
		}

		// Use IP address as key
		key := c.ClientIP()

		// Get or create rate limiter
		refillRate := window / time.Duration(maxRequests)
		limiter := globalRateLimiterStore.GetLimiter(key, maxRequests, refillRate)

		if !limiter.Allow() {
			globalRateLimiterStore.logger.Warnf("Rate limit exceeded for IP: %s", c.ClientIP())
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuthRateLimit middleware for authentication endpoints
func AuthRateLimit() gin.HandlerFunc {
	return RateLimit(5, time.Minute) // 5 requests per minute for auth endpoints
}

// APIRateLimit middleware for general API endpoints
func APIRateLimit() gin.HandlerFunc {
	return RateLimit(100, time.Minute) // 100 requests per minute for API endpoints
}

// UserRateLimit middleware for authenticated users (more permissive)
func UserRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if globalRateLimiterStore == nil {
			c.Next()
			return
		}

		// Use user ID if authenticated, otherwise IP
		key := c.ClientIP()
		if userID, exists := c.Get("user_id"); exists {
			key = userID.(string)
		}

		// Higher limits for authenticated users
		limiter := globalRateLimiterStore.GetLimiter(key, 200, 30*time.Second) // 200 requests per minute

		if !limiter.Allow() {
			globalRateLimiterStore.logger.Warnf("User rate limit exceeded for key: %s", key)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
