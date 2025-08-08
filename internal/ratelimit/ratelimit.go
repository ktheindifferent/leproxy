package ratelimit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Limiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	rate     int
	burst    int
	ttl      time.Duration
	
	// DDoS protection
	blacklist     map[string]time.Time
	blacklistTTL  time.Duration
	suspiciousIPs map[string]int
	
	// Configuration
	enabled           bool
	whitelistedIPs    map[string]bool
	whitelistedRanges []*net.IPNet
}

type Visitor struct {
	limiter  *TokenBucket
	lastSeen time.Time
}

type TokenBucket struct {
	tokens    float64
	capacity  float64
	rate      float64
	lastCheck time.Time
	mu        sync.Mutex
}

type Config struct {
	RequestsPerSecond int
	Burst             int
	TTL               time.Duration
	BlacklistTTL      time.Duration
	Enabled           bool
	WhitelistedIPs    []string
	WhitelistedRanges []string
}

func New(cfg Config) (*Limiter, error) {
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 10
	}
	
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.RequestsPerSecond * 10
	}
	
	if cfg.TTL <= 0 {
		cfg.TTL = 3 * time.Minute
	}
	
	if cfg.BlacklistTTL <= 0 {
		cfg.BlacklistTTL = 1 * time.Hour
	}
	
	l := &Limiter{
		visitors:      make(map[string]*Visitor),
		rate:          cfg.RequestsPerSecond,
		burst:         cfg.Burst,
		ttl:           cfg.TTL,
		blacklist:     make(map[string]time.Time),
		blacklistTTL:  cfg.BlacklistTTL,
		suspiciousIPs: make(map[string]int),
		enabled:       cfg.Enabled,
		whitelistedIPs: make(map[string]bool),
	}
	
	// Parse whitelisted IPs
	for _, ip := range cfg.WhitelistedIPs {
		l.whitelistedIPs[ip] = true
	}
	
	// Parse whitelisted ranges
	for _, cidr := range cfg.WhitelistedRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR range %s: %w", cidr, err)
		}
		l.whitelistedRanges = append(l.whitelistedRanges, ipNet)
	}
	
	// Start cleanup goroutine
	go l.cleanupLoop()
	
	return l, nil
}

func (l *Limiter) Allow(ip string) bool {
	if !l.enabled {
		return true
	}
	
	// Check whitelist
	if l.isWhitelisted(ip) {
		return true
	}
	
	// Check blacklist
	l.mu.RLock()
	blacklistedUntil, isBlacklisted := l.blacklist[ip]
	l.mu.RUnlock()
	
	if isBlacklisted {
		if time.Now().Before(blacklistedUntil) {
			return false
		}
		// Remove expired blacklist entry
		l.mu.Lock()
		delete(l.blacklist, ip)
		l.mu.Unlock()
	}
	
	// Get or create visitor
	visitor := l.getVisitor(ip)
	
	// Check rate limit
	allowed := visitor.limiter.Allow()
	
	if !allowed {
		// Track suspicious behavior
		l.trackSuspiciousActivity(ip)
	}
	
	return allowed
}

func (l *Limiter) getVisitor(ip string) *Visitor {
	l.mu.RLock()
	visitor, exists := l.visitors[ip]
	l.mu.RUnlock()
	
	if !exists {
		l.mu.Lock()
		visitor, exists = l.visitors[ip]
		if !exists {
			visitor = &Visitor{
				limiter:  NewTokenBucket(float64(l.rate), float64(l.burst)),
				lastSeen: time.Now(),
			}
			l.visitors[ip] = visitor
		}
		l.mu.Unlock()
	} else {
		l.mu.Lock()
		visitor.lastSeen = time.Now()
		l.mu.Unlock()
	}
	
	return visitor
}

func (l *Limiter) isWhitelisted(ip string) bool {
	// Check exact match
	if l.whitelistedIPs[ip] {
		return true
	}
	
	// Check CIDR ranges
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	for _, ipNet := range l.whitelistedRanges {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	
	return false
}

func (l *Limiter) trackSuspiciousActivity(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.suspiciousIPs[ip]++
	
	// Auto-blacklist after too many violations
	if l.suspiciousIPs[ip] > 10 {
		l.blacklist[ip] = time.Now().Add(l.blacklistTTL)
		delete(l.suspiciousIPs, ip)
	}
}

func (l *Limiter) Blacklist(ip string, duration time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if duration <= 0 {
		duration = l.blacklistTTL
	}
	
	l.blacklist[ip] = time.Now().Add(duration)
}

func (l *Limiter) Unblacklist(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	delete(l.blacklist, ip)
	delete(l.suspiciousIPs, ip)
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		l.cleanup()
	}
}

func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	now := time.Now()
	
	// Clean up old visitors
	for ip, visitor := range l.visitors {
		if now.Sub(visitor.lastSeen) > l.ttl {
			delete(l.visitors, ip)
		}
	}
	
	// Clean up expired blacklist entries
	for ip, until := range l.blacklist {
		if now.After(until) {
			delete(l.blacklist, ip)
		}
	}
	
	// Clean up old suspicious IP tracking
	if len(l.suspiciousIPs) > 1000 {
		// Keep only recent entries
		l.suspiciousIPs = make(map[string]int)
	}
}

func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		
		if !l.Allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) Stats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	return Stats{
		ActiveVisitors: len(l.visitors),
		BlacklistedIPs: len(l.blacklist),
		SuspiciousIPs:  len(l.suspiciousIPs),
	}
}

type Stats struct {
	ActiveVisitors int
	BlacklistedIPs int
	SuspiciousIPs  int
}

func NewTokenBucket(rate, capacity float64) *TokenBucket {
	return &TokenBucket{
		tokens:    capacity,
		capacity:  capacity,
		rate:      rate,
		lastCheck: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(tb.lastCheck).Seconds()
	tb.lastCheck = now
	
	// Add tokens based on elapsed time
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	
	// Check if we have tokens available
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	
	return false
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	
	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}
	
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return host
}

// DDoS Protection features

type DDoSProtection struct {
	limiter           *Limiter
	connectionTracker *ConnectionTracker
	patternDetector   *PatternDetector
}

type ConnectionTracker struct {
	connections map[string]int
	mu          sync.RWMutex
	maxPerIP    int
}

func NewConnectionTracker(maxPerIP int) *ConnectionTracker {
	if maxPerIP <= 0 {
		maxPerIP = 100
	}
	
	return &ConnectionTracker{
		connections: make(map[string]int),
		maxPerIP:    maxPerIP,
	}
}

func (ct *ConnectionTracker) Add(ip string) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	ct.connections[ip]++
	return ct.connections[ip] <= ct.maxPerIP
}

func (ct *ConnectionTracker) Remove(ip string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	if ct.connections[ip] > 0 {
		ct.connections[ip]--
		if ct.connections[ip] == 0 {
			delete(ct.connections, ip)
		}
	}
}

type PatternDetector struct {
	requests  map[string][]*Request
	mu        sync.RWMutex
	window    time.Duration
	threshold int
}

type Request struct {
	Path      string
	Method    string
	Timestamp time.Time
	UserAgent string
}

func NewPatternDetector(window time.Duration, threshold int) *PatternDetector {
	if window <= 0 {
		window = 10 * time.Second
	}
	
	if threshold <= 0 {
		threshold = 50
	}
	
	pd := &PatternDetector{
		requests:  make(map[string][]*Request),
		window:    window,
		threshold: threshold,
	}
	
	go pd.cleanupLoop()
	
	return pd
}

func (pd *PatternDetector) Check(ip string, r *http.Request) bool {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	
	req := &Request{
		Path:      r.URL.Path,
		Method:    r.Method,
		Timestamp: time.Now(),
		UserAgent: r.UserAgent(),
	}
	
	pd.requests[ip] = append(pd.requests[ip], req)
	
	// Check for suspicious patterns
	recentRequests := pd.getRecentRequests(ip)
	
	// Pattern 1: Too many requests in window
	if len(recentRequests) > pd.threshold {
		return false
	}
	
	// Pattern 2: Identical requests (potential bot)
	if pd.hasIdenticalRequests(recentRequests, 10) {
		return false
	}
	
	// Pattern 3: Scanning pattern (sequential paths)
	if pd.hasScannningPattern(recentRequests) {
		return false
	}
	
	return true
}

func (pd *PatternDetector) getRecentRequests(ip string) []*Request {
	cutoff := time.Now().Add(-pd.window)
	recent := make([]*Request, 0)
	
	for _, req := range pd.requests[ip] {
		if req.Timestamp.After(cutoff) {
			recent = append(recent, req)
		}
	}
	
	return recent
}

func (pd *PatternDetector) hasIdenticalRequests(requests []*Request, threshold int) bool {
	if len(requests) < threshold {
		return false
	}
	
	counts := make(map[string]int)
	for _, req := range requests {
		key := fmt.Sprintf("%s:%s:%s", req.Method, req.Path, req.UserAgent)
		counts[key]++
		if counts[key] >= threshold {
			return true
		}
	}
	
	return false
}

func (pd *PatternDetector) hasScannningPattern(requests []*Request) bool {
	if len(requests) < 5 {
		return false
	}
	
	// Check for common scanning patterns
	scanPaths := []string{
		"/admin", "/wp-admin", "/phpmyadmin", "/.env",
		"/config", "/backup", "/api/v1", "/.git",
	}
	
	scanCount := 0
	for _, req := range requests {
		for _, scanPath := range scanPaths {
			if strings.Contains(req.Path, scanPath) {
				scanCount++
				if scanCount >= 3 {
					return true
				}
			}
		}
	}
	
	return false
}

func (pd *PatternDetector) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		pd.cleanup()
	}
}

func (pd *PatternDetector) cleanup() {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	
	cutoff := time.Now().Add(-pd.window * 2)
	
	for ip, requests := range pd.requests {
		filtered := make([]*Request, 0)
		for _, req := range requests {
			if req.Timestamp.After(cutoff) {
				filtered = append(filtered, req)
			}
		}
		
		if len(filtered) == 0 {
			delete(pd.requests, ip)
		} else {
			pd.requests[ip] = filtered
		}
	}
}

func NewDDoSProtection(cfg Config) (*DDoSProtection, error) {
	limiter, err := New(cfg)
	if err != nil {
		return nil, err
	}
	
	return &DDoSProtection{
		limiter:           limiter,
		connectionTracker: NewConnectionTracker(100),
		patternDetector:   NewPatternDetector(10*time.Second, 50),
	}, nil
}

func (ddos *DDoSProtection) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		
		// Check rate limit
		if !ddos.limiter.Allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		
		// Check connection limit
		if !ddos.connectionTracker.Add(ip) {
			http.Error(w, "Too Many Connections", http.StatusTooManyRequests)
			return
		}
		defer ddos.connectionTracker.Remove(ip)
		
		// Check for suspicious patterns
		if !ddos.patternDetector.Check(ip, r) {
			ddos.limiter.Blacklist(ip, 1*time.Hour)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}