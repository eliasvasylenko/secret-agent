package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiter_Allow_disabledWhenLimitZero(t *testing.T) {
	l := NewLimiter(0, time.Minute)
	for i := 0; i < 5; i++ {
		if err := l.Allow("key"); err != nil {
			t.Errorf("Allow() = %v, want nil (limit 0 disables limiting)", err)
		}
	}
}

func TestLimiter_Allow_disabledWhenWindowZero(t *testing.T) {
	l := NewLimiter(2, 0)
	for i := 0; i < 5; i++ {
		if err := l.Allow("key"); err != nil {
			t.Errorf("Allow() = %v, want nil (window 0 disables limiting)", err)
		}
	}
}

func TestLimiter_Allow_underLimit(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if err := l.Allow("user"); err != nil {
			t.Errorf("Allow() call %d = %v, want nil", i+1, err)
		}
	}
}

func TestLimiter_Allow_overLimit(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	_ = l.Allow("user")
	_ = l.Allow("user")
	err := l.Allow("user")
	if err == nil {
		t.Fatal("Allow() = nil, want rate limit error")
	}
	var respErr *ErrorResponse
	if !errors.As(err, &respErr) {
		t.Fatalf("Allow() = %T, want *ErrorResponse", err)
	}
	if respErr.HttpError.Code != http.StatusTooManyRequests {
		t.Errorf("Code = %d, want %d", respErr.HttpError.Code, http.StatusTooManyRequests)
	}
	if retryAfter := respErr.Headers["Retry-After"]; retryAfter != "60" {
		t.Errorf("Retry-After = %q, want \"60\" (window in seconds)", retryAfter)
	}
}

func TestLimiter_Allow_perKey(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	if err := l.Allow("alice"); err != nil {
		t.Errorf("Allow(alice) = %v", err)
	}
	if err := l.Allow("bob"); err != nil {
		t.Errorf("Allow(bob) = %v", err)
	}
	err := l.Allow("alice")
	if err == nil {
		t.Fatal("Allow(alice) second call = nil, want rate limit error")
	}
}

func TestLimiter_Middleware_callsNextWhenAllowed(t *testing.T) {
	l := NewLimiter(5, time.Minute)
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(func(r *http.Request) string { return "key" }, next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestLimiter_Middleware_returns429WhenOverLimit(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	handler := l.Middleware(func(r *http.Request) string { return "key" }, next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first request status = %d, want 200", rec.Code)
	}
	if !nextCalled {
		t.Error("first request: next handler was not called")
	}

	nextCalled = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("second request: next handler was called (should be rate limited)")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestLimiter_Middleware_usesKeyFromRequest(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(func(r *http.Request) string { return r.Header.Get("X-User") }, next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User", "alice")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("alice first request status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User", "bob")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("bob request status = %d (bob has separate quota)", rec.Code)
	}
}
