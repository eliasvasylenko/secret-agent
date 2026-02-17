package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiter_Allow(t *testing.T) {
	tests := []struct {
		name           string
		numCalls       int
		limit          uint32
		window         time.Duration
		wantRetryAfter string // empty if no error
	}{
		{"disabled when limit zero", 5, 0, time.Minute, ""},
		{"disabled when window zero", 5, 2, 0, ""},
		{"under limit", 3, 3, time.Minute, ""},
		{"over limit", 3, 2, time.Minute, "60"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLimiter(tt.limit, tt.window)
			var lastErr error
			for i := 0; i < tt.numCalls; i++ {
				if lastErr != nil {
					t.Errorf("Allow() = %v, not finished yet, want nil", lastErr)
					break
				}
				lastErr = l.Allow("key")
			}
			if tt.wantRetryAfter != "" {
				if lastErr == nil {
					t.Fatal("Allow() = nil, want rate limit error")
				}
				var respErr *ErrorResponse
				if !errors.As(lastErr, &respErr) {
					t.Fatalf("Allow() = %T, want *ErrorResponse", lastErr)
				}
				if respErr.HttpError.Code != http.StatusTooManyRequests {
					t.Errorf("Code = %d, want %d", respErr.HttpError.Code, http.StatusTooManyRequests)
				}
				if got := respErr.Headers["Retry-After"]; got != tt.wantRetryAfter {
					t.Errorf("Retry-After = %q, want %q", got, tt.wantRetryAfter)
				}
			} else if lastErr != nil {
				t.Errorf("Allow() = %v, want nil", lastErr)
			}
		})
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
