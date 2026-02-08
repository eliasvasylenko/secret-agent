package server

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Limiter struct {
	requestLimit  uint32
	requestWindow time.Duration
	counters      map[string]*Counter
	mu            sync.Mutex
}

type Counter struct {
	latestWindowFrom time.Time
	latestBucket     Bucket
	previousBucket   Bucket
	mu               sync.Mutex
}

type Bucket uint32

func NewLimiter(limit uint32, window time.Duration) *Limiter {
	return &Limiter{
		requestLimit:  limit,
		requestWindow: window,
		counters:      make(map[string]*Counter),
	}
}

func (r *Limiter) Allow(key string) error {
	if r.requestLimit <= 0 || r.requestWindow <= 0 {
		return nil
	}
	return r.getCounter(key).Increment(r.requestWindow, r.requestLimit)
}

func (r *Limiter) getCounter(key string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()

	counter, ok := r.counters[key]
	if !ok {
		counter = NewCounter()
		r.counters[key] = counter
	}
	return counter
}

func NewCounter() *Counter {
	return &Counter{}
}

func (c *Counter) Increment(window time.Duration, limit uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	c.slideWindow(window, now)
	count := c.approximateCount(window, now)

	ok := count < limit

	if ok {
		c.latestBucket++
		return nil
	} else {
		err := NewErrorResponse(http.StatusTooManyRequests, errors.New("rate limit exceeded"))
		err.Headers["Retry-After"] = fmt.Sprintf("%d", int(window.Seconds()))
		return err
	}
}

func (c *Counter) slideWindow(window time.Duration, now time.Time) {
	currentWindowFrom := now.Truncate(window)
	if currentWindowFrom.After(c.latestWindowFrom) {
		priorWindowFrom := currentWindowFrom.Add(-window)
		if priorWindowFrom.After(c.latestWindowFrom) {
			c.previousBucket = 0
		} else {
			c.previousBucket = c.latestBucket
		}

		c.latestWindowFrom = currentWindowFrom
		c.latestBucket = 0
	}
}

func (c *Counter) approximateCount(window time.Duration, now time.Time) uint32 {
	elapsed := now.Sub(c.latestWindowFrom)
	remaining := window - elapsed
	fraction := float64(remaining) / float64(window)
	return uint32(float64(c.previousBucket)*fraction) + uint32(c.latestBucket)
}
