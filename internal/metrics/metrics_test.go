package metrics

import "testing"

func TestSnapAggregates(t *testing.T) {
	// Record a mix of requests and errors.
	Record("GET", 200, 100, 2000, 0.02)
	Record("GET", 200, 0, 1500, 0.2)
	Record("PUT", 200, 5000, 0, 0.05)
	Record("GET", 404, 0, 50, 0.3)
	Record("PUT", 500, 10, 0, 1.2)
	APIError("NoSuchKey")
	APIError("NoSuchKey")
	APIError("AccessDenied")

	s := Snap()
	if s.Requests != 5 {
		t.Fatalf("requests: want 5, got %d", s.Requests)
	}
	if s.RequestsByClass["2xx"] != 3 || s.RequestsByClass["4xx"] != 1 || s.RequestsByClass["5xx"] != 1 {
		t.Fatalf("by-class wrong: %v", s.RequestsByClass)
	}
	if s.Errors != 3 || s.TopErrors["NoSuchKey"] != 2 {
		t.Fatalf("errors wrong: total=%d top=%v", s.Errors, s.TopErrors)
	}
	if s.BytesIn != 5110 || s.BytesOut != 3550 {
		t.Fatalf("bytes wrong: in=%d out=%d", s.BytesIn, s.BytesOut)
	}
	if s.AvgLatencyMs <= 0 || s.P50Ms <= 0 || s.P95Ms < s.P50Ms {
		t.Fatalf("latency wrong: avg=%.1f p50=%.1f p95=%.1f", s.AvgLatencyMs, s.P50Ms, s.P95Ms)
	}
}
