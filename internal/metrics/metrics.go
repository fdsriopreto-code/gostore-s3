// Package metrics is a tiny dependency-free Prometheus exposition. The API
// middleware calls Record for every request; the /gostore/metrics handler
// gathers point-in-time gauges (capacity, per-bucket usage) and renders the
// text format.
package metrics

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	start = time.Now()

	mu       sync.Mutex
	reqTotal = map[reqKey]uint64{}
	errTotal = map[string]uint64{}

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	// integrityFail counts objects whose assembled bytes failed the
	// end-to-end checksum check on read (shard-assembly / decode bug that
	// per-block bitrot hashes cannot catch).
	integrityFail atomic.Uint64
	healObjects   atomic.Uint64
	healFail      atomic.Uint64
	repairQueued  atomic.Uint64 // objects enqueued for heal from the read path

	// request-duration histogram (seconds), fixed buckets.
	durBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	durCounts  = make([]uint64, len(durBuckets)+1) // last = +Inf
	durSum     float64
	durN       uint64

	version = "dev"

	// runtime sizing, set once at startup from the container CPU quota.
	rtGomaxprocs atomic.Int64
	rtHostCPU    atomic.Int64
	rtCPUQuota   atomic.Uint64 // milli-cores (quota * 1000)
)

// SetRuntimeInfo records the effective GOMAXPROCS, the host core count, and
// the container CPU quota (in cores) for gostore_runtime_* gauges.
func SetRuntimeInfo(gomaxprocs, hostCPU int, cpuQuota float64) {
	rtGomaxprocs.Store(int64(gomaxprocs))
	rtHostCPU.Store(int64(hostCPU))
	rtCPUQuota.Store(uint64(cpuQuota * 1000))
}

type reqKey struct {
	method string
	class  string // "2xx", "4xx", ...
}

// SetVersion records the build version for gostore_build_info.
func SetVersion(v string) { version = v }

// APIError counts one S3 error response by its code (e.g. "NoSuchKey").
func APIError(code string) {
	mu.Lock()
	errTotal[code]++
	mu.Unlock()
}

// IntegrityFailure records one object that failed end-to-end checksum
// verification when it was read back.
func IntegrityFailure() { integrityFail.Add(1) }

// RepairQueued records that a read reconstructed around a bad shard and
// enqueued the object for background heal.
func RepairQueued() { repairQueued.Add(1) }

// HealResult records the outcome of one background heal attempt.
func HealResult(ok bool) {
	if ok {
		healObjects.Add(1)
	} else {
		healFail.Add(1)
	}
}

// Record accounts one finished HTTP request.
func Record(method string, status int, inBytes, outBytes int64, seconds float64) {
	if status <= 0 {
		status = 200
	}
	k := reqKey{method: method, class: strconv.Itoa(status/100) + "xx"}
	mu.Lock()
	reqTotal[k]++
	i := 0
	for ; i < len(durBuckets); i++ {
		if seconds <= durBuckets[i] {
			break
		}
	}
	durCounts[i]++
	durSum += seconds
	durN++
	mu.Unlock()
	if inBytes > 0 {
		bytesIn.Add(uint64(inBytes))
	}
	if outBytes > 0 {
		bytesOut.Add(uint64(outBytes))
	}
}

// Snapshot is a JSON-friendly aggregate of the live counters, for the console
// (served at /gostore/admin/v1/metrics). It is cheap to produce and read-only.
type Snapshot struct {
	UptimeSeconds     int64             `json:"uptimeSeconds"`
	Requests          uint64            `json:"requests"`
	RequestsByClass   map[string]uint64 `json:"requestsByClass"`
	Errors            uint64            `json:"errors"`
	TopErrors         map[string]uint64 `json:"topErrors"`
	BytesIn           uint64            `json:"bytesIn"`
	BytesOut          uint64            `json:"bytesOut"`
	AvgLatencyMs      float64           `json:"avgLatencyMs"`
	P50Ms             float64           `json:"p50Ms"`
	P95Ms             float64           `json:"p95Ms"`
	Goroutines        int               `json:"goroutines"`
	IntegrityFailures uint64            `json:"integrityFailures"`
	HealOK            uint64            `json:"healOk"`
	HealFailed        uint64            `json:"healFailed"`
	RepairQueued      uint64            `json:"repairQueued"`
}

// Snap returns a point-in-time copy of the aggregated request metrics.
func Snap() Snapshot {
	mu.Lock()
	var total uint64
	byClass := map[string]uint64{}
	for k, v := range reqTotal {
		total += v
		byClass[k.class] += v
	}
	var errs uint64
	top := map[string]uint64{}
	for c, v := range errTotal {
		errs += v
		top[c] = v
	}
	avg := 0.0
	if durN > 0 {
		avg = durSum / float64(durN)
	}
	p50 := histPercentileLocked(0.50)
	p95 := histPercentileLocked(0.95)
	mu.Unlock()
	return Snapshot{
		UptimeSeconds:     int64(time.Since(start).Seconds()),
		Requests:          total,
		RequestsByClass:   byClass,
		Errors:            errs,
		TopErrors:         top,
		BytesIn:           bytesIn.Load(),
		BytesOut:          bytesOut.Load(),
		AvgLatencyMs:      avg * 1000,
		P50Ms:             p50 * 1000,
		P95Ms:             p95 * 1000,
		Goroutines:        runtime.NumGoroutine(),
		IntegrityFailures: integrityFail.Load(),
		HealOK:            healObjects.Load(),
		HealFailed:        healFail.Load(),
		RepairQueued:      repairQueued.Load(),
	}
}

// histPercentileLocked approximates a latency percentile (seconds) from the
// fixed-bucket histogram. Caller holds mu.
func histPercentileLocked(p float64) float64 {
	if durN == 0 {
		return 0
	}
	target := uint64(float64(durN) * p)
	var cum uint64
	for i, c := range durCounts {
		cum += c
		if cum >= target {
			if i < len(durBuckets) {
				return durBuckets[i]
			}
			break
		}
	}
	return durBuckets[len(durBuckets)-1]
}

// BucketUsage is one bucket's accounted size for the gauges.
type BucketUsage struct {
	Bucket  string
	Objects int64
	Bytes   int64
}

// Gauges are the point-in-time values the handler collects per scrape.
type Gauges struct {
	Mode          string
	DisksTotal    int
	DisksOnline   int
	CapacityBytes uint64
	FreeBytes     uint64
	Buckets       []BucketUsage
	HealingDrives int
	Healthy       bool
}

// WritePrometheus renders the exposition format.
func WritePrometheus(w io.Writer, g Gauges) {
	var b strings.Builder

	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	help := func(name, typ, doc string) {
		line("# HELP " + name + " " + doc)
		line("# TYPE " + name + " " + typ)
	}

	help("gostore_build_info", "gauge", "Build metadata; value is always 1.")
	line(fmt.Sprintf("gostore_build_info{version=%q,mode=%q} 1", version, g.Mode))

	help("gostore_uptime_seconds", "gauge", "Seconds since the process started.")
	line(fmt.Sprintf("gostore_uptime_seconds %d", int64(time.Since(start).Seconds())))

	if p := rtGomaxprocs.Load(); p > 0 {
		help("gostore_runtime_gomaxprocs", "gauge", "Effective GOMAXPROCS.")
		line(fmt.Sprintf("gostore_runtime_gomaxprocs %d", p))
		help("gostore_runtime_host_cpu", "gauge", "CPU cores visible on the host.")
		line(fmt.Sprintf("gostore_runtime_host_cpu %d", rtHostCPU.Load()))
		help("gostore_runtime_cpu_quota_cores", "gauge", "Container CPU quota in cores (0 = unlimited).")
		line(fmt.Sprintf("gostore_runtime_cpu_quota_cores %s", strconv.FormatFloat(float64(rtCPUQuota.Load())/1000, 'g', -1, 64)))
	}
	help("gostore_runtime_goroutines", "gauge", "Current goroutine count.")
	line(fmt.Sprintf("gostore_runtime_goroutines %d", runtime.NumGoroutine()))

	help("gostore_up", "gauge", "1 when storage reports healthy, else 0.")
	up := 0
	if g.Healthy {
		up = 1
	}
	line(fmt.Sprintf("gostore_up %d", up))

	help("gostore_http_requests_total", "counter", "HTTP requests by method and status class.")
	mu.Lock()
	keys := make([]reqKey, 0, len(reqTotal))
	for k := range reqTotal {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].class < keys[j].class
	})
	for _, k := range keys {
		line(fmt.Sprintf("gostore_http_requests_total{method=%q,status=%q} %d", k.method, k.class, reqTotal[k]))
	}
	mu.Unlock()

	help("gostore_http_request_bytes_total", "counter", "Total request body bytes received.")
	line(fmt.Sprintf("gostore_http_request_bytes_total %d", bytesIn.Load()))
	help("gostore_http_response_bytes_total", "counter", "Total response body bytes sent.")
	line(fmt.Sprintf("gostore_http_response_bytes_total %d", bytesOut.Load()))

	help("gostore_http_request_duration_seconds", "histogram", "Request latency.")
	mu.Lock()
	var cum uint64
	for i, ub := range durBuckets {
		cum += durCounts[i]
		line(fmt.Sprintf("gostore_http_request_duration_seconds_bucket{le=%q} %d", strconv.FormatFloat(ub, 'g', -1, 64), cum))
	}
	cum += durCounts[len(durBuckets)]
	line(fmt.Sprintf("gostore_http_request_duration_seconds_bucket{le=\"+Inf\"} %d", cum))
	line(fmt.Sprintf("gostore_http_request_duration_seconds_sum %s", strconv.FormatFloat(durSum, 'g', -1, 64)))
	line(fmt.Sprintf("gostore_http_request_duration_seconds_count %d", durN))
	mu.Unlock()

	mu.Lock()
	if len(errTotal) > 0 {
		help("gostore_s3_errors_total", "counter", "S3 error responses by code.")
		ecodes := make([]string, 0, len(errTotal))
		for c := range errTotal {
			ecodes = append(ecodes, c)
		}
		sort.Strings(ecodes)
		for _, c := range ecodes {
			line(fmt.Sprintf("gostore_s3_errors_total{code=%q} %d", c, errTotal[c]))
		}
	}
	mu.Unlock()

	if v := integrityFail.Load(); v > 0 {
		help("gostore_integrity_failures_total", "counter", "Objects that failed end-to-end checksum verification on read.")
		line(fmt.Sprintf("gostore_integrity_failures_total %d", v))
	}
	if ok, bad := healObjects.Load(), healFail.Load(); ok > 0 || bad > 0 {
		help("gostore_heal_objects_total", "counter", "Background heal attempts by outcome.")
		line(fmt.Sprintf("gostore_heal_objects_total{result=%q} %d", "ok", ok))
		line(fmt.Sprintf("gostore_heal_objects_total{result=%q} %d", "error", bad))
	}
	if v := repairQueued.Load(); v > 0 {
		help("gostore_read_repair_queued_total", "counter", "Objects enqueued for heal because a read reconstructed around a bad shard.")
		line(fmt.Sprintf("gostore_read_repair_queued_total %d", v))
	}

	help("gostore_disks", "gauge", "Disk counts by state.")
	line(fmt.Sprintf("gostore_disks{state=\"total\"} %d", g.DisksTotal))
	line(fmt.Sprintf("gostore_disks{state=\"online\"} %d", g.DisksOnline))
	line(fmt.Sprintf("gostore_disks{state=\"healing\"} %d", g.HealingDrives))

	help("gostore_capacity_bytes", "gauge", "Total raw capacity across disks.")
	line(fmt.Sprintf("gostore_capacity_bytes %d", g.CapacityBytes))
	help("gostore_capacity_free_bytes", "gauge", "Free capacity across disks.")
	line(fmt.Sprintf("gostore_capacity_free_bytes %d", g.FreeBytes))

	if len(g.Buckets) > 0 {
		bs := append([]BucketUsage(nil), g.Buckets...)
		sort.Slice(bs, func(i, j int) bool { return bs[i].Bucket < bs[j].Bucket })
		help("gostore_bucket_objects", "gauge", "Objects per bucket (from the last scan).")
		for _, u := range bs {
			line(fmt.Sprintf("gostore_bucket_objects{bucket=%q} %d", u.Bucket, u.Objects))
		}
		help("gostore_bucket_bytes", "gauge", "Logical bytes per bucket (from the last scan).")
		for _, u := range bs {
			line(fmt.Sprintf("gostore_bucket_bytes{bucket=%q} %d", u.Bucket, u.Bytes))
		}
	}

	_, _ = io.WriteString(w, b.String())
}
