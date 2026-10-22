// Command gostore is an S3-compatible object storage server.
//
// Usage:
//
//	gostore server [flags] VOLUME [VOLUME...]
//	gostore version
//
// A single VOLUME runs in single-disk mode; multiple VOLUMEs (even count,
// >=4) run in erasure mode (M4+). Ellipsis specs like ./data/disk{1...4}
// are expanded.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/lojadopocket/gostore/internal/api"
	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/cluster"
	"github.com/lojadopocket/gostore/internal/config"
	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/erasure"
	"github.com/lojadopocket/gostore/internal/event"
	"github.com/lojadopocket/gostore/internal/gostorecli"
	"github.com/lojadopocket/gostore/internal/iam"
	"github.com/lojadopocket/gostore/internal/kms"
	"github.com/lojadopocket/gostore/internal/logger"
	"github.com/lojadopocket/gostore/internal/metrics"
	"github.com/lojadopocket/gostore/internal/object"
	fsbackend "github.com/lojadopocket/gostore/internal/object/fs"
	"github.com/lojadopocket/gostore/internal/remotes3"
	"github.com/lojadopocket/gostore/internal/scanner"
	"github.com/lojadopocket/gostore/internal/storage"
)

// version is overridden at build time (-X main.version); this default is
// used for local `go run` / `go build`.
var version = "0.9.0"

func main() {
	metrics.SetVersion(version)
	applyCPULimit()
	applyMemLimit()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "server":
		if err := runServer(os.Args[2:]); err != nil {
			logger.Fatal("server stopped with error", "err", err)
		}
	case "version", "-version", "--version", "-v":
		fmt.Printf("gostore %s %s/%s (%s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	case "help", "-h", "--help":
		usage()
	case "alias", "ls", "cp", "rm", "mb", "rb", "cat", "stat", "admin", "bench":
		os.Exit(gostorecli.Run(os.Args[1:]))
	default:
		fmt.Fprintf(os.Stderr, "gostore: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gostore - S3-compatible object storage

Usage:
  gostore server [flags] VOLUME [VOLUME...]
  gostore version

Client (talks to a gostore/S3 endpoint):
  gostore alias set NAME URL ACCESS SECRET
  gostore ls|cp|rm|mb|rb|cat|stat ...
  gostore admin info|heal|scrub|readonly|snapshot NAME ...
  (run any of these with no args for details)

Flags (server):
  --address ADDR           S3 API listen address (default ":9000")
  --console-address ADDR   Web console listen address (default ":9001")
  --log-level LEVEL         debug|info|warn|error (default "info")
  --log-json               emit logs as JSON

Environment:
  GOSTORE_ROOT_USER, GOSTORE_ROOT_PASSWORD, GOSTORE_REGION,
  GOSTORE_ADDRESS, GOSTORE_CONSOLE_ADDRESS, GOSTORE_DOMAIN,
  GOSTORE_LOG_LEVEL, GOSTORE_LOG_JSON

Examples:
  gostore server ./data
  gostore server --address :9000 ./data/disk{1...4}
`)
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var (
		address        = fs.String("address", "", "S3 API listen address")
		consoleAddress = fs.String("console-address", "", "web console listen address")
		logLevel       = fs.String("log-level", "", "debug|info|warn|error")
		logJSON        = fs.Bool("log-json", false, "emit logs as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Default()
	cfg.ApplyEnv()
	if *address != "" {
		cfg.Address = *address
	}
	if *consoleAddress != "" {
		cfg.ConsoleAddress = *consoleAddress
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if *logJSON {
		cfg.LogJSON = true
	}

	dargs := fs.Args()
	clusterMode := len(dargs) > 0 && cluster.IsClusterArg(dargs[0])

	var clusterRPC http.Handler
	var obj object.Layer

	if clusterMode {
		self := os.Getenv("GOSTORE_CLUSTER_SELF")
		secret := os.Getenv("GOSTORE_CLUSTER_SECRET")
		spec, err := cluster.Parse(dargs, self, secret)
		if err != nil {
			return err
		}
		for _, d := range spec.LocalDisks {
			if ld, ok := d.(interface{ String() string }); ok {
				cfg.Volumes = append(cfg.Volumes, ld.String())
			}
		}
		logger.Setup(cfg.LogLevel, cfg.LogJSON)
		logger.Info("starting gostore (cluster)",
			"version", version, "api", cfg.Address, "self", self,
			"totalDisks", len(spec.Disks), "localDisks", len(spec.LocalDisks), "peers", spec.PeerBases)

		km, err := kms.New(cfg.Volumes)
		if err != nil {
			return fmt.Errorf("init KMS: %w", err)
		}
		applyInlineMax()
		applyListCacheTTL()
		applyWalkKeysMax()
		applyDirSync()
		applyDedup()
		applyTiers()
		set, err := erasure.NewSet(spec.Disks)
		if err != nil {
			return fmt.Errorf("cluster erasure set: %w", err)
		}
		pool, err := erasure.NewPool(set)
		if err != nil {
			return err
		}
		pool.SetKMS(km)
		rpc := cluster.NewRPCServer(spec.LocalDisks, secret)
		coord := cluster.NewLockCoordinator(rpc, spec.PeerBases, secret)
		pool.SetLocker(coord.NewNSLock)
		clusterRPC = rpc.Handler()
		obj = pool
		cluster.StartPeerMonitor(context.Background(), spec.PeerBases, secret)
		n := len(spec.Disks)
		logger.Info("cluster erasure pool ready", "disks", n, "dataBlocks", n-n/2, "parityBlocks", n/2)
		return serve(cfg, obj, clusterRPC)
	}

	groups, err := expandVolumeGroups(dargs)
	if err != nil {
		return err
	}
	cfg.VolumeGroups = groups
	for _, g := range groups {
		cfg.Volumes = append(cfg.Volumes, g...)
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	logger.Setup(cfg.LogLevel, cfg.LogJSON)
	logger.Info("starting gostore",
		"version", version,
		"api", cfg.Address,
		"console", cfg.ConsoleAddress,
		"volumes", cfg.Volumes,
		"mode", modeString(cfg),
	)

	km, err := kms.New(cfg.Volumes)
	if err != nil {
		return fmt.Errorf("init KMS: %w", err)
	}
	applyInlineMax()
	applyListCacheTTL()
	applyWalkKeysMax()
	applyDirSync()
	applyDedup()
	applyTiers()

	if cfg.SingleDisk() {
		backend, err := fsbackend.New(cfg.VolumeGroups[0][0])
		if err != nil {
			return fmt.Errorf("open volume %s: %w", cfg.VolumeGroups[0][0], err)
		}
		backend.SetKMS(km)
		obj = backend
	} else {
		sets := make([]*erasure.Set, len(cfg.VolumeGroups))
		for si, group := range cfg.VolumeGroups {
			disks := make([]erasure.Disk, len(group))
			for di, v := range group {
				d, err := storage.OpenLocalDisk(v, si, di)
				if err != nil {
					return fmt.Errorf("open disk %s: %w", v, err)
				}
				disks[di] = d
			}
			set, err := erasure.NewSet(disks)
			if err != nil {
				return fmt.Errorf("init erasure set %d: %w", si+1, err)
			}
			sets[si] = set
		}
		pool, err := erasure.NewPool(sets...)
		if err != nil {
			return fmt.Errorf("init erasure pool: %w", err)
		}
		pool.SetKMS(km)
		obj = pool
		n := len(cfg.VolumeGroups[0])
		logger.Info("erasure backend ready",
			"sets", len(sets), "disksPerSet", n,
			"dataBlocks", n-n/2, "parityBlocks", n/2)
	}

	return serve(cfg, obj, nil)
}

// serve wires IAM, bucket config, the scanner and the HTTP servers around an
// already-built object backend, and blocks until shutdown.
func serve(cfg config.Config, obj object.Layer, clusterRPC http.Handler) error {
	cb, ok := obj.(configstore.Backend)
	if !ok {
		return fmt.Errorf("object backend %T does not provide a config store", obj)
	}

	refreshCtx, stopRefresh := context.WithCancel(context.Background())
	defer stopRefresh()
	startMemScavenger(refreshCtx)

	iamMgr, err := iam.New(cfg.RootUser, cfg.RootPassword, cb)
	if err != nil {
		return fmt.Errorf("init IAM: %w", err)
	}
	iamMgr.StartRefresh(refreshCtx, 30*time.Second)
	logger.Info("IAM ready",
		"rootAccessKey", cfg.RootUser,
		"users", len(iamMgr.ListUsers()),
		"serviceAccounts", len(iamMgr.ListServiceAccounts("")))

	// If the volume was empty at boot AND this keeps happening on every
	// restart, the data directory is not persistent — buckets, objects and
	// access keys will vanish on redeploy. Make that loud.
	if fc, ok := obj.(interface {
		FreshlyFormatted() bool
		DataDir() string
	}); ok && fc.FreshlyFormatted() {
		logger.Warn("data volume was EMPTY at startup — first run, OR the volume is not persistent. "+
			"If access keys / buckets disappear after a restart or redeploy, mount a persistent "+
			"volume (named volume or persistent disk) to this path and keep it across deploys.",
			"dataDir", fc.DataDir())
	}
	if os.Getenv("GOSTORE_ALLOW_ANONYMOUS") == "1" {
		logger.Warn("GOSTORE_ALLOW_ANONYMOUS=1: unsigned requests are accepted and skip authorization")
	}

	bcfg, err := bucketcfg.Open(cb)
	if err != nil {
		return fmt.Errorf("init bucket config: %w", err)
	}
	bcfg.StartRefresh(refreshCtx, 30*time.Second)
	bus := event.New(bcfg)

	// MRF: background re-heal of objects that committed on a quorum but not
	// every disk (erasure backend only).
	if pool, ok := obj.(*erasure.Pool); ok {
		if v := os.Getenv("GOSTORE_MRF_INTERVAL"); v != "" {
			if d, perr := time.ParseDuration(v); perr == nil {
				erasure.SetMRFInterval(d)
			}
		}
		pool.EnableMRF(cb)
		pool.StartMRF(refreshCtx)
		pool.LoadLayout(cb)
		pool.AutoHeal(refreshCtx)
	}

	scanInterval := time.Hour
	if v := os.Getenv("GOSTORE_SCAN_INTERVAL"); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
			scanInterval = d
		}
	}
	scanCtx, stopScan := context.WithCancel(context.Background())
	defer stopScan()
	scan := scanner.New(obj, bcfg, scanInterval)
	scrubInterval := 7 * 24 * time.Hour // weekly guaranteed full verify+repair
	if v := os.Getenv("GOSTORE_SCRUB_INTERVAL"); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil {
			scrubInterval = d // 0 disables
		}
	}
	scan.SetScrubInterval(scrubInterval)
	mpuTTL := 7 * 24 * time.Hour // abort abandoned multipart uploads after a week
	if v := os.Getenv("GOSTORE_MULTIPART_TTL"); v != "" {
		if d, perr := time.ParseDuration(v); perr == nil {
			mpuTTL = d // 0 disables
		}
	}
	scan.SetMultipartTTL(mpuTTL)
	go scan.Run(scanCtx)
	logger.Info("background scanner started", "interval", scanInterval, "deepScrubInterval", scrubInterval)

	// One handler serves the S3 API, the admin API, the health endpoints AND
	// the web console. The console SPA signs every request for its own origin,
	// so it only works on a port that also serves the API. We therefore mount
	// the SAME handler on both the API port and the console port: whichever one
	// is exposed (some PaaS setups publish :9001 as "the console"), the real
	// console and the API both work there. No dead placeholder page.
	handler := api.NewServer(cfg, obj, iamMgr, bcfg, bus, clusterRPC, scan)
	apiSrv := &http.Server{
		Addr:              cfg.Address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	consoleSrv := &http.Server{
		Addr:              cfg.ConsoleAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Optional built-in HTTPS: GOSTORE_TLS_DOMAIN=host[,host] makes gostore
	// obtain and renew a Let's Encrypt cert itself — no reverse proxy needed.
	acmeCache := ""
	if len(cfg.Volumes) > 0 {
		acmeCache = filepath.Join(cfg.Volumes[0], ".gostore.sys", "acme")
	}
	challengeSrv, tlsOn := setupAutoTLS(apiSrv, acmeCache)

	errCh := make(chan error, 3)
	go func() {
		if tlsOn {
			logger.Info("S3 API listening (HTTPS)", "addr", cfg.Address)
			if err := apiSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("api server (tls): %w", err)
			}
			return
		}
		logger.Info("S3 API listening", "addr", cfg.Address)
		if err := apiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api server: %w", err)
		}
	}()
	if challengeSrv != nil {
		go func() {
			if err := challengeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("acme http listener: %w", err)
			}
		}()
	}
	go func() {
		logger.Info("console listening", "addr", cfg.ConsoleAddress)
		if err := consoleSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("console server: %w", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(shutdownCtx)
	_ = consoleSrv.Shutdown(shutdownCtx)
	if challengeSrv != nil {
		_ = challengeSrv.Shutdown(shutdownCtx)
	}
	if err := obj.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("backend shutdown: %w", err)
	}
	logger.Info("stopped cleanly")
	return nil
}

// setupAutoTLS enables built-in Let's Encrypt when GOSTORE_TLS_DOMAIN is set.
// It points apiSrv at an autocert TLS config and returns a small HTTP server
// (default :80, override GOSTORE_TLS_HTTP_ADDR) that answers ACME HTTP-01
// challenges and redirects everything else to https. Certs are cached under
// <volume>/.gostore.sys/acme so they survive restarts.
func setupAutoTLS(apiSrv *http.Server, cacheDir string) (challenge *http.Server, enabled bool) {
	var domains []string
	for _, d := range strings.Split(os.Getenv("GOSTORE_TLS_DOMAIN"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		return nil, false
	}
	if cacheDir == "" {
		cacheDir = "./.gostore-acme"
	}
	_ = os.MkdirAll(cacheDir, 0o700)
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Email:      os.Getenv("GOSTORE_TLS_EMAIL"),
	}
	tlsCfg := m.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12
	apiSrv.TLSConfig = tlsCfg

	httpAddr := os.Getenv("GOSTORE_TLS_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = ":80"
	}
	challenge = &http.Server{
		Addr:              httpAddr,
		Handler:           m.HTTPHandler(nil),
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("auto-HTTPS enabled (Let's Encrypt)",
		"domains", domains, "challengeAddr", httpAddr, "certCache", cacheDir)
	return challenge, true
}

// applyInlineMax honours GOSTORE_INLINE_MAX (bytes; 0 disables inlining) for
// the erasure backend's small-object-in-xl.meta threshold.
func applyInlineMax() {
	v := os.Getenv("GOSTORE_INLINE_MAX")
	if v == "" {
		return
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		logger.Warn("ignoring invalid GOSTORE_INLINE_MAX", "value", v)
		return
	}
	erasure.SetInlineMax(n)
	logger.Info("inline object threshold set", "bytes", n)
}

// applyListCacheTTL honours GOSTORE_LIST_CACHE_TTL (a duration; 0 disables)
// for the erasure backend's per-bucket namespace-listing cache.
func applyListCacheTTL() {
	v := os.Getenv("GOSTORE_LIST_CACHE_TTL")
	if v == "" {
		// Clustered: another node's write won't invalidate this node's list
		// cache, so keep the default short (bounded cross-node LIST
		// staleness) — still long enough to serve a paginating client.
		if os.Getenv("GOSTORE_CLUSTER_SELF") != "" {
			erasure.SetListCacheTTL(2 * time.Second)
			logger.Info("list cache TTL set", "ttl", "2s", "reason", "clustered default")
		}
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		logger.Warn("ignoring invalid GOSTORE_LIST_CACHE_TTL", "value", v)
		return
	}
	erasure.SetListCacheTTL(d)
	logger.Info("list cache TTL set", "ttl", d)
}

// applyWalkKeysMax honours GOSTORE_LIST_MAX_KEYS — the ceiling on how many
// object keys one namespace walk materialises (OOM guard for huge buckets).
func applyWalkKeysMax() {
	v := os.Getenv("GOSTORE_LIST_MAX_KEYS")
	if v == "" {
		return
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		erasure.SetWalkKeysMax(n)
		logger.Info("namespace walk key ceiling set", "max", n)
	}
}

// applyDirSync honours GOSTORE_FSYNC — "0"/"false" disables the durable
// directory fsync after each object/metadata rename (default on).
func applyDirSync() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GOSTORE_FSYNC"))) {
	case "0", "false", "no", "off":
		storage.SetDirSync(false)
		logger.Warn("directory fsync disabled (GOSTORE_FSYNC=0) — the last write before a power loss may be lost")
	}
}

// applyTiers registers remote cold-storage tiers from GOSTORE_TIER_<NAME>
// env vars: "endpoint|region|bucket|accessKey|secretKey[|prefix]".
func applyTiers() {
	for _, kv := range os.Environ() {
		name, val, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "GOSTORE_TIER_") || val == "" {
			continue
		}
		tier := strings.ToLower(strings.TrimPrefix(name, "GOSTORE_TIER_"))
		f := strings.Split(val, "|")
		if len(f) < 5 {
			logger.Warn("ignoring malformed tier (want endpoint|region|bucket|access|secret[|prefix])", "tier", tier)
			continue
		}
		prefix := ""
		if len(f) >= 6 {
			prefix = f[5]
		}
		erasure.RegisterTier(tier, &remotes3.Client{
			Endpoint: f[0], Region: f[1], Bucket: f[2], Access: f[3], Secret: f[4], Prefix: prefix,
		})
		logger.Info("cold tier registered", "tier", tier, "endpoint", f[0], "bucket", f[2])
	}
}

// applyDedup honours GOSTORE_DEDUP — content-addressed shard sharing for
// byte-identical objects (erasure backend, non-SSE). Off by default.
func applyDedup() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GOSTORE_DEDUP"))) {
	case "1", "true", "yes", "on":
		erasure.SetDedup(true)
		logger.Info("content-addressed dedup enabled (GOSTORE_DEDUP)")
	}
}

func modeString(c config.Config) string {
	if c.SingleDisk() {
		return "single-disk"
	}
	if len(c.VolumeGroups) == 1 {
		return fmt.Sprintf("erasure (1 set, %d disks)", len(c.VolumeGroups[0]))
	}
	return fmt.Sprintf("erasure pool (%d sets)", len(c.VolumeGroups))
}

// expandVolumeGroups turns each CLI argument into a group of disk paths,
// expanding a MinIO-style ellipsis spec ("./data/disk{1...4}"). Each group
// becomes one erasure set; all groups form one pool.
func expandVolumeGroups(args []string) ([][]string, error) {
	if len(args) == 0 {
		return nil, errors.New("no volumes given")
	}
	var groups [][]string
	for _, a := range args {
		openIdx := strings.IndexByte(a, '{')
		closeIdx := strings.IndexByte(a, '}')
		if openIdx < 0 || closeIdx < 0 || closeIdx < openIdx {
			groups = append(groups, []string{a})
			continue
		}
		inner := a[openIdx+1 : closeIdx]
		lo, hi, ok := parseEllipsis(inner)
		if !ok {
			return nil, fmt.Errorf("invalid ellipsis spec %q (want {N...M})", a)
		}
		prefix, suffix := a[:openIdx], a[closeIdx+1:]
		var g []string
		for i := lo; i <= hi; i++ {
			g = append(g, fmt.Sprintf("%s%d%s", prefix, i, suffix))
		}
		groups = append(groups, g)
	}
	return groups, nil
}

func parseEllipsis(s string) (lo, hi int, ok bool) {
	i := strings.Index(s, "...")
	if i < 0 {
		return 0, 0, false
	}
	var err1, err2 error
	lo, err1 = strconv.Atoi(strings.TrimSpace(s[:i]))
	hi, err2 = strconv.Atoi(strings.TrimSpace(s[i+3:]))
	if err1 != nil || err2 != nil || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}

// consolePlaceholder is the interim web console: a single status page. The
// real UI is milestone M14.
func consolePlaceholder(cfg config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>gostore console</title>
<body style="font:14px/1.5 system-ui;margin:3rem;max-width:44rem;color:#1a1a1a">
<h1 style="margin-bottom:.2rem">gostore</h1>
<p style="color:#666;margin-top:0">S3-compatible object storage &mdash; version %s</p>
<table style="border-collapse:collapse">
<tr><td style="padding:.2rem 1rem .2rem 0;color:#666">S3 API port</td><td><code>%s</code></td></tr>
<tr><td style="padding:.2rem 1rem .2rem 0;color:#666">Console port</td><td><code>%s</code> (this page)</td></tr>
<tr><td style="padding:.2rem 1rem .2rem 0;color:#666">Region</td><td><code>%s</code></td></tr>
<tr><td style="padding:.2rem 1rem .2rem 0;color:#666">Mode</td><td><code>%s</code></td></tr>
</table>
<p style="margin-top:1.5rem">Status page only. Point your reverse proxy / PaaS at the
<strong>S3 API port (%s)</strong> &mdash; that port serves the S3 API, the
web console, and the health endpoints:</p>
<ul>
<li><strong>Web console:</strong> <code>&lt;api-host&gt;/gostore/console/</code></li>
<li><code>GET /gostore/health/live</code> &nbsp;/&nbsp; <code>/gostore/health/ready</code></li>
<li><code>GET /gostore/health/selftest</code> &mdash; full write/read/verify/delete round-trip</li>
</ul>
<p>The S3 API requires AWS Signature V4 &mdash; use the console, <code>mc</code>, the
AWS CLI/SDKs, or any S3 client (path-style).</p>
</body>`, version, cfg.Address, cfg.ConsoleAddress, cfg.Region, modeString(cfg), cfg.Address)
	})
}
