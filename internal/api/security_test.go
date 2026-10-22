package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lojadopocket/gostore/internal/api"
	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/config"
	"github.com/lojadopocket/gostore/internal/event"
	"github.com/lojadopocket/gostore/internal/iam"
	fsbackend "github.com/lojadopocket/gostore/internal/object/fs"
)

// secServer wires IAM and bucket-config through the same backend volume the
// objects live on, so a path-traversal attempt against .gostore.sys/iam is
// actually meaningful (the IAM store is a real file under that root).
func secServer(t *testing.T) (*httptest.Server, *iam.Manager) {
	t.Helper()
	root := t.TempDir()
	backend, err := fsbackend.New(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Region = region
	cfg.Volumes = []string{root}
	im, err := iam.New(testAK, testSK, backend)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := bucketcfg.Open(backend)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(api.NewServer(cfg, backend, im, bc, event.New(bc), nil, nil)), im
}

// sendAs issues a signed request as the given credential and returns the
// status code and body.
func sendAs(t *testing.T, srv *httptest.Server, method, path string, body []byte, hdr map[string]string, ak, sk string) (int, string) {
	t.Helper()
	if body == nil {
		body = []byte{}
	}
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	signV4As(t, req, body, ak, sk)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, readBody(t, resp)
}

// between returns the text between the first occurrence of a and the next b.
func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	j := strings.Index(s, b)
	if j < 0 {
		return ""
	}
	return s[:j]
}

// setupLimitedUser creates "secret" + "mine" buckets (with a secret object)
// and a user allowed only PutObject/GetObject on mine/*.
func setupLimitedUser(t *testing.T, srv *httptest.Server, im *iam.Manager) {
	t.Helper()
	sendAs(t, srv, http.MethodPut, "/secret", nil, nil, testAK, testSK)
	sendAs(t, srv, http.MethodPut, "/mine", nil, nil, testAK, testSK)
	if c, b := sendAs(t, srv, http.MethodPut, "/secret/payroll.txt", []byte("TOP SECRET"), nil, testAK, testSK); c != 200 {
		t.Fatalf("seed secret object: %d %s", c, b)
	}
	if err := im.SetPolicy("mineonly", []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":["arn:aws:s3:::mine/*"]}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := im.AddUser("alice", "alicepass123", []string{"mineonly"}); err != nil {
		t.Fatal(err)
	}
}

// S1: a key with write access to one bucket must not be able to copy an object
// it cannot read out of another bucket.
func TestCopyObjectAuthorizesSource(t *testing.T) {
	srv, im := secServer(t)
	defer srv.Close()
	setupLimitedUser(t, srv, im)

	c, _ := sendAs(t, srv, http.MethodPut, "/mine/stolen.txt", nil,
		map[string]string{"x-amz-copy-source": "/secret/payroll.txt"}, "alice", "alicepass123")
	if c != http.StatusForbidden {
		t.Fatalf("cross-bucket CopyObject: want 403, got %d", c)
	}
}

// S1 rollout: GOSTORE_COPY_SOURCE_AUTHZ=warn must allow the copy (so an
// existing deployment is not broken on upgrade) while enforce blocks it.
func TestCopyObjectAuthzWarnMode(t *testing.T) {
	t.Setenv("GOSTORE_COPY_SOURCE_AUTHZ", "warn")
	srv, im := secServer(t)
	defer srv.Close()
	setupLimitedUser(t, srv, im)

	c, b := sendAs(t, srv, http.MethodPut, "/mine/copied.txt", nil,
		map[string]string{"x-amz-copy-source": "/secret/payroll.txt"}, "alice", "alicepass123")
	if c != http.StatusOK {
		t.Fatalf("warn mode should allow the copy: got %d %s", c, b)
	}
	// Traversal is still blocked even in warn mode (it is a validation error,
	// not an authorization decision).
	if c, _ := sendAs(t, srv, http.MethodPut, "/mine/x.json", nil,
		map[string]string{"x-amz-copy-source": "/mine/../.gostore.sys/iam/store.json"}, "alice", "alicepass123"); c == http.StatusOK {
		t.Fatalf("warn mode must not bypass traversal validation")
	}
}

// S2: x-amz-copy-source must not be able to traverse into the reserved
// .gostore.sys namespace (which holds the IAM store with every secret key).
func TestCopyObjectRejectsTraversalSource(t *testing.T) {
	srv, im := secServer(t)
	defer srv.Close()
	setupLimitedUser(t, srv, im)

	for _, src := range []string{
		"/mine/../.gostore.sys/iam/store.json",
		"/.gostore.sys/iam/store.json",
		"/mine/../../etc/passwd",
	} {
		c, b := sendAs(t, srv, http.MethodPut, "/mine/leak.json", nil,
			map[string]string{"x-amz-copy-source": src}, "alice", "alicepass123")
		if c == http.StatusOK {
			t.Fatalf("traversal copy-source %q succeeded (leak): %s", src, b)
		}
	}
	// And the leak object must not exist / not contain secrets.
	c, b := sendAs(t, srv, http.MethodGet, "/mine/leak.json", nil, nil, "alice", "alicepass123")
	if c == http.StatusOK && strings.Contains(b, "secretKey") {
		t.Fatalf("IAM store was exfiltrated: %s", b)
	}
}

// S3: a batch delete must not be able to remove files outside the bucket via
// a ../ key.
func TestDeleteObjectsRejectsTraversal(t *testing.T) {
	srv, im := secServer(t)
	defer srv.Close()
	setupLimitedUser(t, srv, im)

	body := []byte(`<Delete><Object><Key>../../.gostore.sys/iam/store.json</Key></Object><Object><Key>../secret/payroll.txt</Key></Object></Delete>`)
	c, b := sendAs(t, srv, http.MethodPost, "/mine?delete", body, nil, testAK, testSK)
	if c != http.StatusOK {
		t.Fatalf("DeleteObjects: %d %s", c, b)
	}
	if !strings.Contains(b, "<Error>") {
		t.Fatalf("traversal keys were not rejected: %s", b)
	}
	// IAM must still be intact: alice still authenticates and can do her
	// allowed action (GET on mine/*).
	sendAs(t, srv, http.MethodPut, "/mine/ok.txt", []byte("hi"), nil, testAK, testSK)
	if sc, b := sendAs(t, srv, http.MethodGet, "/mine/ok.txt", nil, nil, "alice", "alicepass123"); sc != http.StatusOK {
		t.Fatalf("IAM store appears damaged: alice can no longer use her access (%d %s)", sc, b)
	}
	// The real secret object (inside the bucket, reachable via ..) must survive.
	if sc, _ := sendAs(t, srv, http.MethodHead, "/secret/payroll.txt", nil, nil, testAK, testSK); sc != http.StatusOK {
		t.Fatalf("secret/payroll.txt was deleted via traversal: %d", sc)
	}
}

// S4: a service account restricted by an inline policy must not be able to
// escalate to its parent (root) by calling AssumeRole.
func TestAssumeRoleNoEscalation(t *testing.T) {
	srv, im := secServer(t)
	defer srv.Close()
	setupLimitedUser(t, srv, im)

	// Service account of root, inline-restricted to GetObject on mine/*.
	if err := im.AddServiceAccount(testAK, "svcro", "svcrosecret1",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::mine/*"]}]}`); err != nil {
		t.Fatal(err)
	}

	c, b := sendAs(t, srv, http.MethodPost, "/?Action=AssumeRole", nil, nil, "svcro", "svcrosecret1")
	if c != http.StatusOK {
		t.Fatalf("AssumeRole: %d %s", c, b)
	}
	ak := between(b, "<AccessKeyId>", "</AccessKeyId>")
	sk := between(b, "<SecretAccessKey>", "</SecretAccessKey>")
	if ak == "" || sk == "" {
		t.Fatalf("no STS creds in response: %s", b)
	}

	// The temp creds must NOT be able to read the secret bucket...
	if sc, _ := sendAs(t, srv, http.MethodGet, "/secret/payroll.txt", nil, nil, ak, sk); sc != http.StatusForbidden {
		t.Fatalf("STS escalated to read secret bucket: want 403, got %d", sc)
	}
	// ...nor reach the admin API.
	if sc, _ := sendAs(t, srv, http.MethodGet, "/gostore/admin/v1/info", nil, nil, ak, sk); sc == http.StatusOK {
		t.Fatalf("STS escalated to admin API (got 200)")
	}
	// ...but must still do what the service account itself could (GET mine/*).
	sendAs(t, srv, http.MethodPut, "/mine/ok.txt", []byte("hi"), nil, testAK, testSK)
	if sc, _ := sendAs(t, srv, http.MethodGet, "/mine/ok.txt", nil, nil, ak, sk); sc != http.StatusOK {
		t.Fatalf("STS lost the access it legitimately inherited: GET mine/ok.txt => %d", sc)
	}
}

// S5: a key with only s3:CreateBucket must not be able to configure lifecycle
// (or other sub-resources) on a bucket it does not own.
func TestSubresourceActionMapping(t *testing.T) {
	srv, im := secServer(t)
	defer srv.Close()
	setupLimitedUser(t, srv, im)

	if err := im.SetPolicy("createonly", []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:CreateBucket"],"Resource":["arn:aws:s3:::*"]}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := im.AddUser("carol", "carolpass123", []string{"createonly"}); err != nil {
		t.Fatal(err)
	}

	lc := []byte(`<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`)
	if c, b := sendAs(t, srv, http.MethodPut, "/secret?lifecycle", lc, nil, "carol", "carolpass123"); c != http.StatusForbidden {
		t.Fatalf("CreateBucket-only key set lifecycle on another bucket: want 403, got %d %s", c, b)
	}
	// Root (s3:*) must still be able to set it.
	if c, b := sendAs(t, srv, http.MethodPut, "/secret?lifecycle", lc, nil, testAK, testSK); c != http.StatusOK {
		t.Fatalf("root PutBucketLifecycle: want 200, got %d %s", c, b)
	}
}

// A browser hitting the root (GET /, Accept: text/html, no credentials) is
// redirected to the web console; an S3 client (no html Accept) is not.
func TestBrowserRootRedirectsToConsole(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	cl := srv.Client()
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/gostore/console/" {
		t.Fatalf("browser root: want 302 -> /gostore/console/, got %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	// S3 client (no text/html Accept) must NOT be redirected.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	resp2, err := cl.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode == http.StatusFound {
		t.Fatalf("S3 client root was redirected (should not be): %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}
