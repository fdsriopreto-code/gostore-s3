package api_test

import (
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"testing"
)

func ssecHeaders(key []byte) map[string]string {
	sum := md5.Sum(key)
	return map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       base64.StdEncoding.EncodeToString(key),
		"x-amz-server-side-encryption-customer-key-MD5":   base64.StdEncoding.EncodeToString(sum[:]),
	}
}

func TestSSECPutGetHead(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	if resp := do(t, srv, http.MethodPut, "/ssecb", []byte{}, nil); resp.StatusCode != 200 {
		t.Fatalf("CreateBucket: %d", resp.StatusCode)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = byte(200 - i)
	}
	payload := []byte("top secret customer-encrypted payload")

	// PUT with SSE-C.
	if resp := do(t, srv, http.MethodPut, "/ssecb/secret.bin", payload, ssecHeaders(key)); resp.StatusCode != 200 {
		t.Fatalf("PutObject SSE-C: %d %s", resp.StatusCode, readBody(t, resp))
	}

	// GET with the correct key -> content + SSE-C headers.
	{
		resp := do(t, srv, http.MethodGet, "/ssecb/secret.bin", nil, ssecHeaders(key))
		body := readBody(t, resp)
		if resp.StatusCode != 200 || body != string(payload) {
			t.Fatalf("GET with key: %d %q", resp.StatusCode, body)
		}
		if resp.Header.Get("x-amz-server-side-encryption-customer-algorithm") != "AES256" {
			t.Fatalf("missing SSE-C response header: %v", resp.Header)
		}
	}

	// GET without the key -> 400 (InvalidRequest).
	{
		resp := do(t, srv, http.MethodGet, "/ssecb/secret.bin", nil, nil)
		readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET without key: want 400, got %d", resp.StatusCode)
		}
	}

	// GET with the WRONG key -> 403 (AccessDenied).
	{
		resp := do(t, srv, http.MethodGet, "/ssecb/secret.bin", nil, ssecHeaders(wrong))
		readBody(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET wrong key: want 403, got %d", resp.StatusCode)
		}
	}

	// HEAD without the key -> 400; with the key -> 200.
	{
		if resp := do(t, srv, http.MethodHead, "/ssecb/secret.bin", nil, nil); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("HEAD without key: want 400, got %d", resp.StatusCode)
		}
		resp := do(t, srv, http.MethodHead, "/ssecb/secret.bin", nil, ssecHeaders(key))
		if resp.StatusCode != 200 {
			t.Fatalf("HEAD with key: %d", resp.StatusCode)
		}
		if resp.Header.Get("x-amz-server-side-encryption-customer-key-MD5") == "" {
			t.Fatalf("HEAD missing key-MD5 header")
		}
		resp.Body.Close()
	}
}
