// Package remotes3 is a tiny streaming S3 client (SigV4, path-style) used for
// lifecycle tiering to a remote cold backend (B2 / R2 / Wasabi / another
// gostore). GET and PUT stream; nothing is buffered whole.
package remotes3

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client targets one remote bucket.
type Client struct {
	Endpoint string // https://s3.us-west-004.backblazeb2.com
	Region   string
	Bucket   string
	Access   string
	Secret   string
	Prefix   string // optional key prefix in the remote bucket
	HC       *http.Client
}

func (c *Client) http() *http.Client {
	if c.HC != nil {
		return c.HC
	}
	return http.DefaultClient
}

func (c *Client) key(k string) string { return c.Prefix + k }

// Put streams body (of the given length) to the remote object.
func (c *Client) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	req, err := c.newReq(ctx, http.MethodPut, key, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// Streamed body -> unsigned payload.
	c.sign(req, "UNSIGNED-PAYLOAD")
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("remote PUT %s: %s: %s", key, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Get opens a stream over the remote object.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	req, err := c.newReq(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, 0, err
	}
	c.sign(req, emptyHash)
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, 0, fmt.Errorf("remote GET %s: %s: %s", key, resp.Status, strings.TrimSpace(string(b)))
	}
	return resp.Body, resp.ContentLength, nil
}

// Head reports whether the remote object exists and its size/etag.
func (c *Client) Head(ctx context.Context, key string) (exists bool, size int64, etag string, err error) {
	req, err := c.newReq(ctx, http.MethodHead, key, nil)
	if err != nil {
		return false, 0, "", err
	}
	c.sign(req, emptyHash)
	resp, err := c.http().Do(req)
	if err != nil {
		return false, 0, "", err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return false, 0, "", nil
	}
	if resp.StatusCode/100 != 2 {
		return false, 0, "", fmt.Errorf("remote HEAD %s: %s", key, resp.Status)
	}
	return true, resp.ContentLength, strings.Trim(resp.Header.Get("ETag"), `"`), nil
}

// ListEntry is one object in the remote bucket. Key includes the client's
// Prefix (strip it to get back the logical key passed to Put/Get).
type ListEntry struct {
	Key  string
	Size int64
	ETag string
}

// List returns one page (up to 1000) of remote objects under the client's
// Prefix, continuing after token (ListObjectsV2). The returned next token is
// "" when the listing is complete.
func (c *Client) List(ctx context.Context, token string) (entries []ListEntry, next string, err error) {
	u := strings.TrimRight(c.Endpoint, "/") + "/" + c.Bucket
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	vals := url.Values{}
	vals.Set("list-type", "2")
	vals.Set("max-keys", "1000")
	if c.Prefix != "" {
		vals.Set("prefix", c.Prefix)
	}
	if token != "" {
		vals.Set("continuation-token", token)
	}
	req.URL.RawQuery = vals.Encode()
	c.sign(req, emptyHash)
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, "", fmt.Errorf("remote LIST: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		Contents []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
			ETag string `xml:"ETag"`
		} `xml:"Contents"`
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, "", err
	}
	for _, e := range out.Contents {
		entries = append(entries, ListEntry{Key: e.Key, Size: e.Size, ETag: strings.Trim(e.ETag, `"`)})
	}
	if out.IsTruncated {
		next = out.NextContinuationToken
	}
	return entries, next, nil
}

// Delete removes the remote object (a 404 is not an error).
func (c *Client) Delete(ctx context.Context, key string) error {
	req, err := c.newReq(ctx, http.MethodDelete, key, nil)
	if err != nil {
		return err
	}
	c.sign(req, emptyHash)
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 && resp.StatusCode != 404 {
		return fmt.Errorf("remote DELETE %s: %s", key, resp.Status)
	}
	return nil
}

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (c *Client) newReq(ctx context.Context, method, key string, body io.Reader) (*http.Request, error) {
	u := strings.TrimRight(c.Endpoint, "/") + "/" + c.Bucket + "/" + c.key(key)
	// Wrap so net/http never closes a body the caller still owns (e.g. a
	// GetObjectReader whose Close releases a backend lock).
	if body != nil {
		body = io.NopCloser(body)
	}
	return http.NewRequestWithContext(ctx, method, u, body)
}

func (c *Client) sign(req *http.Request, payloadHash string) {
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	host := req.URL.Host
	// Canonical headers: host, x-amz-content-sha256, x-amz-date (+ content-type
	// if present on a PUT).
	hdrs := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		hdrs["content-type"] = ct
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + strings.TrimSpace(hdrs[n]) + "\n")
	}
	signed := strings.Join(names, ";")

	canonReq := req.Method + "\n" + encPath(req.URL.Path) + "\n" +
		canonQuery(req.URL.Query()) + "\n" + ch.String() + "\n" + signed + "\n" + payloadHash
	scope := dateStamp + "/" + region + "/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonReq))
	k := hmac256([]byte("AWS4"+c.Secret), dateStamp)
	k = hmac256(k, region)
	k = hmac256(k, "s3")
	k = hmac256(k, "aws4_request")
	sig := hex.EncodeToString(hmac256(k, sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.Access+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

func hmac256(k []byte, d string) []byte {
	h := hmac.New(sha256.New, k)
	h.Write([]byte(d))
	return h.Sum(nil)
}
func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func encPath(p string) string {
	var b strings.Builder
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if i > 0 {
			b.WriteByte('/')
		}
		b.WriteString(strings.ReplaceAll(url.QueryEscape(s), "+", "%20"))
	}
	return b.String()
}

func canonQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}
