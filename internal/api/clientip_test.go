package api

import (
	"net/http"
	"testing"
)

func req(remoteAddr, xff string) *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIPAntiSpoof(t *testing.T) {
	cases := []struct {
		name, remote, xff, want string
	}{
		// Direct public client sending a spoofed XFF -> header ignored, real peer wins.
		{"public spoof ignored", "203.0.113.9:4444", "1.2.3.4", "203.0.113.9"},
		// Behind a private reverse proxy -> trust XFF, take the client it saw.
		{"trusted proxy", "10.0.0.5:5555", "198.51.100.7", "198.51.100.7"},
		// Chain: client, then two trusted proxies -> first untrusted from the right.
		{"proxy chain", "172.16.0.2:1", "198.51.100.7, 10.1.1.1, 172.16.0.9", "198.51.100.7"},
		// Client tries to prepend a fake hop; edge proxy appends the true one.
		{"prepended fake", "127.0.0.1:1", "9.9.9.9, 198.51.100.7", "198.51.100.7"},
		// No XFF at all -> peer.
		{"no xff", "198.51.100.7:2", "", "198.51.100.7"},
		// Public peer, no XFF -> peer.
		{"public direct", "203.0.113.1:3", "", "203.0.113.1"},
	}
	for _, c := range cases {
		if got := clientIP(req(c.remote, c.xff)); got != c.want {
			t.Errorf("%s: clientIP=%q want %q", c.name, got, c.want)
		}
	}
}
