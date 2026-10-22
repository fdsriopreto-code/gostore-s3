package api

import (
	"encoding/xml"
	"net/http"
	"strconv"
	"time"

	"github.com/lojadopocket/gostore/internal/iam/policy"
	"github.com/lojadopocket/gostore/internal/storage"
)

// isSTSRequest reports whether r is an STS AssumeRole call on the root path.
func isSTSRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	action := r.URL.Query().Get("Action")
	if action == "" {
		_ = r.ParseForm()
		action = r.Form.Get("Action")
	}
	return action == "AssumeRole"
}

type assumeRoleResult struct {
	XMLName     xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
	Credentials struct {
		AccessKeyID     string `xml:"AccessKeyId"`
		SecretAccessKey string `xml:"SecretAccessKey"`
		SessionToken    string `xml:"SessionToken"`
		Expiration      string `xml:"Expiration"`
	} `xml:"AssumeRoleResult>Credentials"`
	RequestMeta struct {
		RequestID string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

// handleAssumeRole issues temporary credentials that carry the caller's
// effective policy, optionally narrowed by an inline session Policy param.
func (s *Server) handleAssumeRole(w http.ResponseWriter, r *http.Request, caller string) {
	if caller == "" {
		writeErrorResponse(w, r, ErrAccessDenied, "/")
		return
	}
	form := r.Form
	get := func(k string) string {
		if v := r.URL.Query().Get(k); v != "" {
			return v
		}
		return form.Get(k)
	}

	dur, _ := strconv.Atoi(get("DurationSeconds"))
	if dur < 900 {
		dur = 3600
	}
	if dur > 12*3600 {
		dur = 12 * 3600
	}

	var inline *policy.Policy
	if doc := get("Policy"); doc != "" {
		p, err := policy.Parse([]byte(doc))
		if err != nil {
			writeErrorResponse(w, r, ErrMalformedXML, "/")
			return
		}
		inline = p
	}

	tmpAK := "GS" + storage.NewID()[:18]
	tmpSK := storage.NewID() + storage.NewID()[:8]
	exp := time.Now().UTC().Add(time.Duration(dur) * time.Second)

	// parentUser: if the caller is itself a temp/svc identity, chain to its
	// parent so the parent's named policies resolve. bound carries the
	// caller's own ceiling (a service account's inline policy, or a bounded
	// STS's ceiling) so the issued credential can never exceed what the caller
	// itself could do — even when the parent is root.
	parent := caller
	var bound *policy.Policy
	if id, ok := s.iam.Identity(caller); ok {
		if id.ParentUser != "" {
			parent = id.ParentUser
		}
		if id.Inline != nil {
			bound = id.Inline
		} else if id.Bound != nil {
			bound = id.Bound
		}
	}
	s.iam.AddSTS(tmpAK, tmpSK, parent, inline, bound, time.Until(exp))

	var res assumeRoleResult
	res.Credentials.AccessKeyID = tmpAK
	res.Credentials.SecretAccessKey = tmpSK
	res.Credentials.SessionToken = tmpAK // token == access key id (self-describing)
	res.Credentials.Expiration = exp.Format(time.RFC3339)
	res.RequestMeta.RequestID = requestIDFrom(r)
	writeXML(w, http.StatusOK, res)
}
