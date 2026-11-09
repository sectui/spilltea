package findings

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sectui/spilltea/internal/message"
)

func request(t *testing.T, raw string, header ...string) *message.Request {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Add(header[i], header[i+1])
	}
	return &message.Request{Method: "GET", URL: u, Header: h}
}

func response(header ...string) *message.Response {
	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Add(header[i], header[i+1])
	}
	return &message.Response{Status: 200, Header: h}
}

func TestCookies(t *testing.T) {
	resp := response(
		"Set-Cookie", "session=abc; Path=/; SameSite=None",
		"Set-Cookie", "good=1; Secure; HttpOnly; SameSite=Lax",
		"Set-Cookie", "gone=; Max-Age=0",
		"Set-Cookie", "old=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
		"Set-Cookie", "pref=dark; Domain=.example.com; Secure",
	)
	hits := Cookies{}.Detect(request(t, "https://app.example.com/login"), resp)
	if len(hits) != 2 {
		t.Fatalf("%+v", hits)
	}
	if h := hits[0]; h.Title != "session: no Secure, no HttpOnly, SameSite=None" || h.Key != "app.example.com:session:no Secure, no HttpOnly, SameSite=None" {
		t.Fatalf("%+v", h)
	}
	if h := hits[1]; h.Title != "pref: no HttpOnly" || !strings.HasPrefix(h.Key, "example.com:pref:") {
		t.Fatalf("%+v", h)
	}
	hits = Cookies{}.Detect(request(t, "http://app.example.com/"), response("Set-Cookie", "session=abc; HttpOnly"))
	if len(hits) != 0 {
		t.Fatalf("Secure is not expected over http: %+v", hits)
	}
}

func TestCORS(t *testing.T) {
	req := request(t, "https://api.example.com/me", "Origin", "https://app.example.com")
	for name, c := range map[string]struct {
		resp  *message.Response
		title string
	}{
		"credentials": {response("Access-Control-Allow-Origin", "https://app.example.com", "Access-Control-Allow-Credentials", "true"), "credentialed CORS"},
		"null":        {response("Access-Control-Allow-Origin", "null", "Access-Control-Allow-Credentials", "TRUE"), "null origin trusted with credentials"},
		"no creds":    {response("Access-Control-Allow-Origin", "https://app.example.com"), ""},
		"wildcard":    {response("Access-Control-Allow-Origin", "*", "Access-Control-Allow-Credentials", "true"), ""},
		"none":        {response(), ""},
	} {
		hits := CORS{}.Detect(req, c.resp)
		switch {
		case c.title == "" && len(hits) != 0:
			t.Errorf("%s: %+v", name, hits)
		case c.title != "" && (len(hits) != 1 || hits[0].Title != c.title || !strings.HasPrefix(hits[0].Key, "api.example.com:") || !strings.Contains(hits[0].Detail, "request Origin: https://app.example.com")):
			t.Errorf("%s: %+v", name, hits)
		}
	}
}
