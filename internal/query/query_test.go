package query

import (
	"testing"
	"time"

	"github.com/sectui/spilltea/internal/project"
)

func TestFields(t *testing.T) {
	p, _ := project.Open(t.TempDir())
	e, _ := p.Add(project.Entry{Method: "POST", URL: "https://api.test/login?x=1", Time: time.Now(),
		Status: 302, Color: "red", Mime: "text/html"}, []byte("POST /login?x=1 HTTP/1.1\r\nHost: api.test\r\n\r\npassword=hunter2"), nil)
	r := New(p, e, project.Meta{Marked: true, Note: "check the redirect"})
	for q, want := range map[string]bool{
		`row.color.eq:"red" AND row.marked.eq:true`: true,
		`row.note.cont:"redirect"`:                  true,
		`resp.mime.eq:"text/html"`:                  true,
		`req.port.eq:443 AND req.query.eq:"x=1"`:    true,
		`"hunter2"`:                                 true,
		`row.asset.eq:true`:                         false,
		`req.created_at.lt:"2000-01-01"`:            false,
	} {
		parsed, err := Schema.Parse(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if got := parsed.Match(r); got != want {
			t.Errorf("%s = %v", q, got)
		}
	}
}
